use crate::xts_core::{precompute_iv, Stealer, Xts};
use crate::{Error, Result};

use cipher::InOutBuf;
use cipher::{
    array::ArraySize, crypto_common::BlockSizes, typenum::Sum, AlgorithmName, Block,
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockModeEncBackend,
    BlockModeEncClosure, BlockModeEncrypt, BlockSizeUser, InOut, Iv, IvSizeUser, IvState, Key,
    KeyInit, KeyIvInit, KeySizeUser, ParBlocks, ParBlocksSizeUser,
};
use core::{fmt, ops::Add};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// XTS mode encryptor.
pub type Encryptor<Cipher> = SplitEncryptor<Cipher, Cipher>;

/// XTS mode encryptor.
/// This structure allows using different ciphers for the cipher itself and the tweak.
#[derive(Clone)]
pub struct SplitEncryptor<Cipher, Tweaker>
where
    Cipher: BlockCipherEncrypt,
    Tweaker: BlockCipherEncrypt,
{
    cipher: Cipher,
    tweaker: Tweaker,
    iv: Block<Cipher>,
}

// This would probably be the cleanest way to do it, but it would require a way to multiply a typenum by 2
impl<BS, C, T, KS1, KS2> KeySizeUser for SplitEncryptor<C, T>
where
    KS1: ArraySize + Add<KS2>,
    KS2: ArraySize,
    <KS1 as Add<KS2>>::Output: ArraySize,
    BS: BlockSizes,
    C: BlockCipherEncrypt<BlockSize = BS> + KeySizeUser<KeySize = KS1>,
    T: BlockCipherEncrypt<BlockSize = BS> + KeySizeUser<KeySize = KS2>,
{
    type KeySize = Sum<KS1, KS2>;
}

impl<BS, C, T> KeyIvInit for SplitEncryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherEncrypt<BlockSize = BS> + KeySizeUser + KeyInit,
    T: BlockCipherEncrypt<BlockSize = BS> + KeySizeUser + KeyInit,
    SplitEncryptor<C, T>: KeySizeUser,
{
    /// Create a new instance of the cipher and initialize it.
    /// This assumes a single key, which is a concatenation of the cipher key and the tweak key, in that order.
    /// To use different key, use `new_from_split_keys`
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        // Split the key and call split key constructor
        // Assumes the key is cipher_key + tweak_key
        let k1 = <&Key<C>>::try_from(&key[..C::key_size()])
            .expect("Due to trait bounds, k1 should always be half the size of the XTS key");
        let k2 = <&Key<T>>::try_from(&key[C::key_size()..])
            .expect("Due to trait bounds, k2 should always be half the size of the XTS key");

        Self::new_from_split_keys(k1, k2, iv)
    }
}

impl<BS, C, T> SplitEncryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherEncrypt<BlockSize = BS> + KeyInit + KeySizeUser,
    T: BlockCipherEncrypt<BlockSize = BS> + KeyInit + KeySizeUser,
{
    /// Create an XTS context and precompute the tweak.
    pub fn new_from_split_keys(k1: &Key<C>, k2: &Key<T>, iv: &Block<Self>) -> Self {
        let cipher = C::new(&k1);
        let tweaker = T::new(&k2);
        let iv = precompute_iv(&tweaker, &iv);

        Self {
            cipher,
            tweaker,
            iv,
        }
    }

    /// Change the IV/sector number.
    pub fn reset_iv(&mut self, iv: &Block<Self>) {
        self.iv = precompute_iv(&self.tweaker, iv)
    }

    /// Encrypt `inout` buffer.
    pub fn encrypt_inout(&mut self, buf: InOutBuf<'_, '_, u8>) -> Result<()> {
        if buf.len() < BS::USIZE {
            return Err(Error);
        };

        if buf.len() % BS::USIZE == 0 {
            // No need for stealing
            let (blocks, _) = buf.into_chunks();
            self.encrypt_blocks_inout(blocks);
        } else {
            let full_blocks = (buf.len() / BS::USIZE - 1) * BS::USIZE;

            let (blocks, mut tail) = buf.split_at(full_blocks);
            let (blocks, _) = blocks.into_chunks();
            self.encrypt_blocks_inout(blocks);

            for mut b in tail.reborrow() {
                *b.get_out() = *b.get_in();
            }

            self.ciphertext_stealing(tail.get_out());
        }

        Ok(())
    }

    /// Encrypt data in-place.
    pub fn encrypt(&mut self, buf: &mut [u8]) -> Result<()> {
        self.encrypt_inout(buf.into())
    }

    /// Encrypt data buffer-to-buffer.
    pub fn encrypt_b2b(&mut self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<()> {
        InOutBuf::new(in_buf, out_buf)
            .map_err(|_| Error)
            .and_then(|buf| self.encrypt_inout(buf))
    }
}

impl<BS, C, T> BlockSizeUser for SplitEncryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherEncrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, C, T> IvSizeUser for SplitEncryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherEncrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    type IvSize = BS;
}

impl<BS, C, T> IvState for SplitEncryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherEncrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

impl<BS, C, T> BlockModeEncrypt for SplitEncryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherEncrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    fn encrypt_with_backend(&mut self, f: impl BlockModeEncClosure<BlockSize = Self::BlockSize>) {
        struct Closure<'a, BS, BM>
        where
            BS: BlockSizes,
            BM: BlockModeEncClosure<BlockSize = BS>,
        {
            iv: &'a mut Block<Self>,
            f: BM,
        }

        impl<BS, BM> BlockSizeUser for Closure<'_, BS, BM>
        where
            BS: BlockSizes,
            BM: BlockModeEncClosure<BlockSize = BS>,
        {
            type BlockSize = BS;
        }

        impl<BS, BM> BlockCipherEncClosure for Closure<'_, BS, BM>
        where
            BS: BlockSizes,
            BM: BlockModeEncClosure<BlockSize = BS>,
        {
            #[inline(always)]
            fn call<B: cipher::BlockCipherEncBackend<BlockSize = BS>>(self, cipher_backend: &B) {
                let Self { iv, f } = self;
                f.call(&mut Backend { iv, cipher_backend });
            }
        }

        // tweaker is only used when setting up IV
        let Self {
            cipher,
            tweaker: _,
            iv,
        } = self;

        let f = Closure { iv, f };
        cipher.encrypt_with_backend(f)
    }
}

impl<BS, C, T> Stealer for SplitEncryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherEncrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    fn process_block(&self, block: &mut Block<Self>) {
        self.cipher.encrypt_block(block);
    }

    fn get_iv(&self) -> &Block<Self> {
        &self.iv
    }

    fn get_iv_mut(&mut self) -> &mut Block<Self> {
        &mut self.iv
    }

    #[inline(always)]
    fn is_decrypt() -> bool {
        false
    }
}

impl<BS, C, T> AlgorithmName for SplitEncryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherEncrypt<BlockSize = BS> + AlgorithmName,
    T: BlockCipherEncrypt<BlockSize = BS> + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("xts::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(",")?;
        <T as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<BS, C, T> fmt::Debug for SplitEncryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherEncrypt<BlockSize = BS> + AlgorithmName,
    T: BlockCipherEncrypt<BlockSize = BS> + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Self::write_alg_name(f)
    }
}

impl<C, T> Drop for SplitEncryptor<C, T>
where
    C: BlockCipherEncrypt,
    T: BlockCipherEncrypt,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockCipherEncrypt + ZeroizeOnDrop> ZeroizeOnDrop for SplitEncryptor<C> {}

struct Backend<'a, BS, BC>
where
    BS: BlockSizes,
    BC: BlockCipherEncBackend<BlockSize = BS>,
{
    iv: &'a mut Block<Self>,
    cipher_backend: &'a BC,
}

impl<BS, BK> BlockSizeUser for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BK> ParBlocksSizeUser for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type ParBlocksSize = BK::ParBlocksSize;
}

impl<BS, BK> BlockModeEncBackend for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn encrypt_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        self.process_block(block);
    }

    #[inline(always)]
    fn encrypt_par_blocks(&mut self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        self.process_par_blocks(blocks);
    }

    #[inline(always)]
    fn encrypt_block_inplace(&mut self, block: &mut Block<Self>) {
        self.process_block_inplace(block);
    }

    #[inline(always)]
    fn encrypt_par_blocks_inplace(&mut self, blocks: &mut ParBlocks<Self>) {
        self.process_par_blocks_inplace(blocks);
    }

    #[inline(always)]
    fn encrypt_tail_blocks(&mut self, blocks: cipher::InOutBuf<'_, '_, Block<Self>>) {
        self.process_tail_blocks(blocks);
    }

    #[inline(always)]
    fn encrypt_tail_blocks_inplace(&mut self, blocks: &mut [Block<Self>]) {
        self.process_tail_blocks_inplace(blocks);
    }
}

impl<BS, BC> Xts for Backend<'_, BS, BC>
where
    BS: BlockSizes,
    BC: BlockCipherEncBackend<BlockSize = BS>,
{
    fn process_inplace(&self, block: &mut Block<Self>) {
        self.cipher_backend.encrypt_block_inplace(block);
    }

    fn process_par_inplace(&self, blocks: &mut ParBlocks<Self>) {
        self.cipher_backend.encrypt_par_blocks_inplace(blocks);
    }

    fn get_iv_mut(&mut self) -> &mut Block<Self> {
        &mut self.iv
    }
}
