use core::{fmt, ops::Add};

use crate::xts_core::{precompute_iv, Stealer, Xts};
use crate::{Error, Result};
use cipher::{
    array::ArraySize,
    crypto_common::{BlockSizes, IvSizeUser},
    inout::InOut,
    typenum::Sum,
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncrypt, BlockModeDecBackend, BlockModeDecClosure, BlockModeDecrypt, BlockSizeUser,
    InOutBuf, Iv, IvState, Key, KeyInit, KeyIvInit, KeySizeUser, ParBlocks, ParBlocksSizeUser,
};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// XTS mode decryptor.
pub type Decryptor<Cipher> = SplitDecryptor<Cipher, Cipher>;

/// XTS mode decryptor.
/// This structure allows using different ciphers for the cipher itself and the tweak.
#[derive(Clone)]
pub struct SplitDecryptor<Cipher, Tweaker>
where
    Cipher: BlockCipherDecrypt,
    Tweaker: BlockCipherEncrypt,
{
    cipher: Cipher,
    tweaker: Tweaker,
    iv: Block<Cipher>,
}

impl<BS, C, T, KS1, KS2> KeySizeUser for SplitDecryptor<C, T>
where
    KS1: ArraySize + Add<KS2>,
    KS2: ArraySize,
    <KS1 as Add<KS2>>::Output: ArraySize,
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS> + KeySizeUser<KeySize = KS1>,
    T: BlockCipherEncrypt<BlockSize = BS> + KeySizeUser<KeySize = KS2>,
{
    type KeySize = Sum<KS1, KS2>;
}

impl<BS, C, T> KeyIvInit for SplitDecryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS> + KeySizeUser + KeyInit,
    T: BlockCipherEncrypt<BlockSize = BS> + KeySizeUser + KeyInit,
    SplitDecryptor<C, T>: KeySizeUser,
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

impl<BS, C, T> SplitDecryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS> + KeyInit + KeySizeUser,
    T: BlockCipherEncrypt<BlockSize = BS> + KeyInit + KeySizeUser,
{
    /// Create an XTS context and precompute the tweak.
    pub fn new_from_split_keys(cipher_key: &Key<C>, tweak_key: &Key<T>, iv: &Block<Self>) -> Self {
        let cipher = C::new(cipher_key);
        let tweaker = T::new(tweak_key);
        let iv = precompute_iv(&tweaker, iv);

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

    /// Decrypt `inout` buffer.
    pub fn decrypt_inout(&mut self, buf: InOutBuf<'_, '_, u8>) -> Result<()> {
        if buf.len() < BS::USIZE {
            return Err(Error);
        };

        if buf.len() % BS::USIZE == 0 {
            // No need for stealing
            let (blocks, _) = buf.into_chunks();
            self.decrypt_blocks_inout(blocks);
        } else {
            let full_blocks = (buf.len() / BS::USIZE - 1) * BS::USIZE;

            let (blocks, mut tail) = buf.split_at(full_blocks);
            let (blocks, _) = blocks.into_chunks();
            self.decrypt_blocks_inout(blocks);

            for mut b in tail.reborrow() {
                *b.get_out() = *b.get_in();
            }

            self.ciphertext_stealing(tail.get_out());
        }

        Ok(())
    }

    /// Decrypt data in-place.
    pub fn decrypt(&mut self, buf: &mut [u8]) -> Result<()> {
        self.decrypt_inout(buf.into())
    }

    /// Decrypt data buffer-to-buffer.
    pub fn decrypt_b2b(&mut self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<()> {
        InOutBuf::new(in_buf, out_buf)
            .map_err(|_| Error)
            .and_then(|buf| self.decrypt_inout(buf))
    }
}

impl<BS, C, T> BlockSizeUser for SplitDecryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, C, T> BlockModeDecrypt for SplitDecryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    fn decrypt_with_backend(&mut self, f: impl BlockModeDecClosure<BlockSize = Self::BlockSize>) {
        struct Closure<'a, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeDecClosure<BlockSize = BS>,
        {
            iv: &'a mut Block<Self>,
            f: BC,
        }

        impl<BS, BC> BlockSizeUser for Closure<'_, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeDecClosure<BlockSize = BS>,
        {
            type BlockSize = BS;
        }

        impl<BS, BC> BlockCipherDecClosure for Closure<'_, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeDecClosure<BlockSize = BS>,
        {
            #[inline(always)]
            fn call<B: BlockCipherDecBackend<BlockSize = Self::BlockSize>>(
                self,
                cipher_backend: &B,
            ) {
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
        cipher.decrypt_with_backend(Closure { iv, f })
    }
}

impl<BS, C, T> Stealer for SplitDecryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    fn process_block(&self, block: &mut Block<Self>) {
        self.cipher.decrypt_block(block);
    }

    fn get_iv(&self) -> &Block<Self> {
        &self.iv
    }

    fn get_iv_mut(&mut self) -> &mut Block<Self> {
        &mut self.iv
    }

    #[inline(always)]
    fn is_decrypt() -> bool {
        true
    }
}

impl<BS, C, T> IvSizeUser for SplitDecryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    type IvSize = BS;
}

impl<BS, C, T> IvState for SplitDecryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

impl<BS, C, T> AlgorithmName for SplitDecryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS> + AlgorithmName,
    T: BlockCipherEncrypt<BlockSize = BS> + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("xts::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(",")?;
        <T as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<BS, C, T> fmt::Debug for SplitDecryptor<C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS> + AlgorithmName,
    T: BlockCipherEncrypt<BlockSize = BS> + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Self::write_alg_name(f)
    }
}

impl<C, T> Drop for SplitDecryptor<C, T>
where
    C: BlockCipherDecrypt,
    T: BlockCipherEncrypt,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C, T> ZeroizeOnDrop for SplitDecryptor<C, T>
where
    C: BlockCipherDecrypt + ZeroizeOnDrop,
    T: BlockCipherEncrypt + ZeroizeOnDrop,
{
}

struct Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    iv: &'a mut Block<Self>,
    cipher_backend: &'a BK,
}

impl<BS, BK> BlockSizeUser for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BK> ParBlocksSizeUser for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    type ParBlocksSize = BK::ParBlocksSize;
}

impl<BS, BK> BlockModeDecBackend for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn decrypt_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        self.process_block(block);
    }

    #[inline(always)]
    fn decrypt_par_blocks(&mut self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        self.process_par_blocks(blocks);
    }

    #[inline(always)]
    fn decrypt_block_inplace(&mut self, block: &mut Block<Self>) {
        self.process_block_inplace(block);
    }

    #[inline(always)]
    fn decrypt_par_blocks_inplace(&mut self, blocks: &mut ParBlocks<Self>) {
        self.process_par_blocks_inplace(blocks);
    }

    #[inline(always)]
    fn decrypt_tail_blocks(&mut self, blocks: cipher::InOutBuf<'_, '_, Block<Self>>) {
        self.process_tail_blocks(blocks);
    }

    #[inline(always)]
    fn decrypt_tail_blocks_inplace(&mut self, blocks: &mut [Block<Self>]) {
        self.process_tail_blocks_inplace(blocks);
    }
}

impl<BS, BC> Xts for Backend<'_, BS, BC>
where
    BS: BlockSizes,
    BC: BlockCipherDecBackend<BlockSize = BS>,
{
    fn process_inplace(&self, block: &mut Block<Self>) {
        self.cipher_backend.decrypt_block_inplace(block);
    }

    fn process_par_inplace(&self, blocks: &mut ParBlocks<Self>) {
        self.cipher_backend.decrypt_par_blocks_inplace(blocks);
    }

    fn get_iv_mut(&mut self) -> &mut Block<Self> {
        self.iv
    }
}
