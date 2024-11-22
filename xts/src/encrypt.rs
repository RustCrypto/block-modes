use crate::xts_core::{precompute_iv, Xts};

use cipher::{
    array::ArraySize, consts::B1, crypto_common::BlockSizes, typenum::Double, AlgorithmName, Array,
    Block, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockModeEncBackend,
    BlockModeEncClosure, BlockModeEncrypt, BlockSizeUser, InOut, Iv, IvSizeUser, IvState, Key,
    KeyInit, KeyIvInit, KeySizeUser, ParBlocks, ParBlocksSizeUser,
};
use core::{fmt, ops::Shl};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// XTS mode encryptor.
#[derive(Clone)]
pub struct Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    cipher: C,
    tweaker: C,
    iv: Block<C>,
}

// This would probably be the cleanest way to do it, but it would require a way to multiply a typenum by 2
impl<C, KS> KeySizeUser for Encryptor<C>
where
    KS: ArraySize + Shl<B1>,
    <KS as Shl<B1>>::Output: ArraySize,
    C: BlockCipherEncrypt + KeySizeUser<KeySize = KS>,
{
    type KeySize = Double<KS>;
}

impl<C> KeyIvInit for Encryptor<C>
where
    C: BlockCipherEncrypt + KeySizeUser + KeyInit,
    Encryptor<C>: KeySizeUser,
{
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        // Split the key and call split key constructor
        let k1 = <&Key<C>>::try_from(&key[..C::key_size()])
            .expect("Due to trait bounds, k1 should always be half the size of the XTS key");
        let k2 = <&Key<C>>::try_from(&key[C::key_size()..])
            .expect("Due to trait bounds, k2 should always be half the size of the XTS key");

        Self::new_from_split_keys(k1, k2, iv)
    }
}

impl<C> Encryptor<C>
where
    C: BlockCipherEncrypt + KeyInit + KeySizeUser,
{
    /// Create an XTS array and precompute it
    pub fn new_from_split_keys(k1: &Key<C>, k2: &Key<C>, iv: &Block<Self>) -> Self {
        let cipher = C::new(&k1);
        let tweaker = C::new(&k2);
        let iv = precompute_iv(&tweaker, &iv);

        Self {
            cipher,
            tweaker,
            iv,
        }
    }

    /// Change the IV
    pub fn reset_iv(&mut self, iv: &Block<Self>) {
        self.iv = precompute_iv(&self.tweaker, iv)
    }
}

impl<C> BlockSizeUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    type BlockSize = C::BlockSize;
}

impl<C> IvSizeUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    type IvSize = C::BlockSize;
}

impl<C> IvState for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

impl<C> BlockModeEncrypt for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    fn encrypt_with_backend(&mut self, f: impl BlockModeEncClosure<BlockSize = Self::BlockSize>) {
        struct Closure<'a, BS, BM>
        where
            BS: BlockSizes,
            BM: BlockModeEncClosure<BlockSize = BS>,
        {
            iv: &'a mut Array<u8, BS>,
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

impl<C> AlgorithmName for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("xts::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("xts::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

impl<C: BlockCipherEncrypt> Drop for Encryptor<C> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockCipherEncrypt + ZeroizeOnDrop> ZeroizeOnDrop for Encryptor<C> {}

struct Backend<'a, BS, BC>
where
    BS: BlockSizes,
    BC: BlockCipherEncBackend<BlockSize = BS>,
{
    iv: &'a mut Array<u8, BS>,
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
        self.iv
    }

    #[inline(always)]
    fn is_decrypt() -> bool {
        false
    }
}
