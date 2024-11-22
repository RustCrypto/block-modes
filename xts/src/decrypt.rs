use crate::xts_core::{precompute_iv, Xts};
use cipher::{
    array::{Array, ArraySize},
    consts::B1,
    crypto_common::{BlockSizes, IvSizeUser},
    inout::InOut,
    typenum::Double,
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncrypt, BlockModeDecBackend, BlockModeDecClosure, BlockModeDecrypt, BlockSizeUser,
    Iv, IvState, Key, KeyInit, KeyIvInit, KeySizeUser, ParBlocks, ParBlocksSizeUser,
};
use core::{fmt, ops::Shl};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// XTS mode decryptor.
#[derive(Clone)]
pub struct Decryptor<BS, C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    cipher: C,
    tweaker: T,
    iv: Block<C>,
}

impl<BS, C, T, KS> KeySizeUser for Decryptor<BS, C, T>
where
    KS: ArraySize + Shl<B1>,
    <KS as Shl<B1>>::Output: ArraySize,
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS> + KeySizeUser<KeySize = KS>,
    T: BlockCipherEncrypt<BlockSize = BS> + KeySizeUser<KeySize = KS>,
{
    type KeySize = Double<KS>;
}

impl<BS, C, T, KS> KeyIvInit for Decryptor<BS, C, T>
where
    KS: ArraySize,
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS> + KeySizeUser<KeySize = KS> + KeyInit,
    T: BlockCipherEncrypt<BlockSize = BS> + KeySizeUser<KeySize = KS> + KeyInit,
    Decryptor<BS, C, T>: KeySizeUser,
{
    fn new(key: &Key<Self>, iv: &Iv<Self>) -> Self {
        // Split the key and call split key constructor
        let k1 = <&Key<C>>::try_from(&key[..C::key_size()])
            .expect("Due to trait bounds, k1 should always be half the size of the XTS key");
        let k2 = <&Key<T>>::try_from(&key[T::key_size()..])
            .expect("Due to trait bounds, k2 should always be half the size of the XTS key");

        Self::new_from_split_keys(k1, k2, iv)
    }
}

impl<BS, C, T> Decryptor<BS, C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS> + KeyInit + KeySizeUser,
    T: BlockCipherEncrypt<BlockSize = BS> + KeyInit + KeySizeUser,
{
    /// Create an XTS array and precompute it
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

    /// Change the IV
    pub fn reset_iv(&mut self, iv: &Block<Self>) {
        self.iv = precompute_iv(&self.tweaker, iv)
    }
}

impl<BS, C, T> BlockSizeUser for Decryptor<BS, C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    type BlockSize = C::BlockSize;
}

impl<BS, C, T> BlockModeDecrypt for Decryptor<BS, C, T>
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
            iv: &'a mut Array<u8, BS>,
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

impl<BS, C, T> IvSizeUser for Decryptor<BS, C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    type IvSize = C::BlockSize;
}

impl<BS, C, T> IvState for Decryptor<BS, C, T>
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

impl<BS, C, T> AlgorithmName for Decryptor<BS, C, T>
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

impl<BS, C, T> fmt::Debug for Decryptor<BS, C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS> + AlgorithmName,
    T: BlockCipherEncrypt<BlockSize = BS> + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("xts::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

impl<BS, C, T> Drop for Decryptor<BS, C, T>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS>,
    T: BlockCipherEncrypt<BlockSize = BS>,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockCipherDecrypt + ZeroizeOnDrop> ZeroizeOnDrop for Decryptor<C> {}

struct Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    iv: &'a mut Array<u8, BS>,
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

    #[inline(always)]
    fn is_decrypt() -> bool {
        true
    }
}
