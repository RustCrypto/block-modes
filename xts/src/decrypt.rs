use crate::xts_core::{precompute_iv, Xts};
use cipher::{
    array::Array,
    crypto_common::{BlockSizes, InnerUser, IvSizeUser},
    inout::InOut,
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockCipherEncrypt, BlockModeDecBackend, BlockModeDecClosure, BlockModeDecrypt, BlockSizeUser,
    InnerIvInit, Iv, IvState, KeyInit, ParBlocks, ParBlocksSizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// XTS mode decryptor.
#[derive(Clone)]
pub struct Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    cipher: C,
    iv: Block<C>,
}

// This would probably be the cleanest way to do it, but it would require a way to multiply a typenum by 2
// impl<C> KeySizeUser for Decryptor<C> where C: KeySizeUser {
//     type KeySize = C::KeySize * 2;
// }

impl<BS, C> Decryptor<C>
where
    BS: BlockSizes,
    C: BlockCipherDecrypt<BlockSize = BS> + KeyInit,
{
    /// Create an XTS array and precompute it
    pub fn new_xts<E>(
        k1: Array<u8, C::KeySize>,
        k2: Array<u8, E::KeySize>,
        mut iv: Block<Self>,
    ) -> Self
    where
        E: BlockCipherEncrypt<BlockSize = BS> + KeyInit,
    {
        let tweaker = E::new(&k2);
        precompute_iv(&tweaker, &mut iv);

        let cipher = C::new(&k1);

        Self { cipher, iv }
    }
}

impl<C> BlockSizeUser for Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockModeDecrypt for Decryptor<C>
where
    C: BlockCipherDecrypt,
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

        let Self { cipher, iv } = self;
        cipher.decrypt_with_backend(Closure { iv, f })
    }
}

impl<C> InnerUser for Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    type Inner = C;
}

impl<C> IvSizeUser for Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C> IvState for Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

impl<C> AlgorithmName for Decryptor<C>
where
    C: BlockCipherDecrypt + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("xts::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Decryptor<C>
where
    C: BlockCipherDecrypt + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("xts::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

impl<C: BlockCipherDecrypt> Drop for Decryptor<C> {
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
