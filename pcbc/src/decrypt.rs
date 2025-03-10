use crate::xor;
use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockModeDecBackend, BlockModeDecClosure, BlockModeDecrypt, BlockSizeUser, InnerIvInit, Iv,
    IvState, ParBlocksSizeUser,
    array::Array,
    consts::U1,
    crypto_common::{BlockSizes, InnerUser, IvSizeUser},
    inout::InOut,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// PCBC mode decryptor.
#[derive(Clone)]
pub struct Decryptor<C>
where
    C: BlockCipherDecrypt,
{
    cipher: C,
    iv: Block<C>,
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
        /// This closure is used to recieve block cipher backend and create
        /// respective `Backend` based on it.
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
        f.write_str("pcbc::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Decryptor<C>
where
    C: BlockCipherDecrypt + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pcbc::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockCipherDecrypt> Drop for Decryptor<C> {
    fn drop(&mut self) {
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
    type ParBlocksSize = U1;
}

impl<BS, BK> BlockModeDecBackend for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn decrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut t1 = block.clone_in();
        let mut t2 = block.clone_in();
        self.cipher_backend.decrypt_block((&mut t1).into());
        xor(&mut t1, self.iv);
        xor(&mut t2, &t1);
        *self.iv = t2;
        *block.get_out() = t1;
    }
}
