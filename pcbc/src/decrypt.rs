use crate::xor;
use cipher::{
    array::Array,
    consts::U1,
    crypto_common::{BlockSizes, InnerUser, IvSizeUser},
    inout::InOut,
    AlgorithmName, Block, BlockBackend, BlockCipher, BlockCipherDecrypt, BlockClosure,
    BlockModeDecrypt, BlockSizeUser, InnerIvInit, Iv, IvState, ParBlocksSizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// PCBC mode decryptor.
#[derive(Clone)]
pub struct Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
{
    cipher: C,
    iv: Block<C>,
}

impl<C> BlockSizeUser for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockModeDecrypt for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
{
    fn decrypt_with_backend(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, iv } = self;
        cipher.decrypt_with_backend(Closure { iv, f })
    }
}

impl<C> InnerUser for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
{
    type Inner = C;
}

impl<C> IvSizeUser for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
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
    C: BlockCipherDecrypt + BlockCipher,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

impl<C> AlgorithmName for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pcbc::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("pcbc::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockCipherDecrypt + BlockCipher> Drop for Decryptor<C> {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockCipherDecrypt + BlockCipher + ZeroizeOnDrop> ZeroizeOnDrop for Decryptor<C> {}

struct Closure<'a, BS, BC>
where
    BS: BlockSizes,
    BC: BlockClosure<BlockSize = BS>,
{
    iv: &'a mut Array<u8, BS>,
    f: BC,
}

impl<'a, BS, BC> BlockSizeUser for Closure<'a, BS, BC>
where
    BS: BlockSizes,
    BC: BlockClosure<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, BC> BlockClosure for Closure<'a, BS, BC>
where
    BS: BlockSizes,
    BC: BlockClosure<BlockSize = BS>,
{
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
        let Self { iv, f } = self;
        f.call(&mut Backend { iv, backend });
    }
}

struct Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockBackend<BlockSize = BS>,
{
    iv: &'a mut Array<u8, BS>,
    backend: &'a mut BK,
}

impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, BK> ParBlocksSizeUser for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockBackend<BlockSize = BS>,
{
    type ParBlocksSize = U1;
}

impl<'a, BS, BK> BlockBackend for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut t1 = block.clone_in();
        let mut t2 = block.clone_in();
        self.backend.proc_block((&mut t1).into());
        xor(&mut t1, self.iv);
        xor(&mut t2, &t1);
        *self.iv = t2;
        *block.get_out() = t1;
    }
}
