use crate::xor;
use cipher::{
    consts::U1, crypto_common::InnerUser, AlgorithmName, Block, BlockCipherEncrypt,
    BlockModeEncBackend, BlockModeEncClosure, BlockModeEncrypt, BlockSizeUser, InOut, InnerIvInit,
    Iv, IvSizeUser, IvState, ParBlocksSizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// CBC mode encryptor.
#[derive(Clone)]
pub struct Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    cipher: C,
    iv: Block<C>,
}

impl<C> BlockSizeUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    type BlockSize = C::BlockSize;
}

impl<C> InnerUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    type Inner = C;
}

impl<C> IvSizeUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
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
        f.call(self)
    }
}

impl<C> ParBlocksSizeUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    type ParBlocksSize = U1;
}

impl<C> BlockModeEncBackend for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    #[inline(always)]
    fn encrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut t = block.clone_in();
        xor(&mut t, &self.iv);
        self.cipher.encrypt_block(&mut t);
        self.iv = t.clone();
        *block.get_out() = t;
    }
}

impl<C> AlgorithmName for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cbc::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cbc::Encryptor<")?;
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
