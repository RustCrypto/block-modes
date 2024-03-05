use crate::xor;
use cipher::{
    array::Array,
    consts::U1,
    crypto_common::{BlockSizes, InnerUser, IvSizeUser},
    inout::InOut,
    AlgorithmName, Block, BlockBackend, BlockCipher, BlockCipherEncrypt, BlockClosure,
    BlockModeEncrypt, BlockSizeUser, InnerIvInit, Iv, IvState, ParBlocksSizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// CBC mode encryptor.
#[derive(Clone)]
pub struct Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher,
{
    cipher: C,
    iv: Block<C>,
}

impl<C> BlockSizeUser for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockModeEncrypt for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher,
{
    fn encrypt_with_backend(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend(Closure { iv, f })
    }
}

impl<C> InnerUser for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher,
{
    type Inner = C;
}

impl<C> IvSizeUser for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher,
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
    C: BlockCipherEncrypt + BlockCipher,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

impl<C> AlgorithmName for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cbc::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipher + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cbc::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockCipherEncrypt + BlockCipher> Drop for Encryptor<C> {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockCipherEncrypt + BlockCipher + ZeroizeOnDrop> ZeroizeOnDrop for Encryptor<C> {}

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
        let mut t = block.clone_in();
        xor(&mut t, self.iv);
        self.backend.proc_block((&mut t).into());
        *self.iv = t.clone();
        *block.get_out() = t;
    }
}
