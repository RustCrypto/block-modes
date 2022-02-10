use cipher::{
    consts::U1,
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::{ArrayLength, GenericArray},
    inout::InOut,
    AlgorithmName, AsyncStreamCipher, Block, BlockBackend, BlockCipher, BlockClosure,
    BlockDecryptMut, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv, IvState, ParBlocksSizeUser,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// CFB-8 mode decryptor.
#[derive(Clone)]
pub struct Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    cipher: C,
    iv: Block<C>,
}

impl<C> BlockSizeUser for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type BlockSize = U1;
}

impl<C> BlockDecryptMut for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    fn decrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend_mut(Closure { iv, f })
    }
}

impl<C: BlockEncryptMut + BlockCipher> AsyncStreamCipher for Decryptor<C> {}

impl<C> InnerUser for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type Inner = C;
}

impl<C> IvSizeUser for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let iv = iv.clone();
        Self { cipher, iv }
    }
}

impl<C> IvState for Decryptor<C>
where
    C: BlockEncryptMut + BlockDecryptMut + BlockCipher,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

impl<C> AlgorithmName for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb8::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Decryptor<C>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb8::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockEncryptMut + BlockCipher> Drop for Decryptor<C> {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockEncryptMut + BlockCipher + ZeroizeOnDrop> ZeroizeOnDrop for Decryptor<C> {}

struct Closure<'a, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = U1>,
{
    iv: &'a mut GenericArray<u8, BS>,
    f: BC,
}

impl<'a, BS, BC> BlockSizeUser for Closure<'a, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = U1>,
{
    type BlockSize = BS;
}

impl<'a, BS, BC> BlockClosure for Closure<'a, BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = U1>,
{
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
        let Self { iv, f } = self;
        f.call(&mut Backend { iv, backend });
    }
}

struct Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    iv: &'a mut GenericArray<u8, BS>,
    backend: &'a mut BK,
}

impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    type BlockSize = U1;
}

impl<'a, BS, BK> ParBlocksSizeUser for Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    type ParBlocksSize = U1;
}

impl<'a, BS, BK> BlockBackend for Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut t = self.iv.clone();
        self.backend.proc_block((&mut t).into());
        let r = block.get(0).clone_in();
        block.xor_in2out(GenericArray::from_slice(&t[..1]));
        let n = self.iv.len();
        for i in 0..n - 1 {
            self.iv[i] = self.iv[i + 1];
        }
        self.iv[n - 1] = r;
    }
}
