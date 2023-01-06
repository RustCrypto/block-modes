use cipher::{
    consts::U1,
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::{ArrayLength, GenericArray},
    inout::InOut,
    AlgorithmName, AsyncStreamCipher, Block, BlockBackend, BlockCipher, BlockClosure, BlockDecrypt,
    BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv, IvState, ParBlocksSizeUser,
};
use core::{fmt, marker::PhantomData};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// CFB mode encryptor.
#[derive(Clone)]
pub struct Encryptor<C, MBS = <C as BlockSizeUser>::BlockSize>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    cipher: C,
    iv: Block<C>,
    _pd: PhantomData<MBS>,
}

impl<C, MBS> BlockSizeUser for Encryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    type BlockSize = MBS;
}

impl<C, MBS> BlockEncryptMut for Encryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    fn encrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, iv, _pd } = self;
        cipher.encrypt_with_backend_mut(Closure {
            iv,
            f,
            _pd: _pd.clone(),
        })
    }
}

impl<C, MBS> AsyncStreamCipher for Encryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
}

impl<C, MBS> InnerUser for Encryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    type Inner = C;
}

impl<C, MBS> IvSizeUser for Encryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    type IvSize = C::BlockSize;
}

impl<C, MBS> InnerIvInit for Encryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    #[inline]
    fn inner_iv_init(mut cipher: C, iv: &Iv<Self>) -> Self {
        let mut iv = iv.clone();
        cipher.encrypt_block_mut(&mut iv);
        Self {
            cipher,
            iv,
            _pd: PhantomData,
        }
    }
}

impl<C, MBS> IvState for Encryptor<C, MBS>
where
    C: BlockEncryptMut + BlockDecrypt + BlockCipher,
    MBS: ArrayLength<u8>,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        let mut res = self.iv.clone();
        self.cipher.decrypt_block(&mut res);
        res
    }
}

impl<C, MBS> AlgorithmName for Encryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
    MBS: ArrayLength<u8>,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C, MBS> fmt::Debug for Encryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
    MBS: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C, MBS> Drop for Encryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C, MBS> ZeroizeOnDrop for Encryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher + ZeroizeOnDrop,
    MBS: ArrayLength<u8>,
{
}

struct Closure<'a, CBS, MBS, BC>
where
    CBS: ArrayLength<u8>,
    MBS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = MBS>,
{
    iv: &'a mut GenericArray<u8, CBS>,
    f: BC,
    _pd: PhantomData<MBS>,
}

impl<'a, CBS, MBS, BC> BlockSizeUser for Closure<'a, CBS, MBS, BC>
where
    CBS: ArrayLength<u8>,
    MBS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = MBS>,
{
    type BlockSize = CBS;
}

impl<'a, CBS, MBS, BC> BlockClosure for Closure<'a, CBS, MBS, BC>
where
    CBS: ArrayLength<u8>,
    MBS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = MBS>,
{
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
        let Self { iv, f, _pd } = self;
        f.call(&mut Backend { iv, backend, _pd });
    }
}

struct Backend<'a, CBS, MBS, BK>
where
    CBS: ArrayLength<u8>,
    MBS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = CBS>,
{
    iv: &'a mut GenericArray<u8, CBS>,
    backend: &'a mut BK,
    _pd: PhantomData<MBS>,
}

impl<'a, CBS, MBS, BK> BlockSizeUser for Backend<'a, CBS, MBS, BK>
where
    CBS: ArrayLength<u8>,
    MBS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = CBS>,
{
    type BlockSize = MBS;
}

impl<'a, CBS, MBS, BK> ParBlocksSizeUser for Backend<'a, CBS, MBS, BK>
where
    CBS: ArrayLength<u8>,
    MBS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = CBS>,
{
    type ParBlocksSize = U1;
}

impl<'a, CBS, MBS, BK> BlockBackend for Backend<'a, CBS, MBS, BK>
where
    CBS: ArrayLength<u8>,
    MBS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = CBS>,
{
    #[inline(always)]
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let cbs = CBS::USIZE;
        let mbs = MBS::USIZE;
        if mbs == cbs {
            block.xor_in2out(GenericArray::from_slice(self.iv));
            let mut t = block.get_out().clone();
            let block = GenericArray::from_mut_slice(&mut t);
            self.backend.proc_block(block.into());
            self.iv.copy_from_slice(&t);
        } else {
            let mut t = self.iv.clone();
            self.backend.proc_block((&mut t).into());
            block.xor_in2out(GenericArray::from_slice(&t[..mbs]));

            let ct = block.get_out();
            let mid = cbs - mbs;
            for i in 0..mid {
                self.iv[i] = self.iv[i + mbs];
            }
            self.iv[mid..].copy_from_slice(&ct);
        }
    }
}
