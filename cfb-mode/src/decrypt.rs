use cipher::{
    consts::U1,
    crypto_common::{InnerUser, IvSizeUser},
    generic_array::{ArrayLength, GenericArray},
    inout::InOut,
    AlgorithmName, AsyncStreamCipher, Block, BlockBackend, BlockCipher, BlockClosure,
    BlockDecryptMut, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv, IvState, ParBlocksSizeUser,
};
use core::{fmt, marker::PhantomData};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// CFB mode decryptor.
#[derive(Clone)]
pub struct Decryptor<C, MBS = <C as BlockSizeUser>::BlockSize>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    cipher: C,
    iv: Block<C>,
    _pd: PhantomData<MBS>,
}

impl<C, MBS> BlockSizeUser for Decryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    type BlockSize = MBS;
}

impl<C, MBS> BlockDecryptMut for Decryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    fn decrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, iv, _pd } = self;
        cipher.encrypt_with_backend_mut(Closure { iv, f, _pd: *_pd })
    }
}

impl<C, MBS> AsyncStreamCipher for Decryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
}

impl<C, MBS> InnerUser for Decryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    type Inner = C;
}

impl<C, MBS> IvSizeUser for Decryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    type IvSize = C::BlockSize;
}

impl<C, MBS> InnerIvInit for Decryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            _pd: PhantomData,
        }
    }
}

impl<C, MBS> IvState for Decryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher,
    MBS: ArrayLength<u8>,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

impl<C, MBS> AlgorithmName for Decryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
    MBS: ArrayLength<u8>,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C, MBS> fmt::Debug for Decryptor<C, MBS>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
    MBS: ArrayLength<u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C, MBS> Drop for Decryptor<C, MBS>
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
impl<C, MBS> ZeroizeOnDrop for Decryptor<C, MBS>
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
    // It's possible to implement parallel decryption, but currently
    // `ParBlocksSize` is tied to block size. Since cipher block size
    // and method block size in general can be different, we can not
    // write `type ParBlocksSize = BK::ParBlocksSize`.
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

        let mut iv_cpy = self.iv.clone();

        let mid = cbs - mbs;
        self.iv[..mid].copy_from_slice(&iv_cpy[mbs..]);
        self.iv[mid..].copy_from_slice(block.get_in());

        self.backend.proc_block((&mut iv_cpy).into());
        block.xor_in2out(GenericArray::from_slice(&iv_cpy[..mbs]));
    }

    // See comment in `ParBlocksSizeUser` impl
    /*
        #[inline(always)]
        fn proc_par_blocks(&mut self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
            // let mut t = ParBlocks::<Self>::default();
            // let b = (blocks.get_in(), &mut t).into();
            // self.backend.proc_par_blocks(b);

            // let n = t.len();
            // blocks.get(0).xor_in2out(self.iv);
            // for i in 1..n {
            //     blocks.get(i).xor_in2out(&t[i - 1])
            // }
            // *self.iv = t[n - 1].clone();
        }
    */
}
