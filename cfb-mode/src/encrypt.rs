use cipher::{
    AlgorithmName, AsyncStreamCipher, Block, BlockCipherDecrypt, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockCipherEncrypt, BlockModeEncBackend, BlockModeEncClosure,
    BlockModeEncrypt, BlockSizeUser, InOut, InnerIvInit, Iv, IvSizeUser, IvState,
    ParBlocksSizeUser,
    array::Array,
    consts::U1,
    crypto_common::{BlockSizes, InnerUser},
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

mod buf;
pub use buf::BufEncryptor;

/// CFB mode encryptor.
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

impl<C> BlockModeEncrypt for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    fn encrypt_with_backend(&mut self, f: impl BlockModeEncClosure<BlockSize = Self::BlockSize>) {
        /// This closure is used to recieve block cipher backend and create
        /// respective `Backend` based on it.
        struct Closure<'a, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeEncClosure<BlockSize = BS>,
        {
            iv: &'a mut Array<u8, BS>,
            f: BC,
        }

        impl<BS, BC> BlockSizeUser for Closure<'_, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeEncClosure<BlockSize = BS>,
        {
            type BlockSize = BS;
        }

        impl<BS, BC> BlockCipherEncClosure for Closure<'_, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeEncClosure<BlockSize = BS>,
        {
            #[inline(always)]
            fn call<B: BlockCipherEncBackend<BlockSize = Self::BlockSize>>(
                self,
                cipher_backend: &B,
            ) {
                let Self { iv, f } = self;
                f.call(&mut CbcEncryptBackend { iv, cipher_backend });
            }
        }

        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend(Closure { iv, f })
    }
}

impl<C> AsyncStreamCipher for Encryptor<C> where C: BlockCipherEncrypt {}

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
        let mut iv = iv.clone();
        cipher.encrypt_block(&mut iv);
        Self { cipher, iv }
    }
}

impl<C> IvState for Encryptor<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        let mut res = self.iv.clone();
        self.cipher.decrypt_block(&mut res);
        res
    }
}

impl<C> AlgorithmName for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::Encryptor<")?;
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

struct CbcEncryptBackend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    iv: &'a mut Array<u8, BS>,
    cipher_backend: &'a BK,
}

impl<BS, BK> BlockSizeUser for CbcEncryptBackend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BK> ParBlocksSizeUser for CbcEncryptBackend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type ParBlocksSize = U1;
}

impl<BS, BK> BlockModeEncBackend for CbcEncryptBackend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn encrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        block.xor_in2out(self.iv);
        let mut t = block.get_out().clone();
        self.cipher_backend.encrypt_block((&mut t).into());
        *self.iv = t;
    }
}

#[inline(always)]
fn xor_set1(buf1: &mut [u8], buf2: &mut [u8]) {
    for (a, b) in buf1.iter_mut().zip(buf2) {
        let t = *a ^ *b;
        *a = t;
        *b = t;
    }
}
