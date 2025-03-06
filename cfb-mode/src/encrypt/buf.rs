use super::xor_set1;
use cipher::{
    AlgorithmName, Block, BlockCipherEncrypt, InnerIvInit, Iv, IvSizeUser,
    crypto_common::InnerUser, typenum::Unsigned,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// CFB mode buffered encryptor.
#[derive(Clone)]
pub struct BufEncryptor<C>
where
    C: BlockCipherEncrypt,
{
    cipher: C,
    iv: Block<C>,
    pos: usize,
}

impl<C> BufEncryptor<C>
where
    C: BlockCipherEncrypt,
{
    /// Encrypt a buffer in multiple parts.
    pub fn encrypt(&mut self, mut data: &mut [u8]) {
        let bs = C::BlockSize::USIZE;
        let n = data.len();

        if n < bs - self.pos {
            xor_set1(data, &mut self.iv[self.pos..self.pos + n]);
            self.pos += n;
            return;
        }

        let (left, right) = { data }.split_at_mut(bs - self.pos);
        data = right;
        let mut iv = self.iv.clone();
        xor_set1(left, &mut iv[self.pos..]);
        self.cipher.encrypt_block(&mut iv);

        let mut chunks = data.chunks_exact_mut(bs);
        for chunk in &mut chunks {
            xor_set1(chunk, iv.as_mut_slice());
            self.cipher.encrypt_block(&mut iv);
        }

        let rem = chunks.into_remainder();
        xor_set1(rem, iv.as_mut_slice());
        self.pos = rem.len();
        self.iv = iv;
    }

    /// Returns the current state (block and position) of the decryptor.
    pub fn get_state(&self) -> (&Block<C>, usize) {
        (&self.iv, self.pos)
    }

    /// Restore from the given state for resumption.
    pub fn from_state(cipher: C, iv: &Block<C>, pos: usize) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
            pos,
        }
    }
}

impl<C> InnerUser for BufEncryptor<C>
where
    C: BlockCipherEncrypt,
{
    type Inner = C;
}

impl<C> IvSizeUser for BufEncryptor<C>
where
    C: BlockCipherEncrypt,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for BufEncryptor<C>
where
    C: BlockCipherEncrypt,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let mut iv = iv.clone();
        cipher.encrypt_block(&mut iv);
        Self { cipher, iv, pos: 0 }
    }
}

impl<C> AlgorithmName for BufEncryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::BufEncryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for BufEncryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::BufEncryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

impl<C: BlockCipherEncrypt> Drop for BufEncryptor<C> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockCipherEncrypt + ZeroizeOnDrop> ZeroizeOnDrop for BufEncryptor<C> {}
