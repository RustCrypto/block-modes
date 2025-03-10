use cipher::{
    AlgorithmName, Array, AsyncStreamCipher, Block, BlockCipherDecrypt, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockCipherEncrypt, BlockModeDecBackend, BlockModeDecClosure,
    BlockModeDecrypt, BlockSizeUser, InOut, InnerIvInit, Iv, IvSizeUser, IvState, ParBlocks,
    ParBlocksSizeUser,
    crypto_common::{BlockSizes, InnerUser},
    typenum::Unsigned,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// CFB mode decryptor.
#[derive(Clone)]
pub struct Decryptor<C>
where
    C: BlockCipherEncrypt,
{
    cipher: C,
    iv: Block<C>,
}

/// CFB mode buffered decryptor.
#[derive(Clone)]
pub struct BufDecryptor<C>
where
    C: BlockCipherEncrypt,
{
    cipher: C,
    iv: Block<C>,
    pos: usize,
}

impl<C> BufDecryptor<C>
where
    C: BlockCipherEncrypt,
{
    /// Decrypt a buffer in multiple parts.
    pub fn decrypt(&mut self, mut data: &mut [u8]) {
        let bs = C::BlockSize::USIZE;
        let n = data.len();

        if n < bs - self.pos {
            xor_set2(data, &mut self.iv[self.pos..self.pos + n]);
            self.pos += n;
            return;
        }
        let (left, right) = { data }.split_at_mut(bs - self.pos);
        data = right;
        let mut iv = self.iv.clone();
        xor_set2(left, &mut iv[self.pos..]);
        self.cipher.encrypt_block(&mut iv);

        let mut chunks = data.chunks_exact_mut(bs);
        for chunk in &mut chunks {
            xor_set2(chunk, iv.as_mut_slice());
            self.cipher.encrypt_block(&mut iv);
        }

        let rem = chunks.into_remainder();
        xor_set2(rem, iv.as_mut_slice());
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

impl<C> InnerUser for BufDecryptor<C>
where
    C: BlockCipherEncrypt,
{
    type Inner = C;
}

impl<C> IvSizeUser for BufDecryptor<C>
where
    C: BlockCipherEncrypt,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for BufDecryptor<C>
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

impl<C> AlgorithmName for BufDecryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::BufDecryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for BufDecryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::BufDecryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

impl<C: BlockCipherEncrypt> Drop for BufDecryptor<C> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockCipherEncrypt + ZeroizeOnDrop> ZeroizeOnDrop for BufDecryptor<C> {}

impl<C> BlockSizeUser for Decryptor<C>
where
    C: BlockCipherEncrypt,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockModeDecrypt for Decryptor<C>
where
    C: BlockCipherEncrypt,
{
    fn decrypt_with_backend(&mut self, f: impl BlockModeDecClosure<BlockSize = Self::BlockSize>) {
        /// This closure is used to recieve block cipher backend and
        /// create respective [`CbcDecryptBackend`] based on it.
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

        impl<BS, BC> BlockCipherEncClosure for Closure<'_, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeDecClosure<BlockSize = BS>,
        {
            #[inline(always)]
            fn call<B: BlockCipherEncBackend<BlockSize = Self::BlockSize>>(
                self,
                cipher_backend: &B,
            ) {
                let Self { iv, f } = self;
                f.call(&mut CbcDecryptBackend { iv, cipher_backend });
            }
        }

        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend(Closure { iv, f })
    }
}

impl<C> AsyncStreamCipher for Decryptor<C> where C: BlockCipherEncrypt {}

impl<C> InnerUser for Decryptor<C>
where
    C: BlockCipherEncrypt,
{
    type Inner = C;
}

impl<C> IvSizeUser for Decryptor<C>
where
    C: BlockCipherEncrypt,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for Decryptor<C>
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

impl<C> IvState for Decryptor<C>
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

impl<C> AlgorithmName for Decryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Decryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cfb::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

impl<C: BlockCipherEncrypt> Drop for Decryptor<C> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockCipherEncrypt + ZeroizeOnDrop> ZeroizeOnDrop for Decryptor<C> {}

struct CbcDecryptBackend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    iv: &'a mut Array<u8, BS>,
    cipher_backend: &'a BK,
}

impl<BS, BK> BlockSizeUser for CbcDecryptBackend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BK> ParBlocksSizeUser for CbcDecryptBackend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type ParBlocksSize = BK::ParBlocksSize;
}

impl<BS, BK> BlockModeDecBackend for CbcDecryptBackend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn decrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut t = block.clone_in();
        block.xor_in2out(self.iv);
        self.cipher_backend.encrypt_block((&mut t).into());
        *self.iv = t;
    }

    #[inline(always)]
    fn decrypt_par_blocks(&mut self, mut blocks: InOut<'_, '_, ParBlocks<Self>>) {
        let mut t = ParBlocks::<Self>::default();
        let b = (blocks.get_in(), &mut t).into();
        self.cipher_backend.encrypt_par_blocks(b);

        let n = t.len();
        blocks.get(0).xor_in2out(self.iv);
        for i in 1..n {
            blocks.get(i).xor_in2out(&t[i - 1])
        }
        *self.iv = t[n - 1].clone();
    }
}

#[inline(always)]
fn xor_set2(buf1: &mut [u8], buf2: &mut [u8]) {
    for (a, b) in buf1.iter_mut().zip(buf2) {
        let t = *a;
        *a ^= *b;
        *b = t;
    }
}
