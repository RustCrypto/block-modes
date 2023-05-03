use belt_block::BeltBlock;
use cipher::consts::U1;
use cipher::crypto_common::InnerInit;
use cipher::inout::InOut;
use cipher::{
    crypto_common::InnerUser, AlgorithmName, ArrayLength, Block, BlockBackend, BlockCipher,
    BlockClosure, BlockEncryptMut, BlockSizeUser, ParBlocksSizeUser, Unsigned,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::ZeroizeOnDrop;

/// ECB mode buffered encryptor.
#[derive(Clone)]
pub struct BufEncryptor<C = BeltBlock>
where
    C: BlockEncryptMut + BlockCipher,
{
    cipher: C,
}

impl<C> BufEncryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    /// Encrypt a buffer in multiple parts.
    pub fn encrypt(&mut self, data: &mut [u8]) {
        let bs = C::BlockSize::USIZE;
        let len = data.len();
        let n = len / bs;


        {
            let mut chunks = data.chunks_exact_mut(bs);
            for chunk in chunks.by_ref() {
                self.cipher.encrypt_block_mut(chunk.into());
            }
        }
        let tail_len = len % bs;
        let mut block: Block<C> = Default::default();

        if tail_len != 0 {
            {
                let two_last = &mut data[(n - 1) * bs..];
                let last_block = &two_last[..bs];
                let tail = &two_last[bs..];

                let r = &last_block[tail_len..];
                block[..tail_len].copy_from_slice(tail);
                block[tail_len..].copy_from_slice(r);
                self.cipher.encrypt_block_mut(&mut block);
            }

            for i in 0..tail_len + 1 {
                let t = data[(n - 1) * bs + i];
                data[(n - 1) * bs + i] = block[i];
                block[i] = t
            }

            data[n * bs..].copy_from_slice(&block[..tail_len]);
        }
    }
}

impl<C> InnerUser for BufEncryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type Inner = C;
}

impl<C> InnerInit for BufEncryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    fn inner_init(cipher: Self::Inner) -> Self {
        Self { cipher }
    }
}

impl<C> AlgorithmName for BufEncryptor<C>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ecb::BufEncryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for BufEncryptor<C>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ecb::BufEncryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockEncryptMut + BlockCipher + ZeroizeOnDrop> ZeroizeOnDrop for BufEncryptor<C> {}

struct Closure<BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    f: BC,
}

impl<BS, BC> BlockSizeUser for Closure<BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BC> BlockClosure for Closure<BS, BC>
where
    BS: ArrayLength<u8>,
    BC: BlockClosure<BlockSize = BS>,
{
    #[inline(always)]
    fn call<B: BlockBackend<BlockSize = Self::BlockSize>>(self, backend: &mut B) {
        let Self { f } = self;
        f.call(&mut Backend { backend });
    }
}

struct Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    backend: &'a mut BK,
}

impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
where
    BS: ArrayLength<u8>,
    BK: BlockBackend<BlockSize = BS>,
{
    type BlockSize = BS;
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
        let mut t = block.get_out().clone();
        self.backend.proc_block((&mut t).into());
    }
}

impl<C> BlockSizeUser for BufEncryptor<C>
where
    C: BlockCipher + BlockEncryptMut,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockEncryptMut for BufEncryptor<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    fn encrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher } = self;
        cipher.encrypt_with_backend_mut(Closure { f })
    }
}
