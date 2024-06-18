use belt_block::BeltBlock;
use cipher::crypto_common::InnerInit;
use cipher::{
    crypto_common::InnerUser, generic_array::ArrayLength, inout::InOut, AlgorithmName, Block,
    BlockBackend, BlockCipher, BlockClosure, BlockDecryptMut, BlockSizeUser, ParBlocksSizeUser,
    Unsigned,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::ZeroizeOnDrop;

/// ECB mode buffered decryptor.
#[derive(Clone)]
pub struct BufDecryptor<C = BeltBlock>
where
    C: BlockDecryptMut + BlockCipher,
{
    cipher: C,
}

impl<C> BufDecryptor<C>
where
    C: BlockDecryptMut + BlockCipher,
{
    /// Decrypt a buffer in multiple parts.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        let bs = C::BlockSize::USIZE;
        let len = data.len();
        let n = len / bs;

        {
            let mut chunks = data.chunks_exact_mut(bs);
            for chunk in chunks.by_ref() {
                self.cipher.decrypt_block_mut(chunk.into());
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
                self.cipher.decrypt_block_mut(&mut block);
            }

            for i in 0..bs {
                let t = data[(n - 1) * bs + i];
                data[(n - 1) * bs + i] = block[i];
                block[i] = t
            }

            data[n * bs..].copy_from_slice(&block[..tail_len]);
        }
    }
}

impl<C> InnerUser for BufDecryptor<C>
where
    C: BlockDecryptMut + BlockCipher,
{
    type Inner = C;
}

impl<C> InnerInit for BufDecryptor<C>
where
    C: BlockDecryptMut + BlockCipher,
{
    #[inline]
    fn inner_init(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C> AlgorithmName for BufDecryptor<C>
where
    C: BlockDecryptMut + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ecb::BufDecryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for BufDecryptor<C>
where
    C: BlockDecryptMut + BlockCipher + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ecb::BufDecryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockDecryptMut + BlockCipher + ZeroizeOnDrop> ZeroizeOnDrop for BufDecryptor<C> {}

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
    type ParBlocksSize = BK::ParBlocksSize;
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

impl<C> BlockSizeUser for BufDecryptor<C>
where
    C: BlockCipher + BlockDecryptMut,
{
    type BlockSize = C::BlockSize;
}

impl<C> BlockDecryptMut for BufDecryptor<C>
where
    C: BlockDecryptMut + BlockCipher,
{
    fn decrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher } = self;
        cipher.decrypt_with_backend_mut(Closure { f })
    }
}
