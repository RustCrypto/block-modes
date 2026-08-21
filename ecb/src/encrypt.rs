use cipher::{
    AlgorithmName, Block, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt,
    BlockModeEncBackend, BlockModeEncClosure, BlockModeEncrypt, BlockSizeUser, InOut, InOutBuf,
    ParBlocks, ParBlocksSizeUser,
    array::ArraySize,
    common::{InnerInit, InnerUser},
};
use core::fmt;

/// ECB mode encryptor.
#[derive(Clone)]
pub struct Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    cipher: C,
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
        let Self { cipher } = self;
        cipher.encrypt_with_backend(Closure { f });
    }
}

impl<C> InnerUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    type Inner = C;
}

impl<C> InnerInit for Encryptor<C>
where
    C: BlockCipherEncrypt,
{
    #[inline]
    fn inner_init(cipher: C) -> Self {
        Self { cipher }
    }
}

impl<C> AlgorithmName for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ecb::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ecb::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

struct Closure<BS, BC>
where
    BS: ArraySize,
    BC: BlockModeEncClosure<BlockSize = BS>,
{
    f: BC,
}

impl<BS, BC> BlockSizeUser for Closure<BS, BC>
where
    BS: ArraySize,
    BC: BlockModeEncClosure<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BC> BlockCipherEncClosure for Closure<BS, BC>
where
    BS: ArraySize,
    BC: BlockModeEncClosure<BlockSize = BS>,
{
    #[inline(always)]
    fn call<B: BlockCipherEncBackend<BlockSize = Self::BlockSize>>(self, cipher_backend: &B) {
        let Self { f } = self;
        f.call(&mut Backend { cipher_backend });
    }
}

struct Backend<'a, BS, BK>
where
    BS: ArraySize,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    cipher_backend: &'a BK,
}

impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
where
    BS: ArraySize,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, BK> ParBlocksSizeUser for Backend<'a, BS, BK>
where
    BS: ArraySize,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type ParBlocksSize = BK::ParBlocksSize;
}

impl<'a, BS, BK> BlockModeEncBackend for Backend<'a, BS, BK>
where
    BS: ArraySize,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn encrypt_block(&mut self, block: InOut<'_, '_, Block<Self>>) {
        self.cipher_backend.encrypt_block(block);
    }

    #[inline(always)]
    fn encrypt_par_blocks(&mut self, blocks: InOut<'_, '_, ParBlocks<Self>>) {
        self.cipher_backend.encrypt_par_blocks(blocks);
    }

    #[inline(always)]
    fn encrypt_tail_blocks(&mut self, blocks: InOutBuf<'_, '_, Block<Self>>) {
        self.cipher_backend.encrypt_tail_blocks(blocks);
    }
}
