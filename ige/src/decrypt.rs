use crate::{xor, IgeIvSize};
use cipher::{
    array::{Array, ArraySize},
    crypto_common::{BlockSizes, InnerUser, IvSizeUser},
    inout::InOut,
    typenum::{Unsigned, U1},
    AlgorithmName, Block, BlockBackend, BlockCipher, BlockCipherDecrypt, BlockClosure,
    BlockModeDecrypt, BlockSizeUser, InnerIvInit, Iv, IvState, ParBlocksSizeUser,
};
use core::{fmt, ops::Add};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// IGE mode decryptor.
#[derive(Clone)]
pub struct Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    cipher: C,
    x: Block<C>,
    y: Block<C>,
}

impl<C> BlockModeDecrypt for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    fn decrypt_with_backend(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, x, y } = self;
        cipher.decrypt_with_backend(Closure { x, y, f })
    }
}

impl<C> BlockSizeUser for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    type BlockSize = C::BlockSize;
}

impl<C> InnerUser for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    type Inner = C;
}

impl<C> IvSizeUser for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    type IvSize = IgeIvSize<C>;
}

impl<C> InnerIvInit for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let (y, x) = iv.split_at(C::BlockSize::to_usize());
        Self {
            cipher,
            x: Array::clone_from_slice(x),
            y: Array::clone_from_slice(y),
        }
    }
}

impl<C> IvState for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.y.clone().concat(self.x.clone())
    }
}

impl<C> AlgorithmName for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher + AlgorithmName,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ige::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher + AlgorithmName,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ige::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> Drop for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    fn drop(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C> ZeroizeOnDrop for Decryptor<C>
where
    C: BlockCipherDecrypt + BlockCipher + ZeroizeOnDrop,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
}

struct Closure<'a, BS, BC>
where
    BS: BlockSizes,
    BC: BlockClosure<BlockSize = BS>,
{
    x: &'a mut Array<u8, BS>,
    y: &'a mut Array<u8, BS>,
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
        let Self { x, y, f } = self;
        f.call(&mut Backend { x, y, backend });
    }
}

struct Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockBackend<BlockSize = BS>,
{
    x: &'a mut Array<u8, BS>,
    y: &'a mut Array<u8, BS>,
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
        let new_y = block.clone_in();
        let mut t = new_y.clone();
        xor(&mut t, self.x);
        self.backend.proc_block((&mut t).into());
        xor(&mut t, self.y);
        *block.get_out() = t.clone();
        *self.x = t;
        *self.y = new_y;
    }
}
