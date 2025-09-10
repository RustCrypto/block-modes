use crate::{IgeIvSize, xor};
use cipher::{
    AlgorithmName, Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt,
    BlockModeDecBackend, BlockModeDecClosure, BlockModeDecrypt, BlockSizeUser, InnerIvInit, Iv,
    IvState, ParBlocksSizeUser,
    array::{Array, ArraySize},
    crypto_common::{BlockSizes, InnerUser, IvSizeUser},
    inout::InOut,
    typenum::{U1, Unsigned},
};
use core::{fmt, ops::Add};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// IGE mode decryptor.
pub struct Decryptor<C>
where
    C: BlockCipherDecrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    cipher: C,
    x: Block<C>,
    y: Block<C>,
}

impl<C> BlockModeDecrypt for Decryptor<C>
where
    C: BlockCipherDecrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    fn decrypt_with_backend(&mut self, f: impl BlockModeDecClosure<BlockSize = Self::BlockSize>) {
        struct Closure<'a, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeDecClosure<BlockSize = BS>,
        {
            x: &'a mut Array<u8, BS>,
            y: &'a mut Array<u8, BS>,
            f: BC,
        }

        impl<BS, BC> BlockSizeUser for Closure<'_, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeDecClosure<BlockSize = BS>,
        {
            type BlockSize = BS;
        }

        impl<BS, BC> BlockCipherDecClosure for Closure<'_, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeDecClosure<BlockSize = BS>,
        {
            #[inline(always)]
            fn call<B: BlockCipherDecBackend<BlockSize = Self::BlockSize>>(
                self,
                cipher_backend: &B,
            ) {
                let Self { x, y, f } = self;
                f.call(&mut Backend {
                    x,
                    y,
                    cipher_backend,
                });
            }
        }

        let Self { cipher, x, y } = self;
        cipher.decrypt_with_backend(Closure { x, y, f })
    }
}

impl<C> BlockSizeUser for Decryptor<C>
where
    C: BlockCipherDecrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    type BlockSize = C::BlockSize;
}

impl<C> InnerUser for Decryptor<C>
where
    C: BlockCipherDecrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    type Inner = C;
}

impl<C> IvSizeUser for Decryptor<C>
where
    C: BlockCipherDecrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    type IvSize = IgeIvSize<C>;
}

impl<C> InnerIvInit for Decryptor<C>
where
    C: BlockCipherDecrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let n = C::BlockSize::USIZE;
        let y = iv[..n].try_into().unwrap();
        let x = iv[n..].try_into().unwrap();
        Self { cipher, x, y }
    }
}

impl<C> IvState for Decryptor<C>
where
    C: BlockCipherDecrypt,
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
    C: BlockCipherDecrypt + AlgorithmName,
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
    C: BlockCipherDecrypt + AlgorithmName,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ige::Decryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

impl<C> Drop for Decryptor<C>
where
    C: BlockCipherDecrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.x.zeroize();
            self.y.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<C> ZeroizeOnDrop for Decryptor<C>
where
    C: BlockCipherDecrypt + ZeroizeOnDrop,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
}

struct Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    x: &'a mut Array<u8, BS>,
    y: &'a mut Array<u8, BS>,
    cipher_backend: &'a BK,
}

impl<BS, BK> BlockSizeUser for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BK> ParBlocksSizeUser for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    type ParBlocksSize = U1;
}

impl<BS, BK> BlockModeDecBackend for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherDecBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn decrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let new_y = block.clone_in();
        let mut t = new_y.clone();
        xor(&mut t, self.x);
        self.cipher_backend.decrypt_block((&mut t).into());
        xor(&mut t, self.y);
        *block.get_out() = t.clone();
        *self.x = t;
        *self.y = new_y;
    }
}
