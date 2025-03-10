use crate::{IgeIvSize, xor};
use cipher::{
    AlgorithmName, Block, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt,
    BlockModeEncBackend, BlockModeEncClosure, BlockModeEncrypt, BlockSizeUser, InnerIvInit, Iv,
    IvState, ParBlocksSizeUser,
    array::{Array, ArraySize},
    crypto_common::{BlockSizes, InnerUser, IvSizeUser},
    inout::InOut,
    typenum::{U1, Unsigned},
};
use core::{fmt, ops::Add};

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// IGE mode encryptor.
#[derive(Clone)]
pub struct Encryptor<C>
where
    C: BlockCipherEncrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    cipher: C,
    x: Block<C>,
    y: Block<C>,
}

impl<C> BlockModeEncrypt for Encryptor<C>
where
    C: BlockCipherEncrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    fn encrypt_with_backend(&mut self, f: impl BlockModeEncClosure<BlockSize = Self::BlockSize>) {
        struct Closure<'a, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeEncClosure<BlockSize = BS>,
        {
            x: &'a mut Array<u8, BS>,
            y: &'a mut Array<u8, BS>,
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
                let Self { x, y, f } = self;
                f.call(&mut Backend {
                    x,
                    y,
                    cipher_backend,
                });
            }
        }

        let Self { cipher, x, y } = self;
        cipher.encrypt_with_backend(Closure { x, y, f })
    }
}

impl<C> BlockSizeUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    type BlockSize = C::BlockSize;
}

impl<C> InnerUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    type Inner = C;
}

impl<C> IvSizeUser for Encryptor<C>
where
    C: BlockCipherEncrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    type IvSize = IgeIvSize<C>;
}

impl<C> InnerIvInit for Encryptor<C>
where
    C: BlockCipherEncrypt,
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

impl<C> IvState for Encryptor<C>
where
    C: BlockCipherEncrypt,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.y.clone().concat(self.x.clone())
    }
}

impl<C> AlgorithmName for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ige::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for Encryptor<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ige::Encryptor<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

impl<C> Drop for Encryptor<C>
where
    C: BlockCipherEncrypt,
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
impl<C> ZeroizeOnDrop for Encryptor<C>
where
    C: BlockCipherEncrypt + ZeroizeOnDrop,
    C::BlockSize: Add,
    IgeIvSize<C>: ArraySize,
{
}

struct Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    x: &'a mut Array<u8, BS>,
    y: &'a mut Array<u8, BS>,
    cipher_backend: &'a BK,
}

impl<BS, BK> BlockSizeUser for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<BS, BK> ParBlocksSizeUser for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type ParBlocksSize = U1;
}

impl<BS, BK> BlockModeEncBackend for Backend<'_, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn encrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let new_x = block.clone_in();
        let mut t = new_x.clone();
        xor(&mut t, self.y);
        self.cipher_backend.encrypt_block((&mut t).into());
        xor(&mut t, self.x);
        *block.get_out() = t.clone();
        *self.x = new_x;
        *self.y = t;
    }
}
