#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]

pub use cipher;

use belt_block::BeltBlock;
use cipher::{
    AlgorithmName, Block, BlockCipherDecrypt, BlockCipherEncBackend, BlockCipherEncClosure,
    BlockCipherEncrypt, BlockSizeUser, InOut, InnerIvInit, Iv, IvSizeUser, IvState, ParBlocks,
    ParBlocksSizeUser, StreamCipherBackend, StreamCipherClosure, StreamCipherCore,
    StreamCipherCoreWrapper, StreamCipherSeekCore, array::Array, common::InnerUser, consts::U16,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Byte-level BelT CTR
pub type BeltCtr<C = BeltBlock> = StreamCipherCoreWrapper<BeltCtrCore<C>>;

/// Block-level BelT CTR
pub struct BeltCtrCore<C = BeltBlock>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    cipher: C,
    s: u128,
    s_init: u128,
}

impl<C> StreamCipherCore for BeltCtrCore<C>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    fn remaining_blocks(&self) -> Option<usize> {
        let used = self.s.wrapping_sub(self.s_init);
        (u128::MAX - used).try_into().ok()
    }

    fn process_with_backend(&mut self, f: impl StreamCipherClosure<BlockSize = Self::BlockSize>) {
        struct Closure<'a, C: StreamCipherClosure<BlockSize = U16>> {
            s: &'a mut u128,
            f: C,
        }

        impl<C: StreamCipherClosure<BlockSize = U16>> BlockSizeUser for Closure<'_, C> {
            type BlockSize = U16;
        }

        impl<C: StreamCipherClosure<BlockSize = U16>> BlockCipherEncClosure for Closure<'_, C> {
            #[inline(always)]
            fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, cipher_backend: &B) {
                let Self { s, f } = self;
                f.call(&mut Backend { s, cipher_backend })
            }
        }

        let Self { cipher, s, .. } = self;
        cipher.encrypt_with_backend(Closure { s, f });
    }
}

impl<C> StreamCipherSeekCore for BeltCtrCore<C>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    type Counter = u128;

    fn get_block_pos(&self) -> Self::Counter {
        self.s.wrapping_sub(self.s_init)
    }

    fn set_block_pos(&mut self, pos: Self::Counter) {
        self.s = self.s_init.wrapping_add(pos);
    }
}

impl<C> BlockSizeUser for BeltCtrCore<C>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    type BlockSize = C::BlockSize;
}

impl<C> IvSizeUser for BeltCtrCore<C>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerUser for BeltCtrCore<C>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    type Inner = C;
}

impl<C> InnerIvInit for BeltCtrCore<C>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let mut t = Array::default();
        cipher.encrypt_block_b2b(iv, &mut t);
        let s = u128::from_le_bytes(t.into());
        Self {
            cipher,
            s,
            s_init: s,
        }
    }
}

impl<C> IvState for BeltCtrCore<C>
where
    C: BlockCipherEncrypt + BlockCipherDecrypt + BlockSizeUser<BlockSize = U16>,
{
    fn iv_state(&self) -> Iv<Self> {
        let mut t = self.s.to_le_bytes().into();
        self.cipher.decrypt_block(&mut t);
        t
    }
}

impl<C> AlgorithmName for BeltCtrCore<C>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16> + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltCtr<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for BeltCtrCore<C>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16> + AlgorithmName,
{
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltCtr<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

impl<C: BlockCipherEncrypt> Drop for BeltCtrCore<C>
where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16>,
{
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        {
            self.s.zeroize();
            self.s_init.zeroize();
        }
    }
}

#[cfg(feature = "zeroize")]
impl<C> ZeroizeOnDrop for BeltCtrCore<C> where
    C: BlockCipherEncrypt + BlockSizeUser<BlockSize = U16> + ZeroizeOnDrop
{
}

struct Backend<'a, B: BlockCipherEncBackend<BlockSize = U16>> {
    s: &'a mut u128,
    cipher_backend: &'a B,
}

impl<B: BlockCipherEncBackend<BlockSize = U16>> BlockSizeUser for Backend<'_, B> {
    type BlockSize = B::BlockSize;
}

impl<B: BlockCipherEncBackend<BlockSize = U16>> ParBlocksSizeUser for Backend<'_, B> {
    type ParBlocksSize = B::ParBlocksSize;
}

impl<B: BlockCipherEncBackend<BlockSize = U16>> StreamCipherBackend for Backend<'_, B> {
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        *self.s = self.s.wrapping_add(1);
        let tmp = self.s.to_le_bytes().into();
        self.cipher_backend.encrypt_block((&tmp, block).into());
    }

    #[inline(always)]
    fn gen_par_ks_blocks(&mut self, blocks: &mut ParBlocks<Self>) {
        let mut tmp = ParBlocks::<Self>::default();
        let mut s = *self.s;
        for block in tmp.iter_mut() {
            s = s.wrapping_add(1);
            *block = s.to_le_bytes().into();
        }
        *self.s = s;
        let io_blocks = InOut::from((&tmp, blocks));
        self.cipher_backend.encrypt_par_blocks(io_blocks);
    }
}
