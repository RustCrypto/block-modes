#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]

pub use cipher;

use belt_block::BeltBlock;
use cipher::{
    consts::U16, crypto_common::InnerUser, generic_array::GenericArray, BlockDecrypt, BlockEncrypt,
    BlockSizeUser, InnerIvInit, Iv, IvSizeUser, IvState, StreamCipherCore, StreamCipherCoreWrapper,
    StreamCipherSeekCore, StreamClosure,
};
use core::fmt;

mod backend;

/// Byte-level BelT CTR
pub type BeltCtr<C = BeltBlock> = StreamCipherCoreWrapper<BeltCtrCore<C>>;

/// Block-level BelT CTR
pub struct BeltCtrCore<C = BeltBlock>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    cipher: C,
    s: u128,
    s_init: u128,
}

impl<C: BlockEncrypt + BlockSizeUser<BlockSize = U16>> fmt::Debug for BeltCtrCore<C> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BeltCtrCore { ... }")
    }
}
impl<C> StreamCipherCore for BeltCtrCore<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    fn remaining_blocks(&self) -> Option<usize> {
        let used = self.s.wrapping_sub(self.s_init);
        (u128::MAX - used).try_into().ok()
    }

    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, s, .. } = self;
        cipher.encrypt_with_backend(backend::Closure { s, f });
    }
}

impl<C> StreamCipherSeekCore for BeltCtrCore<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
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
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    type BlockSize = C::BlockSize;
}

impl<C> IvSizeUser for BeltCtrCore<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerUser for BeltCtrCore<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    type Inner = C;
}

impl<C> InnerIvInit for BeltCtrCore<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let mut t = GenericArray::default();
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
    C: BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16>,
{
    fn iv_state(&self) -> Iv<Self> {
        let mut t = self.s.to_le_bytes().into();
        self.cipher.decrypt_block(&mut t);
        t
    }
}
