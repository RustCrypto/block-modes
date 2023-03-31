//! Implementation of [BelT CTR][1].
//!
//! Mode functionality is accessed using traits from re-exported [`cipher`] crate.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//! [AEADs][https://github.com/RustCrypto/AEADs] provide simple authenticated encryption,
//! which is much less error-prone than manual integrity verification.
//!
//! # Example
//! ```
//! use belt_block::BeltBlock;
//! use cipher::{KeyIvInit, StreamCipher};
//! use hex_literal::hex;
//! use belt_ctr::BeltCtr;
//!
//! let key = [0x42; 32];
//! let iv = [0x24; 16];
//! let plaintext = *b"hello world! this is my plaintext.";
//! let ciphertext = hex!(
//!     "38DF06243BD85DA1CAE597CE680D3AFE0EBB372A4F6A858DB2DBE20A63567EED7D1B"
//! );
//!
//! // encrypt in-place
//! let mut buf = plaintext.to_vec();
//! let mut cipher: BeltCtr = BeltCtr::new_from_slices(&key, &iv).unwrap();
//! cipher.apply_keystream(&mut buf);
//! println!("{:02X?}", buf);
//! assert_eq!(buf[..], ciphertext[..]);
//!
//! ```
//!
//! [1]: https://apmi.bsu.by/assets/files/std/belt-spec371.pdf

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

use belt_block::BeltBlock;

use cipher::consts::U16;
use cipher::{
    crypto_common::InnerUser, generic_array::GenericArray, inout::InOutBuf, BlockEncrypt,
    BlockSizeUser, InnerIvInit, Iv, IvSizeUser, IvState, StreamCipher, StreamCipherCore,
    StreamCipherError, StreamCipherSeekCore, StreamClosure,
};

/// BelT CTR Mode
pub struct BeltCtr<C = BeltBlock>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    cipher: C,
    ctr: u128,
    s: GenericArray<u8, C::BlockSize>,
}

impl<C> BeltCtr<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    fn gen_block(&mut self) -> GenericArray<u8, C::BlockSize> {
        self.ctr = self.ctr.wrapping_add(1);
        let s = u128::from_le_bytes(self.s.as_slice().try_into().unwrap()).wrapping_add(self.ctr);
        let mut s = s.to_le_bytes().into();
        self.cipher.encrypt_block(&mut s);
        s
    }
}

impl<C> StreamCipher for BeltCtr<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    fn try_apply_keystream_inout(
        &mut self,
        data: InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError> {
        self.ctr = 0;
        let (blocks, mut leftover) = data.into_chunks();

        for mut block in blocks {
            let s = &self.gen_block();
            block.xor_in2out(s);
        }

        let n = leftover.len();
        let s = self.gen_block();
        leftover.xor_in2out(&s[..n]);

        Ok(())
    }
}

impl<C> StreamCipherCore for BeltCtr<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    fn remaining_blocks(&self) -> Option<usize> {
        (u128::MAX - self.ctr).try_into().ok()
    }

    fn process_with_backend(&mut self, _: impl StreamClosure<BlockSize = Self::BlockSize>) {
        unreachable!("BeltCtr does not support backend processing")
    }
}

impl<C> StreamCipherSeekCore for BeltCtr<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    type Counter = u128;

    fn get_block_pos(&self) -> Self::Counter {
        self.ctr
    }

    fn set_block_pos(&mut self, pos: Self::Counter) {
        self.ctr = pos;
    }
}

impl<C> BlockSizeUser for BeltCtr<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    type BlockSize = C::BlockSize;
}

impl<C> IvSizeUser for BeltCtr<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerUser for BeltCtr<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    type Inner = C;
}

impl<C> IvState for BeltCtr<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.s
    }
}

impl<C> InnerIvInit for BeltCtr<C>
where
    C: BlockEncrypt + BlockSizeUser<BlockSize = U16>,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        let mut s = GenericArray::default();
        cipher.encrypt_block_b2b(iv, &mut s);
        Self { cipher, ctr: 0, s }
    }
}
