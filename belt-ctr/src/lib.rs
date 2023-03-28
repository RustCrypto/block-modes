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
//! use belt_ctr::flavors::ctr128::Ctr128LE;
//!
//! type BeltCtrT = BeltCtr<BeltBlock, Ctr128LE>;
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
//! let mut cipher = BeltCtrT::new_from_slices(&key, &iv).unwrap();
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

/// Flavors for LE and BE U128
pub mod flavors;

use crate::flavors::CtrFlavor;

use cipher::{
    crypto_common::InnerUser, generic_array::GenericArray, inout::InOutBuf, BlockCipher,
    BlockEncrypt, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv, IvSizeUser, IvState,
    StreamCipher, StreamCipherError,
};

/// BelT CTR Mode
pub struct BeltCtr<C, F>
where
    C: BlockEncryptMut + BlockCipher,
    F: CtrFlavor<C::BlockSize>,
{
    cipher: C,
    f: F::CtrNonce,
}

impl<C, F> BeltCtr<C, F>
where
    C: BlockEncryptMut + BlockCipher + BlockEncrypt,
    F: CtrFlavor<C::BlockSize>,
{
    fn gen_block(&mut self) -> GenericArray<u8, C::BlockSize> {
        let mut nonce = F::next_block(&mut self.f);
        self.cipher.encrypt_block(&mut nonce);
        nonce
    }

    fn gen_init_block(&mut self) -> GenericArray<u8, C::BlockSize> {
        let mut nonce = F::next_block(&mut self.f);
        self.cipher.encrypt_block(&mut nonce);
        F::increment(&mut nonce);
        nonce
    }
}

impl<C, F> StreamCipher for BeltCtr<C, F>
where
    C: BlockEncryptMut + BlockCipher + BlockEncrypt,
    F: CtrFlavor<C::BlockSize, Backend = u128>,
{
    fn try_apply_keystream_inout(
        &mut self,
        data: InOutBuf<'_, '_, u8>,
    ) -> Result<(), StreamCipherError> {
        self.f = F::from_nonce(&self.gen_init_block());

        let (blocks, mut leftover) = data.into_chunks();

        for mut block in blocks {
            block.xor_in2out(&self.gen_block());
        }

        let n = leftover.len();
        let s = self.gen_block();
        leftover.xor_in2out(&s[..n]);

        Ok(())
    }
}

impl<C, F> BlockSizeUser for BeltCtr<C, F>
where
    C: BlockEncryptMut + BlockCipher,
    F: CtrFlavor<C::BlockSize>,
{
    type BlockSize = C::BlockSize;
}

impl<C, F> IvSizeUser for BeltCtr<C, F>
where
    C: BlockEncryptMut + BlockCipher,
    F: CtrFlavor<C::BlockSize>,
{
    type IvSize = C::BlockSize;
}

impl<C, F> InnerUser for BeltCtr<C, F>
where
    C: BlockEncryptMut + BlockCipher,
    F: CtrFlavor<C::BlockSize>,
{
    type Inner = C;
}

impl<C, F> IvState for BeltCtr<C, F>
where
    C: BlockEncryptMut + BlockCipher,
    F: CtrFlavor<C::BlockSize>,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        F::current_block(&self.f)
    }
}

impl<C, F> InnerIvInit for BeltCtr<C, F>
where
    C: BlockEncryptMut + BlockCipher,
    F: CtrFlavor<C::BlockSize>,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            f: F::from_nonce(iv),
        }
    }
}
