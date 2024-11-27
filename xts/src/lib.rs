//! [Xor-Encrypt-Xor Tweaked-codebook with ciphertext Stealing][1] (XTS) mode.
//!
//! Mode functionality is accessed using traits from re-exported [`cipher`] crate.
//!
//! # ⚠️ Security Warning: Hazmat!
//!
//! This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
//! is not verified, which can lead to serious vulnerabilities!
//! [AEADs](https://github.com/RustCrypto/AEADs) provide simple authenticated encryption,
//! which is much less error-prone than manual integrity verification.
//!
//! # Example
//! ```
//! use aes::cipher::KeyIvInit;
//! use hex_literal::hex;
//!
//! type Aes128XtsEnc = xts::Encryptor<aes::Aes128>;
//! type Aes128XtsDec = xts::Decryptor<aes::Aes128>;
//!
//! let key = [0x42u8; 32];
//! let mut tweak = [0x24u8; 16];
//! tweak[8..].fill(0);
//!
//! let plaintext = *b"hello world! this is my plaintext.";
//! let ciphertext = hex!( // TODO fix this
//!     "bf970595626410ad91f032cc5fa36bcafb5cfe9c2bfe7e226582ec079a27e8c8521c"
//! );
//!
//! // encrypt/decrypt in-place
//! // XTS does not need padding, so output is the same length as the buffer
//! let pt_len = plaintext.len();
//! let mut buf = vec![0u8; pt_len];
//! buf.copy_from_slice(&plaintext);
//!
//! Aes128XtsEnc::new(&key.into(), &tweak.into())
//!     .encrypt(&mut buf)
//!     .unwrap();
//! assert_eq!(&buf, &ciphertext);
//!
//! Aes128XtsDec::new(&key.into(), &tweak.into())
//!     .decrypt(&mut buf)
//!     .unwrap();
//! assert_eq!(&buf, &plaintext);
//!
//! // encrypt/decrypt from buffer to buffer
//! let mut buf = vec![0u8; pt_len];
//! Aes128XtsEnc::new(&key.into(), &tweak.into())
//!     .encrypt_b2b(&plaintext, &mut buf)
//!     .unwrap();
//! assert_eq!(&buf, &ciphertext);
//!
//! Aes128XtsDec::new(&key.into(), &tweak.into())
//!     .decrypt_b2b(&ciphertext, &mut buf)
//!     .unwrap();
//! assert_eq!(&buf, &plaintext);
//! ```
//! [1]: https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]

use cipher::array::{Array, ArraySize};

mod decrypt;
mod encrypt;
mod gf;
mod xts_core;

pub use cipher;
pub use decrypt::{Decryptor, SplitDecryptor};
pub use encrypt::{Encryptor, SplitEncryptor};

/// Error which indicates that message is smaller than cipher's block size.
#[derive(Copy, Clone, Debug)]
pub struct Error;

/// Result type of the crate.
pub type Result<T> = core::result::Result<T, Error>;

#[inline(always)]
fn xor<N: ArraySize>(out: &mut Array<u8, N>, buf: &Array<u8, N>) {
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}
