//! [Xor-Encrypt-Xor Tweaked-codebook with ciphertext Stealing][1] (XTS) mode.
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
//! use aes::cipher::{BlockModeEncrypt, BlockModeDecrypt, KeyIvInit};
//! use hex_literal::hex;
//!
//! type Aes128XtsEnc = xts::Encryptor<aes::Aes128>;
//! type Aes128XtsDec = xts::Decryptor<aes::Aes128>;
//!
//! let key = [0x42; 32];
//! let tweak = [0x24; 16];
//! let plaintext = *b"hello world! this is my plaintext.";
//! let ciphertext = hex!( // TODO fix this
//!     "c7fe247ef97b21f07cbdd26cb5d346bf"
//!     "d27867cb00d9486723e159978fb9a5f9"
//!     "14cfb228a710de4171e396e7b6cf859e"
//! );
//!
//! // encrypt/decrypt in-place
//! // buffer must be big enough for padded plaintext
//! let pt_len = plaintext.len();
//! let mut buf = [0u8; pt_len];
//! buf.copy_from_slice(&plaintext);
//! Aes128XtsEnc::new(&key.into(), &tweak.into())
//!     .encrypt_blocks(&mut buf)
//!     .unwrap();
//! assert_eq!(&buf, &ciphertext);
//!
//! Aes128XtsDec::new(&key.into(), &iv.into())
//!     .decrypt_blocks(&mut buf)
//!     .unwrap();
//! assert_eq!(&buf, &plaintext);
//!
//! // encrypt/decrypt from buffer to buffer
//! let mut buf = [0u8; pt_len];
//! Aes128XtsEnc::new(&key.into(), &iv.into())
//!     .encrypt_blocks_b2b(&plaintext, &mut buf)
//!     .unwrap();
//! assert_eq!(&buf, &ciphertext);
//!
//! let pt = Aes128XtsDec::new(&key.into(), &iv.into())
//!     .decrypt_blocks_b2b(&ct, &mut buf)
//!     .unwrap();
//! assert_eq!(&buf, &plaintext);
//! ```
//!
//! With enabled `alloc` (or `std`) feature you also can use allocating
//! convenience methods:
//! NOTE FOR REVIEWER: Aren't we missing a `encrypt_blocks_vec` method or something in the cipher crate?
//! ```
//! # use aes::cipher::{BlockModeEncrypt, BlockModeDecrypt, KeyIvInit};
//! # use hex_literal::hex;
//! # type Aes128XtsEnc = xts::Encryptor<aes::Aes128>;
//! # type Aes128XtsDec = xts::Decryptor<aes::Aes128>;
//! # let key = [0x42; 32];
//! # let iv = [0x24; 16];
//! # let plaintext = *b"hello world! this is my plaintext.";
//! # let ciphertext = hex!(
//! #     "c7fe247ef97b21f07cbdd26cb5d346bf"
//! #     "d27867cb00d9486723e159978fb9a5f9"
//! #     "14cfb228a710de4171e396e7b6cf859e"
//! # );
//! // let res = Aes128CbcEnc::new(&key.into(), &iv.into())
//! //     .encrypt_blocks_vec(&plaintext);
//! // assert_eq!(res[..], ciphertext[..]);
//! // let res = Aes128CbcDec::new(&key.into(), &iv.into())
//! //     .decrypt_padded_vec::<Pkcs7>(&res)
//! //     .unwrap();
//! // assert_eq!(res[..], plaintext[..]);
//! # }
//! ```
//!
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
mod xts_core;

pub use decrypt::Decryptor;
pub use encrypt::Encryptor;

#[inline(always)]
fn xor<N: ArraySize>(out: &mut Array<u8, N>, buf: &Array<u8, N>) {
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}
