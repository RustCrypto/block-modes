//! [BelT Electronic Codebook][1] (ECB) mode.
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
//!
//! // encrypt/decrypt in-place
//! use belt_block::BeltBlock;
//! use cipher::KeyInit;
//! use belt_ecb::{BufDecryptor, BufEncryptor};
//!
//! type BeltEcbEnc = BufEncryptor<BeltBlock>;
//! type BeltEcbDec = BufDecryptor<BeltBlock>;
//!
//!
//! let key = [0x42; 32];
//! let mut buf = [0u8; 48];
//! let pt = buf.clone();
//!
//! let mut enc = BeltEcbEnc::new_from_slice(&key).unwrap();
//! enc.encrypt(&mut buf);
//!
//! let mut dec = BeltEcbDec::new_from_slice(&key).unwrap();
//! dec.decrypt(&mut buf);
//!
//! assert_eq!(buf, pt);
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

mod decrypt;
mod encrypt;

pub use cipher;
pub use decrypt::BufDecryptor;
pub use encrypt::BufEncryptor;
