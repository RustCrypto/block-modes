//! [Propagating Cipher Block Chaining][1] (PCBC) mode.
//!
//! <img src="https://raw.githubusercontent.com/RustCrypto/media/26acc39f/img/block-modes/pcbc_enc.svg" width="49%" />
//! <img src="https://raw.githubusercontent.com/RustCrypto/media/26acc39f/img/block-modes/pcbc_dec.svg" width="49%"/>
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
//! # #[cfg(feature = "block-padding")] {
//! use aes::cipher::{block_padding::Pkcs7, BlockModeEncrypt, BlockModeDecrypt, KeyIvInit};
//! use hex_literal::hex;
//!
//! type Aes128PcbcEnc = pcbc::Encryptor<aes::Aes128>;
//! type Aes128PcbcDec = pcbc::Decryptor<aes::Aes128>;
//!
//! let key = [0x42; 16];
//! let iv = [0x24; 16];
//! let plaintext = *b"hello world! this is my plaintext.";
//! let ciphertext = hex!(
//!     "c7fe247ef97b21f07cbdd26cb5d346bf"
//!     "ab13156d0b2f05f91c4837db5157bad5"
//!     "62cb0b6fa7816e254a2fc8d852fb4315"
//! );
//!
//! // encrypt/decrypt in-place
//! // buffer must be big enough for padded plaintext
//! let mut buf = vec![0u8; 48];
//! let pt_len = plaintext.len();
//! buf[..pt_len].copy_from_slice(&plaintext);
//! let ct = Aes128PcbcEnc::new(&key.into(), &iv.into())
//!     .encrypt_padded::<Pkcs7>(&mut buf, pt_len)
//!     .unwrap();
//! assert_eq!(ct, &ciphertext[..]);
//!
//! let pt = Aes128PcbcDec::new(&key.into(), &iv.into())
//!     .decrypt_padded::<Pkcs7>(&mut buf)
//!     .unwrap();
//! assert_eq!(pt, &plaintext);
//!
//! // encrypt/decrypt from buffer to buffer
//! let mut buf = vec![0u8; 48];
//! let ct = Aes128PcbcEnc::new(&key.into(), &iv.into())
//!     .encrypt_padded_b2b::<Pkcs7>(&plaintext, &mut buf)
//!     .unwrap();
//! assert_eq!(ct, &ciphertext[..]);
//!
//! let mut buf = vec![0u8; 48];
//! let pt = Aes128PcbcDec::new(&key.into(), &iv.into())
//!     .decrypt_padded_b2b::<Pkcs7>(&ct, &mut buf)
//!     .unwrap();
//! assert_eq!(pt, &plaintext);
//! # }
//! ```
//!
//! With enabled `alloc` (or `std`) feature you also can use allocating
//! convenience methods:
//! ```
//! # #[cfg(all(feature = "alloc", feature = "block-padding"))] {
//! # use aes::cipher::{block_padding::Pkcs7, BlockModeEncrypt, BlockModeDecrypt, KeyIvInit};
//! # use hex_literal::hex;
//! # type Aes128PcbcEnc = pcbc::Encryptor<aes::Aes128>;
//! # type Aes128PcbcDec = pcbc::Decryptor<aes::Aes128>;
//! # let key = [0x42; 16];
//! # let iv = [0x24; 16];
//! # let plaintext = *b"hello world! this is my plaintext.";
//! # let ciphertext = hex!(
//! #     "c7fe247ef97b21f07cbdd26cb5d346bf"
//! #     "ab13156d0b2f05f91c4837db5157bad5"
//! #     "62cb0b6fa7816e254a2fc8d852fb4315"
//! # );
//! let res = Aes128PcbcEnc::new(&key.into(), &iv.into())
//!     .encrypt_padded_vec::<Pkcs7>(&plaintext);
//! assert_eq!(res[..], ciphertext[..]);
//! let res = Aes128PcbcDec::new(&key.into(), &iv.into())
//!     .decrypt_padded_vec::<Pkcs7>(&res)
//!     .unwrap();
//! assert_eq!(res[..], plaintext[..]);
//! # }
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Propagating_cipher_block_chaining_(PCBC)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]

mod decrypt;
mod encrypt;

pub use cipher;
pub use decrypt::Decryptor;
pub use encrypt::Encryptor;

use cipher::array::{Array, ArraySize};

#[inline(always)]
fn xor<N: ArraySize>(out: &mut Array<u8, N>, buf: &Array<u8, N>) {
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}
