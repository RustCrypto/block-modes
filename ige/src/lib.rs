//! [Infinite Garble Extension][1] (IGE) block cipher mode of operation.
//!
//! <img src="https://raw.githubusercontent.com/RustCrypto/media/26acc39f/img/block-modes/ige_enc.svg" width="49%" />
//! <img src="https://raw.githubusercontent.com/RustCrypto/media/26acc39f/img/block-modes/ige_dec.svg" width="49%"/>
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
//! type Aes128IgeEnc = ige::Encryptor<aes::Aes128>;
//! type Aes128IgeDec = ige::Decryptor<aes::Aes128>;
//!
//! let key = [0x42; 16];
//! let iv = [0x24; 32];
//! let plaintext = *b"hello world! this is my plaintext.";
//! let ciphertext = hex!(
//!     "e3da005add5f05d45899f64891f7629b"
//!     "6fcff7d21537fcd3569373d25701a5d1"
//!     "d9e586e4c5b8ac09f2190485a76873c2"
//! );
//!
//! // encrypt/decrypt in-place
//! // buffer must be big enough for padded plaintext
//! let mut buf = [0u8; 48];
//! let pt_len = plaintext.len();
//! buf[..pt_len].copy_from_slice(&plaintext);
//! let ct = Aes128IgeEnc::new(&key.into(), &iv.into())
//!     .encrypt_padded::<Pkcs7>(&mut buf, pt_len)
//!     .unwrap();
//! assert_eq!(ct, &ciphertext[..]);
//!
//! let pt = Aes128IgeDec::new(&key.into(), &iv.into())
//!     .decrypt_padded::<Pkcs7>(&mut buf)
//!     .unwrap();
//! assert_eq!(pt, &plaintext);
//!
//! // encrypt/decrypt from buffer to buffer
//! let mut buf = [0u8; 48];
//! let ct = Aes128IgeEnc::new(&key.into(), &iv.into())
//!     .encrypt_padded_b2b::<Pkcs7>(&plaintext, &mut buf)
//!     .unwrap();
//! assert_eq!(ct, &ciphertext[..]);
//!
//! let mut buf = [0u8; 48];
//! let pt = Aes128IgeDec::new(&key.into(), &iv.into())
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
//! # type Aes128IgeEnc = ige::Encryptor<aes::Aes128>;
//! # type Aes128IgeDec = ige::Decryptor<aes::Aes128>;
//! # let key = [0x42; 16];
//! # let iv = [0x24; 32];
//! # let plaintext = *b"hello world! this is my plaintext.";
//! # let ciphertext = hex!(
//! #     "e3da005add5f05d45899f64891f7629b"
//! #     "6fcff7d21537fcd3569373d25701a5d1"
//! #     "d9e586e4c5b8ac09f2190485a76873c2"
//! # );
//! let res = Aes128IgeEnc::new(&key.into(), &iv.into())
//!     .encrypt_padded_vec::<Pkcs7>(&plaintext);
//! assert_eq!(res[..], ciphertext[..]);
//! let res = Aes128IgeDec::new(&key.into(), &iv.into())
//!     .decrypt_padded_vec::<Pkcs7>(&res)
//!     .unwrap();
//! assert_eq!(res[..], plaintext[..]);
//! # }
//! ```
//! [1]: https://www.links.org/files/openssl-ige.pdf

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]

mod decrypt;
mod encrypt;

pub use cipher;
pub use decrypt::Decryptor;
pub use encrypt::Encryptor;

use cipher::{
    BlockSizeUser,
    array::{Array, ArraySize},
    typenum::Sum,
};

type BlockSize<C> = <C as BlockSizeUser>::BlockSize;
type IgeIvSize<C> = Sum<BlockSize<C>, BlockSize<C>>;

#[inline(always)]
fn xor<N: ArraySize>(out: &mut Array<u8, N>, buf: &Array<u8, N>) {
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}
