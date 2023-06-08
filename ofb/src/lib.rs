//! [Output feedback][1] (OFB) mode.
//!
//! <img src="https://raw.githubusercontent.com/RustCrypto/media/26acc39f/img/block-modes/ofb_enc.svg" width="49%" />
//! <img src="https://raw.githubusercontent.com/RustCrypto/media/26acc39f/img/block-modes/ofb_dec.svg" width="49%"/>
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
//! use aes::cipher::{KeyIvInit, StreamCipher};
//! use hex_literal::hex;
//!
//! type Aes128Ofb = ofb::Ofb<aes::Aes128>;
//!
//! let key = [0x42; 16];
//! let iv = [0x24; 16];
//! let plaintext = *b"hello world! this is my plaintext.";
//! let ciphertext = hex!(
//!     "3357121ebb5a29468bd861467596ce3dc6ba5df50e536a2443b8ee16c2f7cd0869c9"
//! );
//!
//! // encrypt in-place
//! let mut buf = plaintext.to_vec();
//! let mut cipher = Aes128Ofb::new(&key.into(), &iv.into());
//! cipher.apply_keystream(&mut buf);
//! assert_eq!(buf[..], ciphertext[..]);
//!
//! // OFB mode can be used with streaming messages
//! let mut cipher = Aes128Ofb::new(&key.into(), &iv.into());
//! for chunk in buf.chunks_mut(3) {
//!     cipher.apply_keystream(chunk);
//! }
//! assert_eq!(buf[..], plaintext[..]);
//!
//! // encrypt/decrypt from buffer to buffer
//! // buffer length must be equal to input length
//! let mut buf1 = [0u8; 34];
//! let mut cipher = Aes128Ofb::new(&key.into(), &iv.into());
//! cipher
//!     .apply_keystream_b2b(&plaintext, &mut buf1)
//!     .unwrap();
//! assert_eq!(buf1[..], ciphertext[..]);
//!
//! let mut buf2 = [0u8; 34];
//! let mut cipher = Aes128Ofb::new(&key.into(), &iv.into());
//! cipher.apply_keystream_b2b(&buf1, &mut buf2).unwrap();
//! assert_eq!(buf2[..], plaintext[..]);
//! ```
//!
//! [1]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)

#![no_std]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]

pub use cipher;

mod backend;

use cipher::{
    crypto_common::{InnerUser, IvSizeUser},
    AlgorithmName, Block, BlockCipher, BlockClosure, BlockDecryptMut, BlockEncryptMut,
    BlockSizeUser, InnerIvInit, Iv, IvState, StreamCipherCore, StreamCipherCoreWrapper,
    StreamClosure,
};
use core::fmt;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Buffered Output feedback (OFB) mode.
pub type Ofb<C> = StreamCipherCoreWrapper<OfbCore<C>>;

/// Output feedback (OFB) mode.
#[derive(Clone)]
pub struct OfbCore<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    cipher: C,
    iv: Block<C>,
}

impl<C> BlockSizeUser for OfbCore<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type BlockSize = C::BlockSize;
}

impl<C> InnerUser for OfbCore<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type Inner = C;
}

impl<C> IvSizeUser for OfbCore<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for OfbCore<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn inner_iv_init(cipher: C, iv: &Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C> IvState for OfbCore<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

impl<C> StreamCipherCore for OfbCore<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend_mut(backend::Closure1 { iv, f });
    }
}

impl<C> BlockEncryptMut for OfbCore<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn encrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend_mut(backend::Closure2 { iv, f })
    }
}

impl<C> BlockDecryptMut for OfbCore<C>
where
    C: BlockEncryptMut + BlockCipher,
{
    #[inline]
    fn decrypt_with_backend_mut(&mut self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend_mut(backend::Closure2 { iv, f })
    }
}

impl<C> AlgorithmName for OfbCore<C>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ofb<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for OfbCore<C>
where
    C: BlockEncryptMut + BlockCipher + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OfbCore<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockEncryptMut + BlockCipher> Drop for OfbCore<C> {
    fn drop(&mut self) {
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<C: BlockEncryptMut + BlockCipher + ZeroizeOnDrop> ZeroizeOnDrop for OfbCore<C> {}
