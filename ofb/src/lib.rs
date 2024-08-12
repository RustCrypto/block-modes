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

use cipher::{
    consts::U1,
    crypto_common::{BlockSizes, InnerUser, IvSizeUser},
    AlgorithmName, Array, Block, BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt,
    BlockModeDecBackend, BlockModeDecClosure, BlockModeDecrypt, BlockModeEncBackend,
    BlockModeEncClosure, BlockModeEncrypt, BlockSizeUser, InOut, InnerIvInit, Iv, IvState,
    ParBlocksSizeUser, StreamBackend, StreamCipherCore, StreamCipherCoreWrapper, StreamClosure,
};
use core::fmt;

pub use cipher;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

/// Buffered Output feedback (OFB) mode.
pub type Ofb<C> = StreamCipherCoreWrapper<OfbCore<C>>;

/// Output feedback (OFB) mode.
#[derive(Clone)]
pub struct OfbCore<C>
where
    C: BlockCipherEncrypt,
{
    cipher: C,
    iv: Block<C>,
}

impl<C> BlockSizeUser for OfbCore<C>
where
    C: BlockCipherEncrypt,
{
    type BlockSize = C::BlockSize;
}

impl<C> InnerUser for OfbCore<C>
where
    C: BlockCipherEncrypt,
{
    type Inner = C;
}

impl<C> IvSizeUser for OfbCore<C>
where
    C: BlockCipherEncrypt,
{
    type IvSize = C::BlockSize;
}

impl<C> InnerIvInit for OfbCore<C>
where
    C: BlockCipherEncrypt,
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
    C: BlockCipherEncrypt,
{
    #[inline]
    fn iv_state(&self) -> Iv<Self> {
        self.iv.clone()
    }
}

impl<C> StreamCipherCore for OfbCore<C>
where
    C: BlockCipherEncrypt,
{
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn process_with_backend(&mut self, f: impl StreamClosure<BlockSize = Self::BlockSize>) {
        pub(crate) struct Closure<'a, BS, SC>
        where
            BS: BlockSizes,
            SC: StreamClosure<BlockSize = BS>,
        {
            pub(crate) iv: &'a mut Array<u8, BS>,
            pub(crate) f: SC,
        }

        impl<'a, BS, SC> BlockSizeUser for Closure<'a, BS, SC>
        where
            BS: BlockSizes,
            SC: StreamClosure<BlockSize = BS>,
        {
            type BlockSize = BS;
        }

        impl<'a, BS, SC> BlockCipherEncClosure for Closure<'a, BS, SC>
        where
            BS: BlockSizes,
            SC: StreamClosure<BlockSize = BS>,
        {
            #[inline(always)]
            fn call<B: BlockCipherEncBackend<BlockSize = Self::BlockSize>>(self, backend: &B) {
                let Self { iv, f } = self;
                f.call(&mut Backend { iv, backend });
            }
        }

        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend(Closure { iv, f });
    }
}

impl<C> BlockModeEncrypt for OfbCore<C>
where
    C: BlockCipherEncrypt,
{
    #[inline]
    fn encrypt_with_backend(&mut self, f: impl BlockModeEncClosure<BlockSize = Self::BlockSize>) {
        pub(crate) struct Closure<'a, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeEncClosure<BlockSize = BS>,
        {
            pub(crate) iv: &'a mut Array<u8, BS>,
            pub(crate) f: BC,
        }

        impl<'a, BS, BC> BlockSizeUser for Closure<'a, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeEncClosure<BlockSize = BS>,
        {
            type BlockSize = BS;
        }

        impl<'a, BS, BC> BlockCipherEncClosure for Closure<'a, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeEncClosure<BlockSize = BS>,
        {
            #[inline(always)]
            fn call<B: BlockCipherEncBackend<BlockSize = Self::BlockSize>>(self, backend: &B) {
                let Self { iv, f } = self;
                f.call(&mut Backend { iv, backend });
            }
        }

        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend(Closure { iv, f })
    }
}

impl<C> BlockModeDecrypt for OfbCore<C>
where
    C: BlockCipherEncrypt,
{
    #[inline]
    fn decrypt_with_backend(&mut self, f: impl BlockModeDecClosure<BlockSize = Self::BlockSize>) {
        pub(crate) struct Closure<'a, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeDecClosure<BlockSize = BS>,
        {
            pub(crate) iv: &'a mut Array<u8, BS>,
            pub(crate) f: BC,
        }

        impl<'a, BS, BC> BlockSizeUser for Closure<'a, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeDecClosure<BlockSize = BS>,
        {
            type BlockSize = BS;
        }

        impl<'a, BS, BC> BlockCipherEncClosure for Closure<'a, BS, BC>
        where
            BS: BlockSizes,
            BC: BlockModeDecClosure<BlockSize = BS>,
        {
            #[inline(always)]
            fn call<B: BlockCipherEncBackend<BlockSize = Self::BlockSize>>(self, backend: &B) {
                let Self { iv, f } = self;
                f.call(&mut Backend { iv, backend });
            }
        }

        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend(Closure { iv, f })
    }
}

impl<C> AlgorithmName for OfbCore<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ofb<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<C> fmt::Debug for OfbCore<C>
where
    C: BlockCipherEncrypt + AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OfbCore<")?;
        <C as AlgorithmName>::write_alg_name(f)?;
        f.write_str("> { ... }")
    }
}

impl<C: BlockCipherEncrypt> Drop for OfbCore<C> {
    fn drop(&mut self) {
        #[cfg(feature = "zeroize")]
        self.iv.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<C: BlockCipherEncrypt + ZeroizeOnDrop> ZeroizeOnDrop for OfbCore<C> {}

pub(crate) struct Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    pub iv: &'a mut Array<u8, BS>,
    pub backend: &'a BK,
}

impl<'a, BS, BK> BlockSizeUser for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type BlockSize = BS;
}

impl<'a, BS, BK> ParBlocksSizeUser for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    type ParBlocksSize = U1;
}

impl<'a, BS, BK> StreamBackend for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        self.backend.encrypt_block(self.iv.into());
        *block = self.iv.clone();
    }
}

impl<'a, BS, BK> BlockModeEncBackend for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn encrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.backend.encrypt_block(self.iv.into());
        block.xor_in2out(self.iv);
    }
}

impl<'a, BS, BK> BlockModeDecBackend for Backend<'a, BS, BK>
where
    BS: BlockSizes,
    BK: BlockCipherEncBackend<BlockSize = BS>,
{
    #[inline(always)]
    fn decrypt_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        self.backend.encrypt_block(self.iv.into());
        block.xor_in2out(self.iv);
    }
}
