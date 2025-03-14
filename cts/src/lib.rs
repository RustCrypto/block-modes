#![no_std]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![deny(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs, rust_2018_idioms)]

pub use cipher;

pub use cipher::{KeyInit, KeyIvInit};

mod cbc_cs1;
mod cbc_cs2;
mod cbc_cs3;
mod ecb_cs1;
mod ecb_cs2;
mod ecb_cs3;

pub use cbc_cs1::CbcCs1;
pub use cbc_cs2::CbcCs2;
pub use cbc_cs3::CbcCs3;
pub use ecb_cs1::EcbCs1;
pub use ecb_cs2::EcbCs2;
pub use ecb_cs3::EcbCs3;

use cipher::{
    Block, BlockCipherDecBackend, BlockCipherEncBackend,
    array::{Array, ArraySize},
    inout::{InOutBuf, NotEqualError},
    typenum::Unsigned,
};

/// Error which indicates that message is smaller than cipher's block size.
#[derive(Copy, Clone, Debug)]
pub struct Error;

/// Encryption functionality of CTS modes.
pub trait Encrypt: Sized {
    /// Encrypt `inout` buffer.
    fn encrypt_inout(self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error>;

    /// Encrypt data in-place.
    fn encrypt(self, buf: &mut [u8]) -> Result<(), Error> {
        self.encrypt_inout(buf.into())
    }

    /// Encrypt data buffer-to-buffer.
    fn encrypt_b2b(self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<(), Error> {
        InOutBuf::new(in_buf, out_buf)
            .map_err(|NotEqualError| Error)
            .and_then(|buf| self.encrypt_inout(buf))
    }
}

/// Decryption functionality of CTS modes.
pub trait Decrypt: Sized {
    /// Decrypt `inout` buffer.
    fn decrypt_inout(self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error>;

    /// Decrypt data in-place.
    fn decrypt(self, buf: &mut [u8]) -> Result<(), Error> {
        self.decrypt_inout(buf.into())
    }

    /// Decrypt data buffer-to-buffer.
    fn decrypt_b2b(self, in_buf: &[u8], out_buf: &mut [u8]) -> Result<(), Error> {
        InOutBuf::new(in_buf, out_buf)
            .map_err(|NotEqualError| Error)
            .and_then(|buf| self.decrypt_inout(buf))
    }
}

fn ecb_enc<B: BlockCipherEncBackend>(cipher: &B, mut blocks: InOutBuf<'_, '_, Block<B>>) {
    if B::ParBlocksSize::USIZE > 1 {
        let (par_blocks, rem_blocks) = blocks.into_chunks();
        blocks = rem_blocks;
        for blocks in par_blocks {
            cipher.encrypt_par_blocks(blocks);
        }
    }
    for block in blocks {
        cipher.encrypt_block(block);
    }
}

fn ecb_dec<B: BlockCipherDecBackend>(cipher: &B, mut blocks: InOutBuf<'_, '_, Block<B>>) {
    if B::ParBlocksSize::USIZE > 1 {
        let (par_blocks, rem_blocks) = blocks.into_chunks();
        blocks = rem_blocks;
        for blocks in par_blocks {
            cipher.decrypt_par_blocks(blocks);
        }
    }
    for block in blocks {
        cipher.decrypt_block(block);
    }
}

fn cbc_enc<B: BlockCipherEncBackend>(
    cipher: &B,
    iv: &mut Block<B>,
    mut blocks: InOutBuf<'_, '_, Block<B>>,
) {
    for mut block in blocks.reborrow() {
        let mut t = block.clone_in();
        xor(&mut t, iv);
        cipher.encrypt_block_inplace(&mut t);
        *iv = t.clone();
        *block.get_out() = t;
    }
}

fn cbc_dec<B: BlockCipherDecBackend>(
    cipher: &B,
    iv: &mut Block<B>,
    mut blocks: InOutBuf<'_, '_, Block<B>>,
) {
    if B::ParBlocksSize::USIZE > 1 {
        let (par_blocks, rem_blocks) = blocks.into_chunks();
        blocks = rem_blocks;

        for mut blocks in par_blocks {
            let in_blocks = blocks.clone_in();
            let mut t = blocks.clone_in();

            cipher.decrypt_par_blocks_inplace(&mut t);
            let n = t.len();
            xor(&mut t[0], iv);
            for i in 1..n {
                xor(&mut t[i], &in_blocks[i - 1])
            }
            *blocks.get_out() = t;
            *iv = in_blocks[n - 1].clone();
        }
    }

    for mut block in blocks {
        let in_block = block.clone_in();
        let mut t = block.clone_in();
        cipher.decrypt_block_inplace(&mut t);
        xor(&mut t, iv);
        *block.get_out() = t;
        *iv = in_block;
    }
}

#[inline(always)]
fn xor<N: ArraySize>(out: &mut Array<u8, N>, buf: &Array<u8, N>) {
    for (a, b) in out.iter_mut().zip(buf) {
        *a ^= *b;
    }
}
