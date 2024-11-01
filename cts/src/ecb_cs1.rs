use core::marker::PhantomData;

use crate::{ecb_dec, ecb_enc, Decrypt, Encrypt, Error};
use cipher::{
    crypto_common::{BlockSizes, InnerInit, InnerUser},
    inout::InOutBuf,
    typenum::Unsigned,
    Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, IvSizeUser,
};

/// The ECB-CS-1 ciphertext stealing mode.
#[derive(Clone)]
pub struct EcbCs1<C: BlockSizeUser> {
    cipher: C,
}

impl<C: BlockSizeUser> InnerUser for EcbCs1<C> {
    type Inner = C;
}

impl<C: BlockSizeUser> IvSizeUser for EcbCs1<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockSizeUser> InnerInit for EcbCs1<C> {
    fn inner_init(cipher: Self::Inner) -> Self {
        Self { cipher }
    }
}

impl<C: BlockCipherEncrypt> Encrypt for EcbCs1<C> {
    fn encrypt_inout(self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
        if buf.len() < C::BlockSize::USIZE {
            return Err(Error);
        }
        self.cipher.encrypt_with_backend(Closure {
            buf,
            _pd: PhantomData,
        });
        Ok(())
    }
}

impl<C: BlockCipherDecrypt> Decrypt for EcbCs1<C> {
    fn decrypt_inout(self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
        if buf.len() < C::BlockSize::USIZE {
            return Err(Error);
        }
        self.cipher.decrypt_with_backend(Closure {
            buf,
            _pd: PhantomData,
        });
        Ok(())
    }
}

struct Closure<'a, BS: BlockSizes> {
    buf: InOutBuf<'a, 'a, u8>,
    _pd: PhantomData<BS>,
}

impl<BS: BlockSizes> BlockSizeUser for Closure<'_, BS> {
    type BlockSize = BS;
}

impl<BS: BlockSizes> BlockCipherEncClosure for Closure<'_, BS> {
    fn call<B: BlockCipherEncBackend<BlockSize = BS>>(self, cipher: &B) {
        let mut buf = self.buf;
        let (mut blocks, tail) = buf.reborrow().into_chunks();

        ecb_enc(cipher, blocks.reborrow());

        if tail.is_empty() {
            return;
        }

        let last_block = blocks.get_out().last_mut().unwrap();
        let mut block = Block::<B>::default();

        let n = tail.len();

        block[..n].copy_from_slice(tail.get_in());
        block[n..].copy_from_slice(&last_block[n..]);
        cipher.encrypt_block_inplace(&mut block);

        let pos = buf.len() - block.len();
        buf.get_out()[pos..].copy_from_slice(&block);
    }
}

impl<BS: BlockSizes> BlockCipherDecClosure for Closure<'_, BS> {
    fn call<B: BlockCipherDecBackend<BlockSize = BS>>(self, cipher: &B) {
        let mut buf = self.buf;
        let (mut blocks, tail) = buf.reborrow().into_chunks();

        if !tail.is_empty() {
            let mid = blocks.len() - 1;
            blocks = blocks.split_at(mid).0;
        };

        ecb_dec(cipher, blocks);

        if tail.is_empty() {
            return;
        }

        let tail_len = tail.len();
        let bs = B::BlockSize::USIZE;
        let mid = buf.len() - (bs + tail_len);
        let mut rem = buf.split_at(mid).1;

        let n = rem.len() - bs;
        let mut block1: Block<B> = rem.get_in()[..bs].try_into().unwrap();
        let mut block2: Block<B> = rem.get_in()[n..].try_into().unwrap();

        cipher.decrypt_block_inplace(&mut block2);
        block1[n..].copy_from_slice(&block2[n..]);

        cipher.decrypt_block_inplace(&mut block1);

        rem.get_out()[..bs].copy_from_slice(&block1);
        rem.get_out()[bs..].copy_from_slice(&block2[..n]);
    }
}
