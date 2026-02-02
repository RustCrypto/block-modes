use core::marker::PhantomData;

use crate::{Decrypt, Encrypt, Error, ecb_dec, ecb_enc};
use cipher::{
    Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, IvSizeUser,
    common::{BlockSizes, InnerInit, InnerUser},
    inout::InOutBuf,
    typenum::Unsigned,
};

/// The ECB-CS-2 ciphertext stealing mode.
pub struct EcbCs2<C: BlockSizeUser> {
    cipher: C,
}

impl<C: BlockSizeUser> InnerUser for EcbCs2<C> {
    type Inner = C;
}

impl<C: BlockSizeUser> IvSizeUser for EcbCs2<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockSizeUser> InnerInit for EcbCs2<C> {
    fn inner_init(cipher: Self::Inner) -> Self {
        Self { cipher }
    }
}

impl<C: BlockCipherEncrypt> Encrypt for EcbCs2<C> {
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

impl<C: BlockCipherDecrypt> Decrypt for EcbCs2<C> {
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
        let (mut blocks, mut tail) = buf.reborrow().into_chunks();

        ecb_enc(cipher, blocks.reborrow());

        if tail.is_empty() {
            return;
        }

        let last_block = blocks.get_out().last_mut().unwrap();

        let n = tail.len();

        let mut block = Block::<B>::default();
        block[..n].copy_from_slice(tail.get_in());
        block[n..].copy_from_slice(&last_block[n..]);
        cipher.encrypt_block_inplace(&mut block);

        tail.get_out().copy_from_slice(&last_block[..n]);
        *last_block = block;
    }
}

impl<BS: BlockSizes> BlockCipherDecClosure for Closure<'_, BS> {
    fn call<B: BlockCipherDecBackend<BlockSize = BS>>(self, cipher: &B) {
        let mut buf = self.buf;
        let (mut blocks, mut tail) = buf.reborrow().into_chunks();

        ecb_dec(cipher, blocks.reborrow());

        if tail.is_empty() {
            return;
        }

        let last_block = blocks.get_out().last_mut().unwrap();

        let tail_len = tail.len();
        let mut block = Block::<B>::default();
        block[..tail_len].copy_from_slice(tail.get_in());
        block[tail_len..].copy_from_slice(&last_block[tail_len..]);
        tail.get_out().copy_from_slice(&last_block[..tail_len]);

        cipher.decrypt_block_inplace(&mut block);

        *last_block = block;
    }
}
