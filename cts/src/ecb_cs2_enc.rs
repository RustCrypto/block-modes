use crate::{ecb_enc, Encrypt, Error};
use cipher::{
    crypto_common::{InnerInit, InnerUser},
    inout::InOutBuf,
    typenum::Unsigned,
    ArrayLength, Block, BlockBackend, BlockClosure, BlockEncrypt, BlockSizeUser, IvSizeUser,
};
use core::marker::PhantomData;

/// The ECB-CS-2 ciphertext stealing mode encryptor.
#[derive(Clone)]
pub struct EcbCs2Enc<C: BlockEncrypt> {
    cipher: C,
}

impl<C: BlockEncrypt> InnerUser for EcbCs2Enc<C> {
    type Inner = C;
}

impl<C: BlockEncrypt> IvSizeUser for EcbCs2Enc<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockEncrypt> InnerInit for EcbCs2Enc<C> {
    fn inner_init(cipher: Self::Inner) -> Self {
        Self { cipher }
    }
}

impl<C: BlockEncrypt> Encrypt for EcbCs2Enc<C> {
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

struct Closure<'a, BS: ArrayLength<u8>> {
    buf: InOutBuf<'a, 'a, u8>,
    _pd: PhantomData<BS>,
}

impl<BS: ArrayLength<u8>> BlockSizeUser for Closure<'_, BS> {
    type BlockSize = BS;
}

impl<BS: ArrayLength<u8>> BlockClosure for Closure<'_, BS> {
    fn call<B: BlockBackend<BlockSize = BS>>(self, cipher: &mut B) {
        let Self { mut buf, _pd } = self;
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
        cipher.proc_block_inplace(&mut block);

        tail.get_out().copy_from_slice(&last_block[..n]);
        *last_block = block;
    }
}
