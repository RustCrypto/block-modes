use crate::{ecb_dec, Decrypt, Error};
use cipher::{
    crypto_common::{InnerInit, InnerUser},
    inout::InOutBuf,
    typenum::Unsigned,
    ArrayLength, Block, BlockBackend, BlockClosure, BlockDecrypt, BlockSizeUser, IvSizeUser,
};
use core::marker::PhantomData;

/// The ECB-CS-2 ciphertext stealing mode decryptor.
#[derive(Clone)]
pub struct EcbCs2Dec<C: BlockDecrypt> {
    cipher: C,
}

impl<C: BlockDecrypt> InnerUser for EcbCs2Dec<C> {
    type Inner = C;
}

impl<C: BlockDecrypt> IvSizeUser for EcbCs2Dec<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockDecrypt> InnerInit for EcbCs2Dec<C> {
    fn inner_init(cipher: Self::Inner) -> Self {
        Self { cipher }
    }
}

impl<C: BlockDecrypt> Decrypt for EcbCs2Dec<C> {
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

        cipher.proc_block_inplace(&mut block);

        *last_block = block;
    }
}
