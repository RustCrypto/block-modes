use super::{ecb_dec, Decrypt, Error};
use cipher::{
    crypto_common::{InnerInit, InnerUser},
    inout::InOutBuf,
    typenum::Unsigned,
    ArrayLength, Block, BlockBackend, BlockClosure, BlockDecrypt, BlockSizeUser, IvSizeUser,
};
use core::marker::PhantomData;

/// The ECB-CS-1 ciphertext stealing mode decryptor.
#[derive(Clone)]
pub struct EcbCs1Dec<C: BlockDecrypt> {
    cipher: C,
}

impl<C: BlockDecrypt> InnerUser for EcbCs1Dec<C> {
    type Inner = C;
}

impl<C: BlockDecrypt> IvSizeUser for EcbCs1Dec<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockDecrypt> InnerInit for EcbCs1Dec<C> {
    fn inner_init(cipher: Self::Inner) -> Self {
        Self { cipher }
    }
}

impl<C: BlockDecrypt> Decrypt for EcbCs1Dec<C> {
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
        let mut block1 = Block::<B>::clone_from_slice(&rem.get_in()[..bs]);
        let mut block2 = Block::<B>::clone_from_slice(&rem.get_in()[n..]);

        cipher.proc_block_inplace(&mut block2);
        block1[n..].copy_from_slice(&block2[n..]);

        cipher.proc_block_inplace(&mut block1);

        rem.get_out()[..bs].copy_from_slice(&block1);
        rem.get_out()[bs..].copy_from_slice(&block2[..n]);
    }
}
