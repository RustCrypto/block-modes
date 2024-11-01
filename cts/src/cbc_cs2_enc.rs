use crate::{cbc_enc, xor, Encrypt, Error};
use cipher::{
    crypto_common::InnerUser, generic_array::GenericArray, inout::InOutBuf, typenum::Unsigned,
    ArrayLength, Block, BlockBackend, BlockClosure, BlockEncrypt, BlockSizeUser, InnerIvInit,
    IvSizeUser,
};

/// The CBC-CS-2 ciphertext stealing mode encryptor.
#[derive(Clone)]
pub struct CbcCs2Enc<C: BlockEncrypt> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockEncrypt> InnerUser for CbcCs2Enc<C> {
    type Inner = C;
}

impl<C: BlockEncrypt> IvSizeUser for CbcCs2Enc<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockEncrypt> InnerIvInit for CbcCs2Enc<C> {
    fn inner_iv_init(cipher: Self::Inner, iv: &cipher::Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockEncrypt> Encrypt for CbcCs2Enc<C> {
    fn encrypt_inout(self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
        if buf.len() < C::BlockSize::USIZE {
            return Err(Error);
        }
        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend(Closure { iv, buf });
        Ok(())
    }
}

struct Closure<'a, BS: ArrayLength<u8>> {
    iv: GenericArray<u8, BS>,
    buf: InOutBuf<'a, 'a, u8>,
}

impl<BS: ArrayLength<u8>> BlockSizeUser for Closure<'_, BS> {
    type BlockSize = BS;
}

impl<BS: ArrayLength<u8>> BlockClosure for Closure<'_, BS> {
    fn call<B: BlockBackend<BlockSize = BS>>(self, cipher: &mut B) {
        let Self { mut iv, mut buf } = self;
        let (mut blocks, mut tail) = buf.reborrow().into_chunks();

        cbc_enc(cipher, &mut iv, blocks.reborrow());

        if tail.is_empty() {
            return;
        }

        let mut block = Block::<B>::default();
        block[..tail.len()].copy_from_slice(tail.get_in());
        xor(&mut block, &iv);
        cipher.proc_block_inplace(&mut block);

        let penult_block = core::mem::replace(blocks.get_out().last_mut().unwrap(), block);
        let tail_val = &penult_block[..tail.len()];
        tail.get_out().copy_from_slice(tail_val);
    }
}
