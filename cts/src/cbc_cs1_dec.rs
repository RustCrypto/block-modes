use crate::{cbc_dec, xor, Decrypt, Error};
use cipher::{
    crypto_common::InnerUser, generic_array::GenericArray, inout::InOutBuf, typenum::Unsigned,
    ArrayLength, Block, BlockBackend, BlockClosure, BlockDecrypt, BlockSizeUser, InnerIvInit,
    IvSizeUser,
};

/// The CBC-CS-1 ciphertext stealing mode decryptor.
#[derive(Clone)]
pub struct CbcCs1Dec<C: BlockDecrypt> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockDecrypt> InnerUser for CbcCs1Dec<C> {
    type Inner = C;
}

impl<C: BlockDecrypt> IvSizeUser for CbcCs1Dec<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockDecrypt> InnerIvInit for CbcCs1Dec<C> {
    fn inner_iv_init(cipher: Self::Inner, iv: &cipher::Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockDecrypt> Decrypt for CbcCs1Dec<C> {
    fn decrypt_inout(self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
        if buf.len() < C::BlockSize::USIZE {
            return Err(Error);
        }
        let Self { cipher, iv } = self;
        cipher.decrypt_with_backend(Closure { iv, buf });
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

        let (mut blocks, tail) = buf.reborrow().into_chunks();

        if !tail.is_empty() {
            let mid = blocks.len() - 1;
            blocks = blocks.split_at(mid).0;
        };

        cbc_dec(cipher, &mut iv, blocks);

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
        xor(&mut block2, &block1);

        cipher.proc_block_inplace(&mut block1);
        xor(&mut block1, &iv);

        rem.get_out()[..bs].copy_from_slice(&block1);
        rem.get_out()[bs..].copy_from_slice(&block2[..n]);
    }
}
