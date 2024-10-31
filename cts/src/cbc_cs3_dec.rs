use crate::{cbc_dec, xor, Decrypt, Error};
use cipher::{
    crypto_common::InnerUser, generic_array::GenericArray, inout::InOutBuf, typenum::Unsigned,
    ArrayLength, Block, BlockBackend, BlockClosure, BlockDecrypt, BlockSizeUser, InnerIvInit,
    IvSizeUser,
};

/// The CBC-CS-3 ciphertext stealing mode decryptor.
#[derive(Clone)]
pub struct CbcCs3Dec<C: BlockDecrypt> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockDecrypt> InnerUser for CbcCs3Dec<C> {
    type Inner = C;
}

impl<C: BlockDecrypt> IvSizeUser for CbcCs3Dec<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockDecrypt> InnerIvInit for CbcCs3Dec<C> {
    fn inner_iv_init(cipher: Self::Inner, iv: &cipher::Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockDecrypt> Decrypt for CbcCs3Dec<C> {
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
        let Self { mut iv, buf } = self;

        let bs = B::BlockSize::USIZE;
        let blocks_len = buf.len().div_ceil(bs);
        let main_blocks = blocks_len.saturating_sub(2);

        let (blocks, mut tail) = buf.split_at(bs * main_blocks);
        let (blocks, rem) = blocks.into_chunks();
        debug_assert_eq!(rem.len(), 0);

        cbc_dec(cipher, &mut iv, blocks);

        let n = tail.len() - bs;
        let mut block1 = GenericArray::clone_from_slice(&tail.get_in()[..bs]);
        cipher.proc_block_inplace(&mut block1);

        let mut block2 = GenericArray::<u8, BS>::default();
        block2[..n].copy_from_slice(&tail.get_in()[bs..]);
        block2[n..].copy_from_slice(&block1[n..]);
        xor(&mut block1, &block2);

        cipher.proc_block_inplace(&mut block2);
        xor(&mut block2, &iv);

        let (l, r) = tail.get_out().split_at_mut(bs);
        l.copy_from_slice(&block2);
        r.copy_from_slice(&block1[..n]);
    }
}
