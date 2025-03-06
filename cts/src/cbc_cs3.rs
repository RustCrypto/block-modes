use crate::{Decrypt, Encrypt, Error, cbc_dec, cbc_enc, xor};
use cipher::{
    Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InnerIvInit, IvSizeUser,
    array::Array,
    crypto_common::{BlockSizes, InnerUser},
    inout::InOutBuf,
    typenum::Unsigned,
};

/// The CBC-CS-3 ciphertext stealing mode.
#[derive(Clone)]
pub struct CbcCs3<C: BlockSizeUser> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockSizeUser> InnerUser for CbcCs3<C> {
    type Inner = C;
}

impl<C: BlockSizeUser> IvSizeUser for CbcCs3<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockSizeUser> InnerIvInit for CbcCs3<C> {
    fn inner_iv_init(cipher: Self::Inner, iv: &cipher::Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockCipherEncrypt> Encrypt for CbcCs3<C> {
    fn encrypt_inout(self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
        if buf.len() < C::BlockSize::USIZE {
            return Err(Error);
        }
        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend(Closure { iv, buf });
        Ok(())
    }
}

impl<C: BlockCipherDecrypt> Decrypt for CbcCs3<C> {
    fn decrypt_inout(self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
        if buf.len() < C::BlockSize::USIZE {
            return Err(Error);
        }
        let Self { cipher, iv } = self;
        cipher.decrypt_with_backend(Closure { iv, buf });
        Ok(())
    }
}

struct Closure<'a, BS: BlockSizes> {
    iv: Array<u8, BS>,
    buf: InOutBuf<'a, 'a, u8>,
}

impl<BS: BlockSizes> BlockSizeUser for Closure<'_, BS> {
    type BlockSize = BS;
}

impl<BS: BlockSizes> BlockCipherEncClosure for Closure<'_, BS> {
    fn call<B: BlockCipherEncBackend<BlockSize = BS>>(self, cipher: &B) {
        let Self { mut iv, mut buf } = self;
        let (mut blocks, mut tail) = buf.reborrow().into_chunks();

        cbc_enc(cipher, &mut iv, blocks.reborrow());

        if tail.is_empty() && blocks.len() > 1 {
            let blocks = blocks.get_out();
            let (last, rest) = blocks.split_last_mut().unwrap();
            let (penultimate, _) = rest.split_last_mut().unwrap();
            core::mem::swap(penultimate, last);
        } else {
            let mut block = Block::<B>::default();
            block[..tail.len()].copy_from_slice(tail.get_in());
            xor(&mut block, &iv);
            cipher.encrypt_block_inplace(&mut block);

            let penult_block = blocks.get_out().last_mut().unwrap();
            let val = core::mem::replace(penult_block, block);

            let tail_val = &val[..tail.len()];
            tail.get_out().copy_from_slice(tail_val);
        }
    }
}

impl<BS: BlockSizes> BlockCipherDecClosure for Closure<'_, BS> {
    fn call<B: BlockCipherDecBackend<BlockSize = BS>>(self, cipher: &B) {
        let Self { mut iv, buf } = self;

        let bs = B::BlockSize::USIZE;
        let blocks_len = buf.len().div_ceil(bs);
        let main_blocks = blocks_len.saturating_sub(2);

        let (blocks, mut tail) = buf.split_at(bs * main_blocks);
        let (blocks, rem) = blocks.into_chunks();
        debug_assert_eq!(rem.len(), 0);

        cbc_dec(cipher, &mut iv, blocks);

        let n = tail.len() - bs;
        let mut block1: Block<B> = tail.get_in()[..bs].try_into().unwrap();
        cipher.decrypt_block_inplace(&mut block1);

        let mut block2 = Block::<B>::default();
        block2[..n].copy_from_slice(&tail.get_in()[bs..]);
        block2[n..].copy_from_slice(&block1[n..]);
        xor(&mut block1, &block2);

        cipher.decrypt_block_inplace(&mut block2);
        xor(&mut block2, &iv);

        let (l, r) = tail.get_out().split_at_mut(bs);
        l.copy_from_slice(&block2);
        r.copy_from_slice(&block1[..n]);
    }
}
