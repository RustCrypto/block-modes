use crate::{Decrypt, Encrypt, Error, cbc_dec, cbc_enc, xor};
use cipher::{
    Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InnerIvInit, IvSizeUser,
    array::Array,
    crypto_common::{BlockSizes, InnerUser},
    inout::InOutBuf,
    typenum::Unsigned,
};

/// The CBC-CS-2 ciphertext stealing mode.
pub struct CbcCs2<C: BlockSizeUser> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockSizeUser> InnerUser for CbcCs2<C> {
    type Inner = C;
}

impl<C: BlockSizeUser> IvSizeUser for CbcCs2<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockSizeUser> InnerIvInit for CbcCs2<C> {
    fn inner_iv_init(cipher: Self::Inner, iv: &cipher::Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockCipherEncrypt> Encrypt for CbcCs2<C> {
    fn encrypt_inout(self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
        if buf.len() < C::BlockSize::USIZE {
            return Err(Error);
        }
        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend(Closure { iv, buf });
        Ok(())
    }
}

impl<C: BlockCipherDecrypt> Decrypt for CbcCs2<C> {
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

        if tail.is_empty() {
            return;
        }

        let mut block = Block::<B>::default();
        block[..tail.len()].copy_from_slice(tail.get_in());
        xor(&mut block, &iv);
        cipher.encrypt_block_inplace(&mut block);

        let penult_block = core::mem::replace(blocks.get_out().last_mut().unwrap(), block);
        let tail_val = &penult_block[..tail.len()];
        tail.get_out().copy_from_slice(tail_val);
    }
}

impl<BS: BlockSizes> BlockCipherDecClosure for Closure<'_, BS> {
    fn call<B: BlockCipherDecBackend<BlockSize = BS>>(self, cipher: &B) {
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
        let mut block1: Block<B> = rem.get_in()[..bs].try_into().unwrap();
        cipher.decrypt_block_inplace(&mut block1);

        let mut block2 = Block::<B>::default();
        block2[..n].copy_from_slice(&rem.get_in()[bs..]);
        block2[n..].copy_from_slice(&block1[n..]);

        xor(&mut block1, &block2);

        cipher.decrypt_block_inplace(&mut block2);
        xor(&mut block2, &iv);

        rem.get_out()[..bs].copy_from_slice(&block2);
        rem.get_out()[bs..].copy_from_slice(&block1[..n]);
    }
}
