use crate::{Decrypt, Encrypt, Error, cbc_dec, cbc_enc, xor};
use cipher::{
    Block, BlockCipherDecBackend, BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncBackend,
    BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, InnerIvInit, IvSizeUser,
    array::Array,
    crypto_common::{BlockSizes, InnerUser},
    inout::InOutBuf,
    typenum::Unsigned,
};

/// The CBC-CS-1 ciphertext stealing mode.
#[derive(Clone)]
pub struct CbcCs1<C: BlockSizeUser> {
    cipher: C,
    iv: Block<C>,
}

impl<C: BlockSizeUser> InnerUser for CbcCs1<C> {
    type Inner = C;
}

impl<C: BlockSizeUser> IvSizeUser for CbcCs1<C> {
    type IvSize = C::BlockSize;
}

impl<C: BlockSizeUser> InnerIvInit for CbcCs1<C> {
    fn inner_iv_init(cipher: Self::Inner, iv: &cipher::Iv<Self>) -> Self {
        Self {
            cipher,
            iv: iv.clone(),
        }
    }
}

impl<C: BlockCipherEncrypt> Encrypt for CbcCs1<C> {
    fn encrypt_inout(self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
        if buf.len() < C::BlockSize::USIZE {
            return Err(Error);
        }
        let Self { cipher, iv } = self;
        cipher.encrypt_with_backend(Closure { iv, buf });
        Ok(())
    }
}

impl<C: BlockCipherDecrypt> Decrypt for CbcCs1<C> {
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
        let (blocks, tail) = buf.reborrow().into_chunks();

        cbc_enc(cipher, &mut iv, blocks);

        if tail.is_empty() {
            return;
        }

        let mut block = Block::<B>::default();
        block[..tail.len()].copy_from_slice(tail.get_in());
        xor(&mut block, &iv);
        cipher.encrypt_block_inplace(&mut block);

        let pos = buf.len() - B::BlockSize::USIZE;
        buf.get_out()[pos..].copy_from_slice(&block);
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
        let mut block2: Block<B> = rem.get_in()[n..].try_into().unwrap();

        cipher.decrypt_block_inplace(&mut block2);
        block1[n..].copy_from_slice(&block2[n..]);
        xor(&mut block2, &block1);

        cipher.decrypt_block_inplace(&mut block1);
        xor(&mut block1, &iv);

        rem.get_out()[..bs].copy_from_slice(&block1);
        rem.get_out()[bs..].copy_from_slice(&block2[..n]);
    }
}
