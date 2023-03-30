//! 128-bit counter falvors.
use cipher::{
    generic_array::{ArrayLength, GenericArray},
    typenum::{PartialDiv, PartialQuot, Unsigned, U16},
};

use crate::flavor::CtrFlavor;
#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};

type ChunkSize = U16;
type Chunks<B> = PartialQuot<B, ChunkSize>;
const CS: usize = ChunkSize::USIZE;

/// u128 nonce
#[derive(Clone)]
pub struct CtrNonce128<N: ArrayLength<u128>> {
    ctr: u128,
    nonce: GenericArray<u128, N>,
}

#[cfg(feature = "zeroize")]
impl<N: ArrayLength<u128>> Drop for CtrNonce128<N> {
    fn drop(&mut self) {
        self.ctr.zeroize();
        self.nonce.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<N: ArrayLength<u128>> ZeroizeOnDrop for CtrNonce128<N> {}

/// 128-bit counter.
pub enum Ctr128 {}

impl<B> CtrFlavor<B> for Ctr128
where
    B: ArrayLength<u8> + PartialDiv<ChunkSize>,
    Chunks<B>: ArrayLength<u128>,
{
    type CtrNonce = CtrNonce128<Chunks<B>>;
    type Backend = u128;
    const NAME: &'static str = "128LE";

    #[inline]
    fn remaining(cn: &Self::CtrNonce) -> Option<usize> {
        (u128::MAX - cn.ctr).try_into().ok()
    }

    #[inline]
    fn next_block(cn: &mut Self::CtrNonce) -> GenericArray<u8, B> {
        let block = Self::current_block(cn);
        cn.ctr = cn.ctr.wrapping_add(1);
        block
    }

    #[inline(always)]
    fn current_block(cn: &Self::CtrNonce) -> GenericArray<u8, B> {
        let mut block = GenericArray::<u8, B>::default();
        block.copy_from_slice(&cn.ctr.to_le_bytes());
        block
    }

    #[inline]
    fn from_nonce(block: &GenericArray<u8, B>) -> Self::CtrNonce {
        let mut nonce = GenericArray::<u128, Chunks<B>>::default();
        for i in 0..Chunks::<B>::USIZE {
            let chunk = block[CS * i..][..CS].try_into().unwrap();
            nonce[i] = if i == Chunks::<B>::USIZE - 1 {
                u128::from_be_bytes(chunk)
            } else {
                u128::from_ne_bytes(chunk)
            }
        }
        let ctr = u128::from_le_bytes(block[..].try_into().unwrap());
        Self::CtrNonce { ctr, nonce }
    }

    #[inline]
    fn set_from_backend(cn: &mut Self::CtrNonce, v: Self::Backend) {
        cn.ctr = v;
    }

    #[inline]
    fn as_backend(cn: &Self::CtrNonce) -> Self::Backend {
        cn.ctr
    }

    #[inline]
    fn reset(cn: &mut Self::CtrNonce) {
        let mut block = GenericArray::<u8, B>::default();
        for i in 0..Chunks::<B>::USIZE {
            let nonce = if i == Chunks::<B>::USIZE - 1 {
                cn.nonce[i].to_be_bytes()
            } else {
                cn.nonce[i].to_ne_bytes()
            };
            block[CS * i..][..CS].copy_from_slice(&nonce);
        }
        cn.ctr = u128::from_le_bytes(block[..].try_into().unwrap());
    }
}
