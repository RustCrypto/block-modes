pub mod ctr128;

use cipher::generic_array::GenericArray;
use cipher::{ArrayLength, Counter};

/// Trait implemented by different CTR flavors.
pub trait CtrFlavor<B: ArrayLength<u8>> {
    /// Inner representation of nonce.
    type CtrNonce: Clone;
    /// Backend numeric type
    type Backend: Counter;
    /// Flavor name
    const NAME: &'static str;

    /// Return number of remaining blocks.
    ///
    /// If result does not fit into `usize`, returns `None`.
    fn remaining(cn: &Self::CtrNonce) -> Option<usize>;

    /// Generate block for given `nonce` and current counter value.
    fn next_block(cn: &mut Self::CtrNonce) -> GenericArray<u8, B>;

    /// Generate block for given `nonce` and current counter value.
    fn current_block(cn: &Self::CtrNonce) -> GenericArray<u8, B>;

    /// Initialize from bytes.
    fn from_nonce(block: &GenericArray<u8, B>) -> Self::CtrNonce;

    /// Convert from a backend value
    fn set_from_backend(cn: &mut Self::CtrNonce, v: Self::Backend);

    /// Convert to a backend value
    fn as_backend(cn: &Self::CtrNonce) -> Self::Backend;

    /// Generate initial `s` value from `nonce`.
    fn reset(cn: &mut Self::CtrNonce);
}
