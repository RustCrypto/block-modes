//! Basic tests for `IvState` and `SetIvState` trait impls
use belt_ctr::BeltCtrCore;
use cipher::{IvState, KeyIvInit, SetIvState, StreamCipherCore};

cipher::iv_state_test!(belt_ctr_iv_state, BeltCtrCore, apply_ks);

#[test]
fn belt_ctr_set_iv() {
    let key = Default::default();
    let iv = Default::default();
    let mut mode = BeltCtrCore::new(&key, &iv);

    let mut blocks = [Default::default(); 16];

    mode.apply_keystream_blocks(&mut blocks);
    let iv = mode.iv_state();

    let mut buf1 = blocks;
    let mut buf2 = blocks;

    mode.peek(|m| m.apply_keystream_blocks(&mut buf1));
    assert_eq!(mode.iv_state(), iv);

    mode.apply_keystream_blocks(&mut blocks);
    let iv2 = mode.iv_state();

    mode.set_iv(&iv);
    mode.apply_keystream_blocks(&mut buf2);

    assert_eq!(blocks, buf1);
    assert_eq!(blocks, buf2);
    assert_eq!(mode.iv_state(), iv2);
}
