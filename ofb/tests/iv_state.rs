//! IV state tests.

use aes::{Aes128, Aes192, Aes256};
use cipher::{
    BlockModeDecrypt, BlockModeEncrypt, IvState, KeyIvInit, SetIvState, StreamCipherCore,
    iv_state_test,
};
use ofb::OfbCore;

iv_state_test!(aes128_ofb_enc_iv_state, OfbCore<Aes128>, encrypt);
iv_state_test!(aes128_ofb_dec_iv_state, OfbCore<Aes128>, decrypt);
iv_state_test!(aes128_ofb_apply_ks_iv_state, OfbCore<Aes128>, apply_ks);
iv_state_test!(aes192_ofb_enc_iv_state, OfbCore<Aes192>, encrypt);
iv_state_test!(aes192_ofb_dec_iv_state, OfbCore<Aes192>, decrypt);
iv_state_test!(aes192_ofb_apply_ks_iv_state, OfbCore<Aes192>, apply_ks);
iv_state_test!(aes256_ofb_enc_iv_state, OfbCore<Aes256>, encrypt);
iv_state_test!(aes256_ofb_dec_iv_state, OfbCore<Aes256>, decrypt);
iv_state_test!(aes256_ofb_apply_ks_iv_state, OfbCore<Aes256>, apply_ks);

#[test]
fn aes128_ofb_set_iv() {
    let key = Default::default();
    let iv = Default::default();
    let mut mode = OfbCore::<Aes128>::new(&key, &iv);

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

#[test]
fn aes128_ofb_encrypt_set_iv() {
    let key = Default::default();
    let iv = Default::default();
    let mut mode = OfbCore::<Aes128>::new(&key, &iv);

    let mut blocks = [Default::default(); 16];

    mode.encrypt_blocks(&mut blocks);
    let iv = mode.iv_state();

    let mut buf1 = blocks;
    let mut buf2 = blocks;

    mode.peek(|m| m.encrypt_blocks(&mut buf1));
    assert_eq!(mode.iv_state(), iv);

    mode.encrypt_blocks(&mut blocks);
    let iv2 = mode.iv_state();

    mode.set_iv(&iv);
    mode.encrypt_blocks(&mut buf2);

    assert_eq!(blocks, buf1);
    assert_eq!(blocks, buf2);
    assert_eq!(mode.iv_state(), iv2);
}

#[test]
fn aes128_ofb_decrypt_set_iv() {
    let key = Default::default();
    let iv = Default::default();
    let mut mode = OfbCore::<Aes128>::new(&key, &iv);

    let mut blocks = [Default::default(); 16];

    mode.decrypt_blocks(&mut blocks);
    let iv = mode.iv_state();

    let mut buf1 = blocks;
    let mut buf2 = blocks;

    mode.peek(|m| m.decrypt_blocks(&mut buf1));
    assert_eq!(mode.iv_state(), iv);

    mode.decrypt_blocks(&mut blocks);
    let iv2 = mode.iv_state();

    mode.set_iv(&iv);
    mode.decrypt_blocks(&mut buf2);

    assert_eq!(blocks, buf1);
    assert_eq!(blocks, buf2);
    assert_eq!(mode.iv_state(), iv2);
}
