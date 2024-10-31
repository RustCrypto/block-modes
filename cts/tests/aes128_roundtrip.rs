use aes::Aes128;
use cts::{
    cipher::{crypto_common::InnerInit, InnerIvInit, KeyInit},
    Decrypt, Encrypt,
};

const KEY: [u8; 16] = [0x42; 16];
const IV: [u8; 16] = [0x24; 16];

const N: usize = 64;
const MSG: [u8; N] = {
    let mut res = [0u8; N];
    let mut i = 0;
    while i < N {
        res[i] = i as u8;
        i += 1;
    }
    res
};

#[test]
fn aes128_cbc_cs1_roundtrip() {
    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];

    let cipher = Aes128::new(&KEY.into());
    for i in 16..MSG.len() {
        let enc_mode = cts::CbcCs1Enc::inner_iv_init(&cipher, &IV.into());
        let ct = &mut buf1[..i];
        enc_mode.encrypt_b2b(&MSG[..i], ct).unwrap();

        let dec_mode = cts::CbcCs1Dec::inner_iv_init(&cipher, &IV.into());
        let pt = &mut buf2[..i];
        dec_mode.decrypt_b2b(ct, pt).unwrap();

        assert_eq!(pt, &MSG[..i]);
    }
}

#[test]
fn aes128_cbc_cs2_roundtrip() {
    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];

    let cipher = Aes128::new(&KEY.into());
    for i in 16..MSG.len() {
        let enc_mode = cts::CbcCs2Enc::inner_iv_init(&cipher, &IV.into());
        let ct = &mut buf1[..i];
        enc_mode.encrypt_b2b(&MSG[..i], ct).unwrap();

        let dec_mode = cts::CbcCs2Dec::inner_iv_init(&cipher, &IV.into());
        let pt = &mut buf2[..i];
        dec_mode.decrypt_b2b(ct, pt).unwrap();

        assert_eq!(pt, &MSG[..i]);
    }
}

#[test]
fn aes128_cbc_cs3_roundtrip() {
    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];

    let cipher = Aes128::new(&KEY.into());
    for i in 16..MSG.len() {
        let enc_mode = cts::CbcCs3Enc::inner_iv_init(&cipher, &IV.into());
        let ct = &mut buf1[..i];
        enc_mode.encrypt_b2b(&MSG[..i], ct).unwrap();

        let dec_mode = cts::CbcCs3Dec::inner_iv_init(&cipher, &IV.into());
        let pt = &mut buf2[..i];
        dec_mode.decrypt_b2b(ct, pt).unwrap();

        assert_eq!(pt, &MSG[..i]);
    }
}

#[test]
fn aes128_ecb_cs1_roundtrip() {
    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];

    let cipher = Aes128::new(&KEY.into());
    for i in 16..MSG.len() {
        let enc_mode = cts::EcbCs1Enc::inner_init(&cipher);
        let ct = &mut buf1[..i];
        enc_mode.encrypt_b2b(&MSG[..i], ct).unwrap();

        let dec_mode = cts::EcbCs1Dec::inner_init(&cipher);
        let pt = &mut buf2[..i];
        dec_mode.decrypt_b2b(ct, pt).unwrap();

        assert_eq!(pt, &MSG[..i]);
    }
}

#[test]
fn aes128_ecb_cs2_roundtrip() {
    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];

    let cipher = Aes128::new(&KEY.into());
    for i in 16..MSG.len() {
        let enc_mode = cts::EcbCs2Enc::inner_init(&cipher);
        let ct = &mut buf1[..i];
        enc_mode.encrypt_b2b(&MSG[..i], ct).unwrap();

        let dec_mode = cts::EcbCs2Dec::inner_init(&cipher);
        let pt = &mut buf2[..i];
        dec_mode.decrypt_b2b(ct, pt).unwrap();

        assert_eq!(pt, &MSG[..i]);
    }
}

#[test]
fn aes128_ecb_cs3_roundtrip() {
    let mut buf1 = [0u8; 64];
    let mut buf2 = [0u8; 64];

    let cipher = Aes128::new(&KEY.into());
    for i in 16..MSG.len() {
        let enc_mode = cts::EcbCs3Enc::inner_init(&cipher);
        let ct = &mut buf1[..i];
        enc_mode.encrypt_b2b(&MSG[..i], ct).unwrap();

        let dec_mode = cts::EcbCs3Dec::inner_init(&cipher);
        let pt = &mut buf2[..i];
        dec_mode.decrypt_b2b(ct, pt).unwrap();

        assert_eq!(pt, &MSG[..i]);
    }
}
