use aes::Aes128;
use cts::{
    cipher::{crypto_common::InnerInit, InnerIvInit, KeyInit},
    Decrypt, Encrypt,
};

const KEY: [u8; 16] = [0x42; 16];
const IV: [u8; 16] = [0x24; 16];

const N: usize = 256;
const MSG: [u8; N] = {
    let mut res = [0u8; N];
    let mut i = 0;
    while i < N {
        res[i] = i as u8;
        i += 1;
    }
    res
};

macro_rules! impl_cbc_roundtrip {
    ($name:ident, $enc:ident, $dec:ident) => {
        #[test]
        fn $name() {
            let mut buf1 = [0u8; N];
            let mut buf2 = [0u8; N];

            let cipher = Aes128::new(&KEY.into());
            for i in 16..MSG.len() {
                let enc_mode = cts::$enc::inner_iv_init(&cipher, &IV.into());
                let ct = &mut buf1[..i];
                enc_mode.encrypt_b2b(&MSG[..i], ct).unwrap();

                let dec_mode = cts::$dec::inner_iv_init(&cipher, &IV.into());
                let pt = &mut buf2[..i];
                dec_mode.decrypt_b2b(ct, pt).unwrap();
                assert_eq!(pt, &MSG[..i]);

                let enc_mode = cts::$enc::inner_iv_init(&cipher, &IV.into());
                enc_mode.encrypt(pt).unwrap();
                assert_eq!(pt, ct);

                let dec_mode = cts::$dec::inner_iv_init(&cipher, &IV.into());
                dec_mode.decrypt(pt).unwrap();
                assert_eq!(pt, &MSG[..i]);
            }
        }
    };
}

impl_cbc_roundtrip!(aes128_cbc_cs1_roundtrip, CbcCs1Enc, CbcCs1Dec);
impl_cbc_roundtrip!(aes128_cbc_cs2_roundtrip, CbcCs2Enc, CbcCs2Dec);
impl_cbc_roundtrip!(aes128_cbc_cs3_roundtrip, CbcCs3Enc, CbcCs3Dec);

macro_rules! impl_ecb_roundtrip {
    ($name:ident, $enc:ident, $dec:ident) => {
        #[test]
        fn $name() {
            let mut buf1 = [0u8; N];
            let mut buf2 = [0u8; N];

            let cipher = Aes128::new(&KEY.into());
            for i in 16..MSG.len() {
                let enc_mode = cts::$enc::inner_init(&cipher);
                let ct = &mut buf1[..i];
                enc_mode.encrypt_b2b(&MSG[..i], ct).unwrap();

                let dec_mode = cts::$dec::inner_init(&cipher);
                let pt = &mut buf2[..i];
                dec_mode.decrypt_b2b(ct, pt).unwrap();
                assert_eq!(pt, &MSG[..i]);

                let enc_mode = cts::$enc::inner_init(&cipher);
                enc_mode.encrypt(pt).unwrap();
                assert_eq!(pt, ct);

                let dec_mode = cts::$dec::inner_init(&cipher);
                dec_mode.decrypt(pt).unwrap();
                assert_eq!(pt, &MSG[..i]);
            }
        }
    };
}

impl_ecb_roundtrip!(aes128_ecb_cs1_roundtrip, EcbCs1Enc, EcbCs1Dec);
impl_ecb_roundtrip!(aes128_ecb_cs2_roundtrip, EcbCs2Enc, EcbCs2Dec);
impl_ecb_roundtrip!(aes128_ecb_cs3_roundtrip, EcbCs3Enc, EcbCs3Dec);
