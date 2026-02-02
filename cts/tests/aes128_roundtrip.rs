use aes::Aes128;
use cts::{
    Decrypt, Encrypt,
    cipher::{InnerIvInit, KeyInit, common::InnerInit},
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
    ($name:ident, $mode:ident) => {
        #[test]
        fn $name() {
            let mut buf1 = [0u8; N];
            let mut buf2 = [0u8; N];

            let cipher = Aes128::new(&KEY.into());
            for i in 16..MSG.len() {
                let orig_pt = &MSG[..i];
                let ct = &mut buf1[..i];
                cts::$mode::inner_iv_init(&cipher, &IV.into())
                    .encrypt_b2b(orig_pt, ct)
                    .unwrap();

                let pt = &mut buf2[..i];
                cts::$mode::inner_iv_init(&cipher, &IV.into())
                    .decrypt_b2b(ct, pt)
                    .unwrap();
                assert_eq!(pt, orig_pt);

                cts::$mode::inner_iv_init(&cipher, &IV.into())
                    .encrypt(pt)
                    .unwrap();
                assert_eq!(pt, ct);

                cts::$mode::inner_iv_init(&cipher, &IV.into())
                    .decrypt(pt)
                    .unwrap();
                assert_eq!(pt, orig_pt);
            }
        }
    };
}

impl_cbc_roundtrip!(aes128_cbc_cs1_roundtrip, CbcCs1);
impl_cbc_roundtrip!(aes128_cbc_cs2_roundtrip, CbcCs2);
impl_cbc_roundtrip!(aes128_cbc_cs3_roundtrip, CbcCs3);

macro_rules! impl_ecb_roundtrip {
    ($name:ident, $mode:ident) => {
        #[test]
        fn $name() {
            let mut buf1 = [0u8; N];
            let mut buf2 = [0u8; N];

            let cipher = Aes128::new(&KEY.into());
            for i in 16..MSG.len() {
                let orig_pt = &MSG[..i];
                let ct = &mut buf1[..i];
                cts::$mode::inner_init(&cipher)
                    .encrypt_b2b(orig_pt, ct)
                    .unwrap();

                let pt = &mut buf2[..i];
                cts::$mode::inner_init(&cipher).decrypt_b2b(ct, pt).unwrap();
                assert_eq!(pt, orig_pt);

                cts::$mode::inner_init(&cipher).encrypt(pt).unwrap();
                assert_eq!(pt, ct);

                cts::$mode::inner_init(&cipher).decrypt(pt).unwrap();
                assert_eq!(pt, orig_pt);
            }
        }
    };
}

impl_ecb_roundtrip!(aes128_ecb_cs1_roundtrip, EcbCs1);
impl_ecb_roundtrip!(aes128_ecb_cs2_roundtrip, EcbCs2);
impl_ecb_roundtrip!(aes128_ecb_cs3_roundtrip, EcbCs3);
