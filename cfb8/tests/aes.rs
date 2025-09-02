// TODO(tarcieri): update tests to support RustCrypto/traits#1916
// use aes::*;
// use cfb8::{Decryptor, Encryptor};
// use cipher::{block_mode_dec_test, block_mode_enc_test, iv_state_test};
//
// iv_state_test!(aes128_cfb8_enc_iv_state, Encryptor<Aes128>, encrypt);
// iv_state_test!(aes128_cfb8_dec_iv_state, Decryptor<Aes128>, decrypt);
// iv_state_test!(aes192_cfb8_enc_iv_state, Encryptor<Aes192>, encrypt);
// iv_state_test!(aes192_cfb8_dec_iv_state, Decryptor<Aes192>, decrypt);
// iv_state_test!(aes256_cfb8_enc_iv_state, Encryptor<Aes256>, encrypt);
// iv_state_test!(aes256_cfb8_dec_iv_state, Decryptor<Aes256>, decrypt);
//
// // Test vectors from CVAP "AES Multiblock Message Test (MMT) Sample Vectors":
// // <https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers>
// block_mode_enc_test!(aes128_cfb8_enc_test, "aes128", Encryptor<Aes128>);
// block_mode_dec_test!(aes128_cfb8_dec_test, "aes128", Decryptor<Aes128>);
// block_mode_enc_test!(aes128enc_cfb8_enc_test, "aes128", Encryptor<Aes128Enc>);
// block_mode_dec_test!(aes128enc_cfb8_dec_test, "aes128", Decryptor<Aes128Enc>);
// block_mode_enc_test!(aes192_cfb8_enc_test, "aes192", Encryptor<Aes192>);
// block_mode_dec_test!(aes192_cfb8_dec_test, "aes192", Decryptor<Aes192>);
// block_mode_enc_test!(aes192enc_cfb8_enc_test, "aes192", Encryptor<Aes192Enc>);
// block_mode_dec_test!(aes192dec_cfb8_dec_test, "aes192", Decryptor<Aes192Enc>);
// block_mode_enc_test!(aes256_cfb8_enc_test, "aes256", Encryptor<Aes256>);
// block_mode_dec_test!(aes256_cfb8_dec_test, "aes256", Decryptor<Aes256>);
// block_mode_enc_test!(aes256enc_cfb8_enc_test, "aes256", Encryptor<Aes256Enc>);
// block_mode_dec_test!(aes256dec_cfb8_dec_test, "aes256", Decryptor<Aes256Enc>);
//
// /// Test methods from the `AsyncStreamCipher` trait.
// #[test]
// fn aes128_cfb8_async_test() {
//     use cipher::{AsyncStreamCipher, KeyIvInit};
//
//     type Enc = Encryptor<Aes128>;
//     type Dec = Decryptor<Aes128>;
//
//     let key = [42; 16];
//     let iv = [24; 16];
//     let mut pt = [0u8; 101];
//     for (i, b) in pt.iter_mut().enumerate() {
//         *b = (i % 11) as u8;
//     }
//     let enc = Enc::new_from_slices(&key, &iv).unwrap();
//     let mut ct = pt;
//     enc.encrypt(&mut ct);
//     for i in 1..100 {
//         let enc = Enc::new_from_slices(&key, &iv).unwrap();
//         let mut t = pt;
//         let t = &mut t[..i];
//         enc.encrypt(t);
//         assert_eq!(t, &ct[..i]);
//
//         let dec = Dec::new_from_slices(&key, &iv).unwrap();
//         dec.decrypt(t);
//         assert_eq!(t, &pt[..i]);
//     }
// }
