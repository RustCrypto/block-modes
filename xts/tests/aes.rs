use aes::*;
use cipher::{block_mode_dec_test, block_mode_enc_test};
use xts::{Decryptor, Encryptor};

mod macros;

// Test vectors from IEEE 1619-2018
block_mode_enc_test!(aes128_xts_enc_vec1_test, "ieee_vec1", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec1_test, "ieee_vec1", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec2_test, "ieee_vec2", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec2_test, "ieee_vec2", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec3_test, "ieee_vec3", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec3_test, "ieee_vec3", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec4_test, "ieee_vec4", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec4_test, "ieee_vec4", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec5_test, "ieee_vec5", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec5_test, "ieee_vec5", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec6_test, "ieee_vec6", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec6_test, "ieee_vec6", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec7_test, "ieee_vec7", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec7_test, "ieee_vec7", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec8_test, "ieee_vec8", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec8_test, "ieee_vec8", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec9_test, "ieee_vec9", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec9_test, "ieee_vec9", Decryptor<Aes128>);
block_mode_enc_test!(aes256_xts_enc_vec10_test, "ieee_vec10", Encryptor<Aes256>);
block_mode_dec_test!(aes256_xts_dec_vec10_test, "ieee_vec10", Decryptor<Aes256>);
block_mode_enc_test!(aes256_xts_enc_vec11_test, "ieee_vec11", Encryptor<Aes256>);
block_mode_dec_test!(aes256_xts_dec_vec11_test, "ieee_vec11", Decryptor<Aes256>);
block_mode_enc_test!(aes256_xts_enc_vec12_test, "ieee_vec12", Encryptor<Aes256>);
block_mode_dec_test!(aes256_xts_dec_vec12_test, "ieee_vec12", Decryptor<Aes256>);
block_mode_enc_test!(aes256_xts_enc_vec13_test, "ieee_vec13", Encryptor<Aes256>);
block_mode_dec_test!(aes256_xts_dec_vec13_test, "ieee_vec13", Decryptor<Aes256>);
block_mode_enc_test!(aes256_xts_enc_vec14_test, "ieee_vec14", Encryptor<Aes256>);
block_mode_dec_test!(aes256_xts_dec_vec14_test, "ieee_vec14", Decryptor<Aes256>);

// Those tests ciphertext stealing, which cannot be done using the `cipher` macro, since the macro asserts
//   that the plaintext/ciphertext length is a multiple of the block size
block_mode_enc_stealing_test!(aes128_xts_enc_vec15_test, "ieee_vec15", Aes128);
block_mode_dec_stealing_test!(aes128_xts_dec_vec15_test, "ieee_vec15", Aes128);
block_mode_enc_stealing_test!(aes128_xts_enc_vec16_test, "ieee_vec16", Aes128);
block_mode_dec_stealing_test!(aes128_xts_dec_vec16_test, "ieee_vec16", Aes128);
block_mode_enc_stealing_test!(aes128_xts_enc_vec17_test, "ieee_vec17", Aes128);
block_mode_dec_stealing_test!(aes128_xts_dec_vec17_test, "ieee_vec17", Aes128);
block_mode_enc_stealing_test!(aes128_xts_enc_vec18_test, "ieee_vec18", Aes128);
block_mode_dec_stealing_test!(aes128_xts_dec_vec18_test, "ieee_vec18", Aes128);

// Those tests checks that the custom methods works without ciphertext stealing
block_mode_enc_stealing_test!(aes128_xts_enc_custom_api_test, "ieee_vec1", Aes128);
block_mode_dec_stealing_test!(aes128_xts_dec_custom_api_test, "ieee_vec1", Aes128);

block_mode_enc_test!(aes128_xts_enc_vec19_test, "ieee_vec19", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec19_test, "ieee_vec19", Decryptor<Aes128>);
