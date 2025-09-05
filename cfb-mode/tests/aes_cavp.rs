//! Test vectors from CVAP "AES Multiblock Message Test (MMT) Sample Vectors":
//! <https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers>

use aes::*;
use cfb_mode::{Decryptor, Encryptor};
use cipher::block_mode_test;

block_mode_test!(aes128_cfb_enc, "aes128", Encryptor<Aes128>, encrypt);
block_mode_test!(aes192_cfb_enc, "aes192", Encryptor<Aes192>, encrypt);
block_mode_test!(aes256_cfb_enc, "aes256", Encryptor<Aes256>, encrypt);

block_mode_test!(aes128_cfb_dec, "aes128", Decryptor<Aes128>, decrypt);
block_mode_test!(aes192_cfb_dec, "aes192", Decryptor<Aes192>, decrypt);
block_mode_test!(aes256_cfb_dec, "aes256", Decryptor<Aes256>, decrypt);

block_mode_test!(aes128enc_cfb_enc, "aes128", Encryptor<Aes128Enc>, encrypt);
block_mode_test!(aes192enc_cfb_enc, "aes192", Encryptor<Aes192Enc>, encrypt);
block_mode_test!(aes256enc_cfb_enc, "aes256", Encryptor<Aes256Enc>, encrypt);

block_mode_test!(aes128enc_cfb_dec, "aes128", Decryptor<Aes128Enc>, decrypt);
block_mode_test!(aes192dec_cfb_dec, "aes192", Decryptor<Aes192Enc>, decrypt);
block_mode_test!(aes256dec_cfb_dec, "aes256", Decryptor<Aes256Enc>, decrypt);
