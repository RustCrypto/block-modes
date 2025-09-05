//! Test vectors from:
//! <https://mgp25.com/blog/2015/06/21/AESIGE/#test-vectors>
use aes::{Aes128, Aes128Dec, Aes128Enc};
use cipher::block_mode_test;
use ige::{Decryptor, Encryptor};

block_mode_test!(aes128_cbc_enc, "aes128", Encryptor<Aes128>, encrypt);
block_mode_test!(aes128_cbc_dec, "aes128", Decryptor<Aes128>, decrypt);
block_mode_test!(aes128enc_cbc_enc, "aes128", Encryptor<Aes128Enc>, encrypt);
block_mode_test!(aes128dec_cbc_dec, "aes128", Decryptor<Aes128Dec>, decrypt);
