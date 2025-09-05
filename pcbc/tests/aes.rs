//! Test vectors generated using this crate.
use aes::{Aes128, Aes128Dec, Aes128Enc};
use cipher::block_mode_test;
use pcbc::{Decryptor, Encryptor};

block_mode_test!(aes128_pcbc_enc, "aes128", Encryptor<Aes128>, encrypt);
block_mode_test!(aes128_pcbc_dec, "aes128", Decryptor<Aes128>, decrypt);
block_mode_test!(aes128enc_pcbc_enc, "aes128", Encryptor<Aes128Enc>, encrypt);
block_mode_test!(aes128dec_pcbc_dec, "aes128", Decryptor<Aes128Dec>, decrypt);
