use aes::*;
use cfb8::{Decryptor, Encryptor};
use cipher::iv_state_test;

iv_state_test!(aes128_cfb8_enc_iv_state, Encryptor<Aes128>, encrypt);
iv_state_test!(aes128_cfb8_dec_iv_state, Decryptor<Aes128>, decrypt);
iv_state_test!(aes192_cfb8_enc_iv_state, Encryptor<Aes192>, encrypt);
iv_state_test!(aes192_cfb8_dec_iv_state, Decryptor<Aes192>, decrypt);
iv_state_test!(aes256_cfb8_enc_iv_state, Encryptor<Aes256>, encrypt);
iv_state_test!(aes256_cfb8_dec_iv_state, Decryptor<Aes256>, decrypt);
