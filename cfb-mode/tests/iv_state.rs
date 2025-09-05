use aes::*;
use cfb_mode::{Decryptor, Encryptor};
use cipher::iv_state_test;

iv_state_test!(aes128_cfb_enc_iv_state, Encryptor<Aes128>, encrypt);
iv_state_test!(aes128_cfb_dec_iv_state, Decryptor<Aes128>, decrypt);
iv_state_test!(aes192_cfb_enc_iv_state, Encryptor<Aes192>, encrypt);
iv_state_test!(aes192_cfb_dec_iv_state, Decryptor<Aes192>, decrypt);
iv_state_test!(aes256_cfb_enc_iv_state, Encryptor<Aes256>, encrypt);
iv_state_test!(aes256_cfb_dec_iv_state, Decryptor<Aes256>, decrypt);
