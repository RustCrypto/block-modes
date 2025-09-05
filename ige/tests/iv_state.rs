use aes::Aes128;
use cipher::iv_state_test;
use ige::{Decryptor, Encryptor};

iv_state_test!(aes128_ige_enc_iv_state, Encryptor<Aes128>, encrypt);
iv_state_test!(aes128_ige_dec_iv_state, Decryptor<Aes128>, decrypt);
