use aes::Aes128;
use cipher::iv_state_test;
use pcbc::{Decryptor, Encryptor};

iv_state_test!(aes128_pcbc_enc_iv_state, Encryptor<Aes128>, encrypt);
iv_state_test!(aes128_pcbc_dec_iv_state, Decryptor<Aes128>, decrypt);
