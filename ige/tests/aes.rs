use aes::{Aes128, Aes128Dec, Aes128Enc};
use cipher::{block_mode_dec_test, block_mode_enc_test, iv_state_test};
use ige::{Decryptor, Encryptor};

iv_state_test!(aes128_ige_enc_iv_state, Encryptor<Aes128>, encrypt);
iv_state_test!(aes128_ige_dec_iv_state, Decryptor<Aes128>, decrypt);

// Test vectors from: <>
block_mode_enc_test!(aes128_cbc_enc_test, "aes128", Encryptor<Aes128>);
block_mode_dec_test!(aes128_cbc_dec_test, "aes128", Decryptor<Aes128>);
block_mode_enc_test!(aes128enc_cbc_enc_test, "aes128", Encryptor<Aes128Enc>);
block_mode_dec_test!(aes128dec_cbc_dec_test, "aes128", Decryptor<Aes128Dec>);
