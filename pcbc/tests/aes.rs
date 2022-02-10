use aes::{Aes128, Aes128Dec, Aes128Enc};
use cipher::{block_mode_dec_test, block_mode_enc_test, iv_state_test};
use pcbc::{Decryptor, Encryptor};

iv_state_test!(aes128_pcbc_enc_iv_state, Encryptor<Aes128>, encrypt);
iv_state_test!(aes128_pcbc_dec_iv_state, Decryptor<Aes128>, decrypt);

// The test vectors are generated using this implementation.
block_mode_enc_test!(aes128_pcbc_enc_test, "aes128", Encryptor<Aes128>);
block_mode_dec_test!(aes128_pcbc_dec_test, "aes128", Decryptor<Aes128>);
block_mode_enc_test!(aes128enc_pcbc_enc_test, "aes128", Encryptor<Aes128Enc>);
block_mode_dec_test!(aes128dec_pcbc_dec_test, "aes128", Decryptor<Aes128Dec>);
