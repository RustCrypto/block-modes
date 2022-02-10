use aes::*;
use cipher::{block_mode_dec_test, block_mode_enc_test, iv_state_test, stream_cipher_test};
use ofb::{Ofb, OfbCore};

iv_state_test!(aes128_ofb_enc_iv_state, OfbCore<Aes128>, encrypt);
iv_state_test!(aes128_ofb_dec_iv_state, OfbCore<Aes128>, decrypt);
iv_state_test!(aes128_ofb_apply_ks_iv_state, OfbCore<Aes128>, apply_ks);
iv_state_test!(aes192_ofb_enc_iv_state, OfbCore<Aes192>, encrypt);
iv_state_test!(aes192_ofb_dec_iv_state, OfbCore<Aes192>, decrypt);
iv_state_test!(aes192_ofb_apply_ks_iv_state, OfbCore<Aes192>, apply_ks);
iv_state_test!(aes256_ofb_enc_iv_state, OfbCore<Aes256>, encrypt);
iv_state_test!(aes256_ofb_dec_iv_state, OfbCore<Aes256>, decrypt);
iv_state_test!(aes256_ofb_apply_ks_iv_state, OfbCore<Aes256>, apply_ks);

// Test vectors from CVAP "AES Multiblock Message Test (MMT) Sample Vectors":
// <https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers>
block_mode_enc_test!(aes128_ofb_enc_test, "aes128", OfbCore<Aes128>);
block_mode_dec_test!(aes128_ofb_dec_test, "aes128", OfbCore<Aes128>);
block_mode_enc_test!(aes128enc_ofb_enc_test, "aes128", OfbCore<Aes128Enc>);
block_mode_dec_test!(aes128dec_ofb_dec_test, "aes128", OfbCore<Aes128Enc>);
stream_cipher_test!(aes128_ofb_stream_test, "aes128", Ofb<Aes128>);
stream_cipher_test!(aes128enc_ofb_stream_test, "aes128", Ofb<Aes128Enc>);
block_mode_enc_test!(aes192_ofb_enc_test, "aes192", OfbCore<Aes192>);
block_mode_dec_test!(aes192_ofb_dec_test, "aes192", OfbCore<Aes192>);
block_mode_enc_test!(aes192enc_ofb_enc_test, "aes192", OfbCore<Aes192Enc>);
block_mode_dec_test!(aes192dec_ofb_dec_test, "aes192", OfbCore<Aes192Enc>);
stream_cipher_test!(aes192_ofb_stream_test, "aes192", Ofb<Aes192>);
stream_cipher_test!(aes192enc_ofb_stream_test, "aes192", Ofb<Aes192Enc>);
block_mode_enc_test!(aes256_ofb_enc_test, "aes256", OfbCore<Aes256>);
block_mode_dec_test!(aes256_ofb_dec_test, "aes256", OfbCore<Aes256>);
block_mode_enc_test!(aes256enc_ofb_enc_test, "aes256", OfbCore<Aes256Enc>);
block_mode_dec_test!(aes256dec_ofb_dec_test, "aes256", OfbCore<Aes256Enc>);
stream_cipher_test!(aes256_ofb_stream_test, "aes256", Ofb<Aes256>);
stream_cipher_test!(aes256enc_ofb_stream_test, "aes256", Ofb<Aes256Enc>);
