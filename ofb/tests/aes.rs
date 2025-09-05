//! Test vectors from CVAP "AES Multiblock Message Test (MMT) Sample Vectors":
//! <https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers>
use aes::*;
use cipher::{block_mode_test, stream_cipher_test};
use ofb::{Ofb, OfbCore};

block_mode_test!(aes128_ofb_enc, "aes128", OfbCore<Aes128>, encrypt);
block_mode_test!(aes192_ofb_enc, "aes192", OfbCore<Aes192>, encrypt);
block_mode_test!(aes256_ofb_enc, "aes256", OfbCore<Aes256>, encrypt);

block_mode_test!(aes128_ofb_dec, "aes128", OfbCore<Aes128>, decrypt);
block_mode_test!(aes192_ofb_dec, "aes192", OfbCore<Aes192>, decrypt);
block_mode_test!(aes256_ofb_dec, "aes256", OfbCore<Aes256>, decrypt);

block_mode_test!(aes128enc_ofb_enc, "aes128", OfbCore<Aes128Enc>, encrypt);
block_mode_test!(aes192enc_ofb_enc, "aes192", OfbCore<Aes192Enc>, encrypt);
block_mode_test!(aes256enc_ofb_enc, "aes256", OfbCore<Aes256Enc>, encrypt);

block_mode_test!(aes128enc_ofb_dec, "aes128", OfbCore<Aes128Enc>, decrypt);
block_mode_test!(aes192enc_ofb_dec, "aes192", OfbCore<Aes192Enc>, decrypt);
block_mode_test!(aes256enc_ofb_dec, "aes256", OfbCore<Aes256Enc>, decrypt);

stream_cipher_test!(aes128_ofb_stream_test, "aes128", Ofb<Aes128>);
stream_cipher_test!(aes192_ofb_stream_test, "aes192", Ofb<Aes192>);
stream_cipher_test!(aes256_ofb_stream_test, "aes256", Ofb<Aes256>);

stream_cipher_test!(aes128enc_ofb_stream_test, "aes128", Ofb<Aes128Enc>);
stream_cipher_test!(aes192enc_ofb_stream_test, "aes192", Ofb<Aes192Enc>);
stream_cipher_test!(aes256enc_ofb_stream_test, "aes256", Ofb<Aes256Enc>);
