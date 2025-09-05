use aes::*;
use cipher::iv_state_test;
use ofb::OfbCore;

iv_state_test!(aes128_ofb_enc_iv_state, OfbCore<Aes128>, encrypt);
iv_state_test!(aes128_ofb_dec_iv_state, OfbCore<Aes128>, decrypt);
iv_state_test!(aes128_ofb_apply_ks_iv_state, OfbCore<Aes128>, apply_ks);
iv_state_test!(aes192_ofb_enc_iv_state, OfbCore<Aes192>, encrypt);
iv_state_test!(aes192_ofb_dec_iv_state, OfbCore<Aes192>, decrypt);
iv_state_test!(aes192_ofb_apply_ks_iv_state, OfbCore<Aes192>, apply_ks);
iv_state_test!(aes256_ofb_enc_iv_state, OfbCore<Aes256>, encrypt);
iv_state_test!(aes256_ofb_dec_iv_state, OfbCore<Aes256>, decrypt);
iv_state_test!(aes256_ofb_apply_ks_iv_state, OfbCore<Aes256>, apply_ks);
