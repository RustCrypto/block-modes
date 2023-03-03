use belt_block::BeltBlock;
use cfb_mode::{Decryptor, Encryptor};
use cipher::{block_mode_dec_test, block_mode_enc_test, iv_state_test};

iv_state_test!(belt_cfb_enc_iv_state, Encryptor<BeltBlock>, encrypt);
iv_state_test!(belt_cfb_dec_iv_state, Decryptor<BeltBlock>, decrypt);

// Test vectors from STB 34.101.31-2020 (tables А.13 and А.14):
// <http://apmi.bsu.by/assets/files/std/belt-spec371.pdf>
block_mode_enc_test!(belt_cfb_enc_test, "belt", Encryptor<BeltBlock>);
block_mode_dec_test!(belt_cfb_dec_test, "belt", Decryptor<BeltBlock>);
