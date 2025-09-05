//! Test vectors from STB 34.101.31-2020 (tables А.13 and А.14):
//! <http://apmi.bsu.by/assets/files/std/belt-spec371.pdf>
use belt_block::BeltBlock;
use cfb_mode::{Decryptor, Encryptor};
use cipher::block_mode_test;

block_mode_test!(belt_cfb_enc_test, "belt", Encryptor<BeltBlock>, encrypt);
block_mode_test!(belt_cfb_dec_test, "belt", Decryptor<BeltBlock>, decrypt);
