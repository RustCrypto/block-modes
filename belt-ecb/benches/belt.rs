#![feature(test)]
extern crate test;

use belt_block::BeltBlock;
use belt_ecb::{BufDecryptor, BufEncryptor};

cipher::block_encryptor_bench!(
    Key: BufEncryptor<BeltBlock>,
    ecb_belt_encrypt_block,
    ecb_belt_encrypt_blocks,
);

cipher::block_decryptor_bench!(
    Key: BufDecryptor<BeltBlock>,
    ecb_belt_decrypt_block,
    ecb_belt_decrypt_blocks,
);
