#![feature(test)]
extern crate test;

use aes::{cipher::consts::U1, Aes128};

cipher::block_encryptor_bench!(
    KeyIv: cfb_mode::Encryptor<Aes128>,
    cfb_aes128_encrypt_block,
    cfb_aes128_encrypt_blocks,
);

cipher::block_decryptor_bench!(
    KeyIv: cfb_mode::Decryptor<Aes128>,
    cfb_aes128_decrypt_block,
    cfb_aes128_decrypt_blocks,
);

cipher::block_encryptor_bench!(
    KeyIv: cfb_mode::Encryptor<Aes128, U1>,
    cfb8_aes128_encrypt_block,
    cfb8_aes128_encrypt_blocks,
);

cipher::block_decryptor_bench!(
    KeyIv: cfb_mode::Decryptor<Aes128, U1>,
    cfb8_aes128_decrypt_block,
    cfb8_aes128_decrypt_blocks,
);
