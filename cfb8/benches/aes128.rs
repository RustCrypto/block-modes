#![feature(test)]
extern crate test;

use aes::Aes128;

cipher::block_encryptor_bench!(
    KeyIv: cfb8::Encryptor<Aes128>,
    cfb8_aes128_encrypt_block,
    cfb8_aes128_encrypt_blocks,
);

cipher::block_decryptor_bench!(
    KeyIv: cfb8::Decryptor<Aes128>,
    cfb8_aes128_decrypt_block,
    cfb8_aes128_decrypt_blocks,
);
