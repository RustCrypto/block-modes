#![feature(test)]
extern crate test;

use aes::Aes128;

cipher::block_encryptor_bench!(
    KeyIv: ige::Encryptor<Aes128>,
    ige_aes128_encrypt_block,
    ige_aes128_encrypt_blocks,
);

cipher::block_decryptor_bench!(
    KeyIv: ige::Decryptor<Aes128>,
    ige_aes128_decrypt_block,
    ige_aes128_decrypt_blocks,
);
