#![feature(test)]
extern crate test;

cipher::block_encryptor_bench!(
    KeyIv: ige::Encryptor<aes::Aes128>,
    ige_aes128_encrypt_block,
    ige_aes128_encrypt_blocks,
);
cipher::block_decryptor_bench!(
    KeyIv: ige::Decryptor<aes::Aes128>,
    ige_aes128_decrypt_block,
    ige_aes128_decrypt_blocks,
);
