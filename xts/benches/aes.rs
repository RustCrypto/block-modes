#![feature(test)]
extern crate test;

use aes::{ Aes128, Aes256 };

cipher::block_encryptor_bench!(
    KeyIv: xts::Encryptor<Aes128>,
    xts_aes128_encrypt_block,
    xts_aes128_encrypt_blocks,
);

cipher::block_decryptor_bench!(
    KeyIv: xts::Decryptor<Aes128>,
    xts_aes128_decrypt_block,
    xts_aes128_decrypt_blocks,
);

cipher::block_encryptor_bench!(
    KeyIv: xts::Encryptor<Aes256>,
    xts_aes256_encrypt_block,
    xts_aes256_encrypt_blocks,
);

cipher::block_decryptor_bench!(
    KeyIv: xts::Decryptor<Aes256>,
    xts_aes256_decrypt_block,
    xts_aes256_decrypt_blocks,
);
