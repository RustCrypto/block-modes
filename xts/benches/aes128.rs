#![feature(test)]
extern crate test;

use aes::{ Aes128, Aes256 };

cipher::block_encryptor_bench!(
    KeyIv: xts::SplitEncryptor<Aes128>,
    xts_aes128_encrypt_block,
    xts_aes128_encrypt_blocks,
);

cipher::block_decryptor_bench!(
    KeyIv: xts::SplitDecryptor<Aes128, Aes128>,
    xts_aes128_decrypt_block,
    xts_aes128_decrypt_blocks,
);

cipher::block_encryptor_bench!(
    KeyIv: xts::SplitEncryptor<Aes256>,
    xts_aes256_encrypt_block,
    xts_aes256_encrypt_blocks,
);

cipher::block_decryptor_bench!(
    KeyIv: xts::SplitDecryptor<Aes256, Aes256>,
    xts_aes256_decrypt_block,
    xts_aes256_decrypt_blocks,
);
