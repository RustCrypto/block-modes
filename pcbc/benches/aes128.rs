#![feature(test)]
extern crate test;

use aes::Aes128;

cipher::block_encryptor_bench!(
    KeyIv: pcbc::Encryptor<Aes128>,
    pcbc_aes128_encrypt_block,
    pcbc_aes128_encrypt_blocks,
);

cipher::block_decryptor_bench!(
    KeyIv: pcbc::Decryptor<Aes128>,
    pcbc_aes128_decrypt_block,
    pcbc_aes128_decrypt_blocks,
);
