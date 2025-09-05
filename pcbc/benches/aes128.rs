#![feature(test)]
extern crate test;

cipher::block_encryptor_bench!(
    KeyIv: pcbc::Encryptor<aes::Aes128>,
    pcbc_aes128_encrypt_block,
    pcbc_aes128_encrypt_blocks,
);
cipher::block_decryptor_bench!(
    KeyIv: pcbc::Decryptor<aes::Aes128>,
    pcbc_aes128_decrypt_block,
    pcbc_aes128_decrypt_blocks,
);
