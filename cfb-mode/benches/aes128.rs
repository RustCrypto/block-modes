#![feature(test)]
extern crate test;

cipher::block_encryptor_bench!(
    KeyIv: cfb_mode::Encryptor<aes::Aes128>,
    cfb_aes128_encrypt_block,
    cfb_aes128_encrypt_blocks,
);
cipher::block_decryptor_bench!(
    KeyIv: cfb_mode::Decryptor<aes::Aes128>,
    cfb_aes128_decrypt_block,
    cfb_aes128_decrypt_blocks,
);
