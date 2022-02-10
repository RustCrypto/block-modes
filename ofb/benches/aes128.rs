#![feature(test)]
extern crate test;

use aes::Aes128;

cipher::stream_cipher_bench!(
    ofb::Ofb<aes::Aes128>;
    ofb_aes128_stream_bench1_16b 16;
    ofb_aes128_stream_bench2_256b 256;
    ofb_aes128_stream_bench3_1kib 1024;
    ofb_aes128_stream_bench4_16kib 16384;
);

cipher::block_encryptor_bench!(
    KeyIv: ofb::OfbCore<Aes128>,
    ofb_aes128_encrypt_block,
    ofb_aes128_encrypt_blocks,
);

cipher::block_decryptor_bench!(
    KeyIv: ofb::OfbCore<Aes128>,
    ofb_aes128_decrypt_block,
    ofb_aes128_decrypt_blocks,
);
