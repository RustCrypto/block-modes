#![feature(test)]
extern crate test;

cipher::stream_cipher_bench!(
    belt_ctr::BeltCtr;
    ctr_128le_belt128_stream_bench1_16b 16;
    ctr_128le_belt128_stream_bench2_256b 256;
    ctr_128le_belt128_stream_bench3_1kib 1024;
    ctr_128le_belt128_stream_bench4_16kib 16384;
);
