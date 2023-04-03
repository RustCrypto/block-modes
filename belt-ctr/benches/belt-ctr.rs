#![feature(test)]
extern crate test;

cipher::stream_cipher_bench!(
    belt_ctr::BeltCtr;
    belt_ctr_bench1_16b 16;
    belt_ctr_bench2_256b 256;
    belt_ctr_bench3_1kib 1024;
    belt_ctr_bench4_16kib 16384;
);
