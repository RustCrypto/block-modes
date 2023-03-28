#![feature(test)]
extern crate test;

use belt_block::BeltBlock;
use belt_ctr::flavors::ctr128::Ctr128LE;

cipher::stream_cipher_bench!(
    belt_ctr::BeltCtr<BeltBlock, Ctr128LE>;
    ctr_128le_belt128_stream_bench1_16b 16;
    ctr_128le_belt128_stream_bench2_256b 256;
    ctr_128le_belt128_stream_bench3_1kib 1024;
    ctr_128le_belt128_stream_bench4_16kib 16384;
);
