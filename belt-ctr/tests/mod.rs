use belt_ctr::BeltCtr;

// Test vectors from the BelT standard (tables A.15 and A.16):
// https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
cipher::stream_cipher_test!(belt_ctr_core, "belt-ctr", BeltCtr);
cipher::stream_cipher_seek_test!(belt_ctr_seek, BeltCtr);
