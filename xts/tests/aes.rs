use aes::*;
use cipher::{block_mode_dec_test, block_mode_enc_test};
use xts::{Decryptor, Encryptor};

#[test]
fn manual_test() {
    use cipher::{
        array::Array, blobby::Blob4Iterator, inout::InOutBuf, typenum::Unsigned,
        BlockCipherEncrypt, BlockModeEncrypt, BlockSizeUser, KeyIvInit,
    };

    fn run_test(key: &[u8], iv: &[u8], pt: &[u8], ct: &[u8]) {
        assert_eq!(pt.len(), ct.len());

        let mut state = <Encryptor<Aes128> as KeyIvInit>::new_from_slices(key, iv).unwrap();
        let mut out = vec![0u8; ct.len()];
        let mut buf = InOutBuf::new(pt, &mut out).unwrap();
        let (blocks, tail) = buf.reborrow().into_chunks();

        assert_eq!(tail.len(), 0);

        for block in blocks {
            state.encrypt_block_inout(block);
        }

        assert_eq!(buf.get_out(), ct);

        let mut state = <Encryptor<Aes128> as KeyIvInit>::new_from_slices(key, iv).unwrap();
        buf.get_out().iter_mut().for_each(|b| *b = 0);
        let (blocks, _) = buf.reborrow().into_chunks();
        state.encrypt_blocks_inout(blocks);

        assert_eq!(buf.get_out(), ct);
    }

    let data = include_bytes!(concat!("data/", "ieee_vec1", ".blb"));
    for row in Blob4Iterator::new(data).unwrap() {
        let [key, iv, pt, ct] = row.unwrap();
        run_test(key, iv, pt, ct);
    }
}

// Test vectors from IEEE 1619-2018
block_mode_enc_test!(aes128_xts_enc_vec1_test, "ieee_vec1", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec1_test, "ieee_vec1", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec2_test, "ieee_vec2", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec2_test, "ieee_vec2", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec3_test, "ieee_vec3", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec3_test, "ieee_vec3", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec4_test, "ieee_vec4", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec4_test, "ieee_vec4", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec5_test, "ieee_vec5", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec5_test, "ieee_vec5", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec6_test, "ieee_vec6", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec6_test, "ieee_vec6", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec7_test, "ieee_vec7", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec7_test, "ieee_vec7", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec8_test, "ieee_vec8", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec8_test, "ieee_vec8", Decryptor<Aes128>);
block_mode_enc_test!(aes128_xts_enc_vec9_test, "ieee_vec9", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec9_test, "ieee_vec9", Decryptor<Aes128>);
block_mode_enc_test!(aes256_xts_enc_vec10_test, "ieee_vec10", Encryptor<Aes256>);
block_mode_dec_test!(aes256_xts_dec_vec10_test, "ieee_vec10", Decryptor<Aes256>);
block_mode_enc_test!(aes256_xts_enc_vec11_test, "ieee_vec11", Encryptor<Aes256>);
block_mode_dec_test!(aes256_xts_dec_vec11_test, "ieee_vec11", Decryptor<Aes256>);
block_mode_enc_test!(aes256_xts_enc_vec12_test, "ieee_vec12", Encryptor<Aes256>);
block_mode_dec_test!(aes256_xts_dec_vec12_test, "ieee_vec12", Decryptor<Aes256>);
block_mode_enc_test!(aes256_xts_enc_vec13_test, "ieee_vec13", Encryptor<Aes256>);
block_mode_dec_test!(aes256_xts_dec_vec13_test, "ieee_vec13", Decryptor<Aes256>);
block_mode_enc_test!(aes256_xts_enc_vec14_test, "ieee_vec14", Encryptor<Aes256>);
block_mode_dec_test!(aes256_xts_dec_vec14_test, "ieee_vec14", Decryptor<Aes256>);

// Those tests ciphertext stealing, which cannot be done using the macro, since the macro asserts
//   that the plaintext/ciphertext length is a multiple of the block size
// block_mode_enc_test!(aes128_xts_enc_vec15_test, "ieee_vec15", Encryptor<Aes128>);
// block_mode_dec_test!(aes128_xts_dec_vec15_test, "ieee_vec15", Decryptor<Aes128>);
// block_mode_enc_test!(aes128_xts_enc_vec16_test, "ieee_vec16", Encryptor<Aes128>);
// block_mode_dec_test!(aes128_xts_dec_vec16_test, "ieee_vec16", Decryptor<Aes128>);
// block_mode_enc_test!(aes128_xts_enc_vec17_test, "ieee_vec17", Encryptor<Aes128>);
// block_mode_dec_test!(aes128_xts_dec_vec17_test, "ieee_vec17", Decryptor<Aes128>);
// block_mode_enc_test!(aes128_xts_enc_vec18_test, "ieee_vec18", Encryptor<Aes128>);
// block_mode_dec_test!(aes128_xts_dec_vec18_test, "ieee_vec18", Decryptor<Aes128>);

block_mode_enc_test!(aes128_xts_enc_vec19_test, "ieee_vec19", Encryptor<Aes128>);
block_mode_dec_test!(aes128_xts_dec_vec19_test, "ieee_vec19", Decryptor<Aes128>);
