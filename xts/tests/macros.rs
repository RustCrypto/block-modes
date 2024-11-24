/// Pasted from the `cipher` crate and adapted to support XTS tests

#[macro_export]
macro_rules! block_mode_enc_stealing_test {
    ($name:ident, $test_name:expr, $cipher:ty $(,)?) => {
        #[test]
        fn $name() {
            use cipher::{blobby::Blob4Iterator, KeyIvInit};

            use xts::Encryptor;

            fn run_test(i: usize, key: &[u8], iv: &[u8], pt: &[u8], ct: &[u8]) {
                assert_eq!(pt.len(), ct.len());
                // test block-by-block processing

                // MODIFICATION: We hardcode XTS encryptor here
                let mut state =
                    <Encryptor<$cipher> as KeyIvInit>::new_from_slices(key, iv).unwrap();

                let mut out = vec![0u8; ct.len()];

                // MODIFICATION: We don't split the block and we call encrypt_directly
                state.encrypt_b2b(pt, &mut out).unwrap();

                // MODIFICATION: Crash here so we can get the actual output
                if out != ct {
                    panic!(
                        "\n\
                         Failed test №{}\n\
                         key:\t{:?}\n\
                         iv:\t{:?}\n\
                         plaintext:\t{:?}\n\
                         ciphertext:\t{:?}\n\
                         actual_ct:\t{:?}\n",
                        i, key, iv, pt, ct, out
                    );
                }
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
                let [key, iv, pt, ct] = row.unwrap();
                run_test(i, key, iv, pt, ct);
            }
        }
    };
}

/// Define block mode decryption test
#[macro_export]
macro_rules! block_mode_dec_stealing_test {
    ($name:ident, $test_name:expr, $cipher:ty $(,)?) => {
        #[test]
        fn $name() {
            use cipher::{blobby::Blob4Iterator, KeyIvInit};

            use xts::Decryptor;

            fn run_test(i: usize, key: &[u8], iv: &[u8], pt: &[u8], ct: &[u8]) {
                assert_eq!(pt.len(), ct.len());
                // test block-by-block processing

                // MODIFICATION: We hardcode XTS encryptor here
                let mut state =
                    <Decryptor<$cipher> as KeyIvInit>::new_from_slices(key, iv).unwrap();

                let mut out = vec![0u8; ct.len()];

                // MODIFICATION: We don't split the block and we call encrypt_directly
                state.decrypt_b2b(ct, &mut out).unwrap();

                // MODIFICATION: Crash here so we can get the actual output
                if out != pt {
                    panic!(
                        "\n\
                         Failed test №{}\n\
                         key:\t{:?}\n\
                         iv:\t{:?}\n\
                         plaintext:\t{:?}\n\
                         ciphertext:\t{:?}\n\
                         actual_pt:\t{:?}\n",
                        i, key, iv, pt, ct, out
                    );
                }
            }

            let data = include_bytes!(concat!("data/", $test_name, ".blb"));
            for (i, row) in Blob4Iterator::new(data).unwrap().enumerate() {
                let [key, iv, pt, ct] = row.unwrap();
                run_test(i, key, iv, pt, ct);
            }
        }
    };
}
