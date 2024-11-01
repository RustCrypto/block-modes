//! Test vectors from RFC 3962: https://www.rfc-editor.org/rfc/rfc3962
use cipher::{InnerIvInit, KeyInit};
use cts::{Decrypt, Encrypt};
use hex_literal::hex;

const KEY: [u8; 16] = hex!("636869636b656e207465726979616b69");
const IV: [u8; 16] = [0u8; 16];

static TEST_VECTORS: &[(&[u8], &[u8])] = &[
    (
        &hex!(
            "4920776f756c64206c696b6520746865"
            "20"
        ),
        &hex!(
            "c6353568f2bf8cb4d8a580362da7ff7f"
            "97"
        ),
    ),
    (
        &hex!(
            "4920776f756c64206c696b6520746865"
            "2047656e6572616c20476175277320"
        ),
        &hex!(
            "fc00783e0efdb2c1d445d4c8eff7ed22"
            "97687268d6ecccc0c07b25e25ecfe5"
        ),
    ),
    (
        &hex!(
            "4920776f756c64206c696b6520746865"
            "2047656e6572616c2047617527732043"
        ),
        &hex!(
            "39312523a78662d5be7fcbcc98ebf5a8"
            "97687268d6ecccc0c07b25e25ecfe584"
        ),
    ),
    (
        &hex!(
            "4920776f756c64206c696b6520746865"
            "2047656e6572616c2047617527732043"
            "6869636b656e2c20706c656173652c"
        ),
        &hex!(
            "97687268d6ecccc0c07b25e25ecfe584"
            "b3fffd940c16a18c1b5549d2f838029e"
            "39312523a78662d5be7fcbcc98ebf5"
        ),
    ),
    (
        &hex!(
            "4920776f756c64206c696b6520746865"
            "2047656e6572616c2047617527732043"
            "6869636b656e2c20706c656173652c20"
        ),
        &hex!(
            "97687268d6ecccc0c07b25e25ecfe584"
            "9dad8bbb96c4cdc03bc103e1a194bbd8"
            "39312523a78662d5be7fcbcc98ebf5a8"
        ),
    ),
    (
        &hex!(
            "4920776f756c64206c696b6520746865"
            "2047656e6572616c2047617527732043"
            "6869636b656e2c20706c656173652c20"
            "616e6420776f6e746f6e20736f75702e"
        ),
        &hex!(
            "97687268d6ecccc0c07b25e25ecfe584"
            "39312523a78662d5be7fcbcc98ebf5a8"
            "4807efe836ee89a526730dbc2f7bc840"
            "9dad8bbb96c4cdc03bc103e1a194bbd8"
        ),
    ),
];

#[test]
fn rfc3962() {
    let cipher = aes::Aes128::new(&KEY.into());
    let iv = IV.into();

    let mut buf = [0u8; 64];
    for &(input, output) in TEST_VECTORS {
        let buf = &mut buf[..input.len()];

        cts::CbcCs3::inner_iv_init(&cipher, &iv)
            .encrypt_b2b(input, buf)
            .unwrap();
        assert_eq!(buf, output);

        cts::CbcCs3::inner_iv_init(&cipher, &iv)
            .decrypt_b2b(output, buf)
            .unwrap();
        assert_eq!(buf, input);
    }
}
