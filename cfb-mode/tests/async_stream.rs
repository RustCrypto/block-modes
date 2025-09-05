//! Tests for the `AsyncStreamCipher` trait methods
use aes::*;
use cfb_mode::{BufDecryptor, BufEncryptor, Decryptor, Encryptor};
use cipher::KeyInit;

#[test]
fn aes128_cfb_async_test() {
    use cipher::{AsyncStreamCipher, KeyIvInit};

    type Enc = Encryptor<Aes128>;
    type Dec = Decryptor<Aes128>;

    let key = [42; 16];
    let iv = [24; 16];
    let mut pt = [0u8; 101];
    for (i, b) in pt.iter_mut().enumerate() {
        *b = (i % 11) as u8;
    }
    let enc = Enc::new_from_slices(&key, &iv).unwrap();
    let mut ct = pt;
    enc.encrypt(&mut ct);
    for i in 1..100 {
        let enc = Enc::new_from_slices(&key, &iv).unwrap();
        let mut t = pt;
        let t = &mut t[..i];
        enc.encrypt(t);
        assert_eq!(t, &ct[..i]);

        let dec = Dec::new_from_slices(&key, &iv).unwrap();
        dec.decrypt(t);
        assert_eq!(t, &pt[..i]);
    }
}

#[test]
fn aes128_cfb_buffered_test() {
    use cipher::{AsyncStreamCipher, KeyIvInit};

    type Enc = Encryptor<Aes128>;

    type BufEnc = BufEncryptor<Aes128>;
    type BufDec = BufDecryptor<Aes128>;

    let key = [42; 16];
    let iv = [24; 16];
    let mut pt = [0u8; 101];
    for (i, b) in pt.iter_mut().enumerate() {
        *b = (i % 11) as u8;
    }

    // unbuffered
    let enc = Enc::new_from_slices(&key, &iv).unwrap();
    let mut ct = pt;
    enc.encrypt(&mut ct);

    // buffered
    for i in 1..100 {
        let mut buf_enc = BufEnc::new_from_slices(&key, &iv).unwrap();
        let mut ct2 = pt;
        for chunk in ct2.chunks_mut(i) {
            buf_enc.encrypt(chunk);
        }
        assert_eq!(ct2, ct);

        let mut buf_dec = BufDec::new_from_slices(&key, &iv).unwrap();
        for chunk in ct2.chunks_mut(i) {
            buf_dec.decrypt(chunk);
        }
        assert_eq!(ct2, pt);
    }

    // buffered with restore
    for i in 1..100 {
        let mut buf_enc = BufEnc::new_from_slices(&key, &iv).unwrap();
        let mut ct2 = pt;
        for chunk in ct2.chunks_mut(i) {
            let (iv, pos) = buf_enc.get_state();
            let cipher = Aes128::new_from_slice(&key).unwrap();
            buf_enc = BufEnc::from_state(cipher, iv, pos);

            buf_enc.encrypt(chunk);
        }
        assert_eq!(ct2, ct);

        let mut buf_dec = BufDec::new_from_slices(&key, &iv).unwrap();
        for chunk in ct2.chunks_mut(i) {
            let (iv, pos) = buf_dec.get_state();
            let cipher = Aes128::new_from_slice(&key).unwrap();
            buf_dec = BufDec::from_state(cipher, iv, pos);

            buf_dec.decrypt(chunk);
        }
        assert_eq!(ct2, pt);
    }
}
