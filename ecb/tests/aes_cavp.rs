//! Test vectors from CAVP "AES Multiblock Message Test (MMT) Sample Vectors":
//! <https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Block-Ciphers>
use aes::*;
use cipher::{BlockModeDecrypt, BlockModeEncrypt, InOutBuf, KeyInit};
use ecb::{Decryptor, Encryptor};

const MAX_LEN: usize = 256;

#[derive(Debug, Clone, Copy)]
struct TestVector {
    pub key: &'static [u8],
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
}

#[test]
fn aes128_ecb_cavp() {
    cipher::dev::blobby::parse_into_structs!(
        include_bytes!("data/aes128.blb");
        static TEST_VECTORS: &[TestVector { key, plaintext, ciphertext }];
    );

    for tv in TEST_VECTORS.iter() {
        encrypt::<Encryptor<Aes128>>(tv).unwrap();
        encrypt::<Encryptor<Aes128Enc>>(tv).unwrap();
        decrypt::<Decryptor<Aes128>>(tv).unwrap();
        decrypt::<Decryptor<Aes128Dec>>(tv).unwrap();
    }
}

#[test]
fn aes192_ecb_cavp() {
    cipher::dev::blobby::parse_into_structs!(
        include_bytes!("data/aes192.blb");
        static TEST_VECTORS: &[TestVector { key, plaintext, ciphertext }];
    );

    for tv in TEST_VECTORS.iter() {
        encrypt::<Encryptor<Aes192>>(tv).unwrap();
        encrypt::<Encryptor<Aes192Enc>>(tv).unwrap();
        decrypt::<Decryptor<Aes192>>(tv).unwrap();
        decrypt::<Decryptor<Aes192Dec>>(tv).unwrap();
    }
}

#[test]
fn aes256_ecb_cavp() {
    cipher::dev::blobby::parse_into_structs!(
        include_bytes!("data/aes256.blb");
        static TEST_VECTORS: &[TestVector { key, plaintext, ciphertext }];
    );

    for tv in TEST_VECTORS.iter() {
        encrypt::<Encryptor<Aes256>>(tv).unwrap();
        encrypt::<Encryptor<Aes256Enc>>(tv).unwrap();
        decrypt::<Decryptor<Aes256>>(tv).unwrap();
        decrypt::<Decryptor<Aes256Dec>>(tv).unwrap();
    }
}

fn encrypt<C: BlockModeEncrypt + KeyInit>(tv: &TestVector) -> Result<(), &'static str> {
    let mut buf = [0u8; MAX_LEN];
    let Some(out) = buf.get_mut(..tv.ciphertext.len()) else {
        return Err("ciphertext is bigger than MAX_MSG_LEN bytes");
    };
    let Ok(mut buf) = InOutBuf::new(tv.plaintext, out) else {
        return Err("plaintext/ciphertext length mismatch");
    };
    let (blocks, tail) = buf.reborrow().into_chunks();
    if !tail.is_empty() {
        return Err("plaintext/ciphertext length is not multiple of block size");
    }

    let Ok(mut cipher) = C::new_from_slice(tv.key) else {
        return Err("cipher initialization failure");
    };
    for block in blocks {
        cipher.encrypt_block_inout(block);
    }
    if buf.get_out() != tv.ciphertext {
        return Err("single block encryption failure");
    }

    // test multi-block processing
    let Ok(mut cipher) = C::new_from_slice(tv.key) else {
        return Err("cipher initialization failure");
    };
    buf.get_out().fill(0);
    let (blocks, _) = buf.reborrow().into_chunks();
    cipher.encrypt_blocks_inout(blocks);
    if buf.get_out() != tv.ciphertext {
        return Err("multi-block encryption failure");
    }
    Ok(())
}

fn decrypt<C: BlockModeDecrypt + KeyInit>(tv: &TestVector) -> Result<(), &'static str> {
    let mut buf = [0u8; MAX_LEN];
    let Some(out) = buf.get_mut(..tv.plaintext.len()) else {
        return Err("plaintext is bigger than MAX_MSG_LEN bytes");
    };
    let Ok(mut buf) = InOutBuf::new(tv.ciphertext, out) else {
        return Err("plaintext/ciphertext length mismatch");
    };
    let (blocks, tail) = buf.reborrow().into_chunks();
    if !tail.is_empty() {
        return Err("plaintext/ciphertext length is not multiple of block size");
    }

    let Ok(mut cipher) = C::new_from_slice(tv.key) else {
        return Err("cipher initialization failure");
    };
    for block in blocks {
        cipher.decrypt_block_inout(block);
    }
    if buf.get_out() != tv.plaintext {
        return Err("single block decryption failure");
    }

    // test multi-block processing
    let Ok(mut cipher) = C::new_from_slice(tv.key) else {
        return Err("cipher initialization failure");
    };
    buf.get_out().fill(0);
    let (blocks, _) = buf.reborrow().into_chunks();
    cipher.decrypt_blocks_inout(blocks);
    if buf.get_out() != tv.plaintext {
        return Err("multi-block decryption failure");
    }
    Ok(())
}
