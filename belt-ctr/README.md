# RustCrypto: belt-ctr

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Generic implementation of the [`belt-ctr`] block mode of operation.

Mode functionality is accessed using traits from the [`cipher`] crate.

# ⚠️ Security Warning: Hazmat!

This crate does not ensure ciphertexts are authentic! Thus ciphertext integrity
is not verified, which can lead to serious vulnerabilities!
[AEADs] provide simple authenticated encryption,
which is much less error-prone than manual integrity verification.

# Example
```rust
use hex_literal::hex;
use belt_ctr::{BeltCtr, cipher::{KeyIvInit, StreamCipher, StreamCipherSeek}};

let key = &[0x42; 32];
let iv = &[0x24; 16];
let plaintext: &[u8; 34] = b"hello world! this is my plaintext.";
let ciphertext: &[u8; 34] = &hex!(
    "38DF06243BD85DA1CAE597CE680D3AFE"
    "0EBB372A4F6A858DB2DBE20A63567EED"
    "7D1B"
);

let mut cipher: BeltCtr = BeltCtr::new_from_slices(key, iv).unwrap();

// encrypt in-place
let mut buf = plaintext.clone();
cipher.apply_keystream(&mut buf);
assert_eq!(buf[..], ciphertext[..]);

cipher.seek(0);
cipher.apply_keystream(&mut buf);
assert_eq!(buf[..], plaintext[..]);
```

## License

Licensed under either of:

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/belt-ctr.svg
[crate-link]: https://crates.io/crates/belt-ctr
[docs-image]: https://docs.rs/belt-ctr/badge.svg
[docs-link]: https://docs.rs/belt-ctr/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/308460-block-modes
[build-image]: https://github.com/RustCrypto/block-modes/workflows/belt-ctr/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/block-modes/actions?query=workflow%3Abelt-ctr+branch%3Amaster

[//]: # (general links)

[`cipher`]: https://docs.rs/cipher/
[`belt-ctr`]: https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
[AEADs]: https://github.com/RustCrypto/AEADs
