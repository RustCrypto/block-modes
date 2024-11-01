# RustCrypto: CTS

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Generic implementation of the [ciphertext stealing] block cipher modes of operation.

## Example
```rust
use aes::Aes128;
use cts::{Decrypt, Encrypt, KeyIvInit};
use hex_literal::hex;

type Aes128CbcCs3 = cts::CbcCs3<Aes128>;

let key = [0x42; 16];
let iv = [0x24; 16];

// Message must be bigger than block size (16 bytes for AES-128)
let msg = b"Lorem ipsum dolor sit amet";
let mut buf = [0u8; 26];

Aes128CbcCs3::new(&key.into(), &iv.into())
    .encrypt_b2b(msg, &mut buf).unwrap();
assert_eq!(buf, hex!("68ec97f172e322fdd38e74fca65cee52658ae2124beb5e4e5315"));

Aes128CbcCs3::new(&key.into(), &iv.into())
    .decrypt(&mut buf).unwrap();
assert_eq!(&buf, msg);
```

If you wan to encrypt many messages with one key, you can use a block cipher reference
to create CTS modes:
```rust
use aes::Aes128;
use cts::{
    cipher::{InnerIvInit, KeyInit},
    Encrypt,
};
use hex_literal::hex;

let key = [0x42; 16];
let cipher = Aes128::new(&key.into());

let iv1 = [0x24; 16];
let msg1 = b"Lorem ipsum dolor sit amet";
let mut buf1 = [0u8; 26];

let iv2 = [0x25; 16];
let msg2 = b"Lorem ipsum dolor sit";
let mut buf2 = [0u8; 21];

cts::CbcCs3::inner_iv_init(&cipher, &iv1.into())
    .encrypt_b2b(msg1, &mut buf1).unwrap();
assert_eq!(buf1, hex!("68ec97f172e322fdd38e74fca65cee52658ae2124beb5e4e5315"));

cts::CbcCs3::inner_iv_init(&cipher, &iv2.into())
    .encrypt_b2b(msg2, &mut buf2).unwrap();
assert_eq!(buf2, hex!("69ebd2059e69c6e416a67351982267a26bf5672934"));
```

## Minimum Supported Rust Version

Rust **1.81** or higher.

Minimum supported Rust version can be changed in the future, but it will be
done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

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

[crate-image]: https://img.shields.io/crates/v/cts.svg
[crate-link]: https://crates.io/crates/cts
[docs-image]: https://docs.rs/cts/badge.svg
[docs-link]: https://docs.rs/cts/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/308460-block-modes
[build-image]: https://github.com/RustCrypto/block-modes/workflows/cts/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/block-modes/actions?query=workflow%3Acts+branch%3Amaster

[//]: # (general links)

[ciphertext stealing]: https://en.wikipedia.org/wiki/Ciphertext_stealing
