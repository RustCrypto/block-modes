# RustCrypto: CFB-8

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Build Status][build-image]][build-link]

Generic implementation of the [Cipher Feedback][CFB-8] with eight bit
feedback (CFB-8) block cipher mode of operation.

<img src="https://raw.githubusercontent.com/RustCrypto/media/26acc39f/img/block-modes/cfb_enc.svg" width="50%"><img src="https://raw.githubusercontent.com/RustCrypto/media/26acc39f/img/block-modes/cfb_dec.svg" width="50%">

See [documentation][cipher-doc] of the `cipher` crate for additional information.

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

[crate-image]: https://img.shields.io/crates/v/cfb8.svg
[crate-link]: https://crates.io/crates/cfb8
[docs-image]: https://docs.rs/cfb8/badge.svg
[docs-link]: https://docs.rs/cfb8/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.81+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/308460-block-modes
[build-image]: https://github.com/RustCrypto/block-modes/workflows/cfb8/badge.svg?branch=master&event=push
[build-link]: https://github.com/RustCrypto/block-modes/actions?query=workflow%3Acfb+branch%3Amaster

[//]: # (general links)

[CFB]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CFB-1,_CFB-8,_CFB-64,_CFB-128,_etc.
[cipher-doc]: https://docs.rs/cipher/
