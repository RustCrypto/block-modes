# RustCrypto: ECB

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build Status][build-image]][build-link]

Generic implementation of the [Electronic Codebook][ECB] (CBC) block cipher
mode of operation.

<img src="https://raw.githubusercontent.com/RustCrypto/media/26acc39f/img/block-modes/ecb_enc.svg" width="49%"><img src="https://raw.githubusercontent.com/RustCrypto/media/26acc39f/img/block-modes/ecb_dec.svg" width="49%">

See [documentation][cipher-doc] of the `cipher` crate for additional information.

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

[crate-image]: https://img.shields.io/crates/v/ecb.svg
[crate-link]: https://crates.io/crates/ecb
[docs-image]: https://docs.rs/ecb/badge.svg
[docs-link]: https://docs.rs/ecb/
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.85+-blue.svg
[build-image]: https://github.com/magic-akari/ecb/actions/workflows/test.yml/badge.svg?branch=main
[build-link]: https://github.com/magic-akari/ecb/actions/workflows/test.yml

[//]: # (general links)

[ECB]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB
[cipher-doc]: https://docs.rs/cipher
