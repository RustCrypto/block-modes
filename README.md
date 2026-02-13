# RustCrypto: block modes

[![Project Chat][chat-image]][chat-link]
[![dependency status][deps-image]][deps-link]
![Apache2/MIT licensed][license-image]
[![HAZMAT][hazmat-image]][hazmat-link]

Collection of [block modes] written in pure Rust generic over block ciphers.

## ⚠️ Security Warning: [Hazmat!][hazmat-link]

Crates in this repository do not ensure ciphertexts are authentic
(i.e. by using a MAC to verify ciphertext integrity), which can lead to
serious vulnerabilities if used incorrectly!
[RustCrypto/AEADs] provide simple authenticated encryption, which is much
less error-prone than manual integrity verification.

**USE AT YOUR OWN RISK!**

## Supported algorithms

| Name | Crate name | crates.io |  Docs  | MSRV |
|------|------------|:---------:|:------:|:----:|
| [BelT CTR] | [`belt-ctr`] |  [![crates.io](https://img.shields.io/crates/v/belt-ctr.svg)](https://crates.io/crates/belt-ctr) | [![Documentation](https://docs.rs/belt-ctr/badge.svg)](https://docs.rs/belt-ctr) |  ![MSRV 1.85][msrv-1.85] |
| [Cipher Block Chaining][CBC] | [`cbc`] | [![crates.io](https://img.shields.io/crates/v/cbc.svg)](https://crates.io/crates/cbc) | [![Documentation](https://docs.rs/cbc/badge.svg)](https://docs.rs/cbc) |  ![MSRV 1.85][msrv-1.85] |
| [8-bit Cipher Feedback][CFB-8] | [`cfb8`] | [![crates.io](https://img.shields.io/crates/v/cfb8.svg)](https://crates.io/crates/cfb8) | [![Documentation](https://docs.rs/cfb8/badge.svg)](https://docs.rs/cfb8) |  ![MSRV 1.85][msrv-1.85] |
| [Full-block Cipher Feedback][CFB] | [`cfb-mode`] | [![crates.io](https://img.shields.io/crates/v/cfb-mode.svg)](https://crates.io/crates/cfb-mode) | [![Documentation](https://docs.rs/cfb-mode/badge.svg)](https://docs.rs/cfb-mode) |  ![MSRV 1.85][msrv-1.85] |
| [Counter][CTR] | [`ctr`] | [![crates.io](https://img.shields.io/crates/v/ctr.svg)](https://crates.io/crates/ctr) | [![Documentation](https://docs.rs/ctr/badge.svg)](https://docs.rs/ctr) |  ![MSRV 1.85][msrv-1.85] |
| [Ciphertext stealing][CTS] | [`cts`] | [![crates.io](https://img.shields.io/crates/v/cts.svg)](https://crates.io/crates/cts) | [![Documentation](https://docs.rs/cts/badge.svg)](https://docs.rs/cts) |  ![MSRV 1.85][msrv-1.85] |
| [GOST R 34.13-2015] | [`gost-modes`] | [![crates.io](https://img.shields.io/crates/v/gost-modes.svg)](https://crates.io/crates/gost-modes) | [![Documentation](https://docs.rs/gost-modes/badge.svg)](https://docs.rs/gost-modes) | ![MSRV 1.85][msrv-1.85] |
| [Infinite Garble Extension][IGE] | [`ige`] | [![crates.io](https://img.shields.io/crates/v/ige.svg)](https://crates.io/crates/ige) | [![Documentation](https://docs.rs/ige/badge.svg)](https://docs.rs/ige) |  ![MSRV 1.85][msrv-1.85] |
| [Output Feedback][OFB] | [`ofb`] | [![crates.io](https://img.shields.io/crates/v/ofb.svg)](https://crates.io/crates/ofb) | [![Documentation](https://docs.rs/ofb/badge.svg)](https://docs.rs/ofb) |  ![MSRV 1.85][msrv-1.85] |
| [Propagating Cipher Block Chaining][PCBC] | [`pcbc`] | [![crates.io](https://img.shields.io/crates/v/pcbc.svg)](https://crates.io/crates/pcbc) | [![Documentation](https://docs.rs/pcbc/badge.svg)](https://docs.rs/pcbc) |  ![MSRV 1.85][msrv-1.85] |

### Minimum Supported Rust Version (MSRV) Policy

MSRV bumps are considered breaking changes and will be performed only with minor version bump.

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/308460-block-modes
[deps-image]: https://deps.rs/repo/github/RustCrypto/block-modes/status.svg
[deps-link]: https://deps.rs/repo/github/RustCrypto/block-modes
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[hazmat-link]: https://github.com/RustCrypto/meta/blob/master/HAZMAT.md
[msrv-1.85]: https://img.shields.io/badge/rustc-1.85.0+-blue.svg

[//]: # (crates)

[`belt-ctr`]: ./belt-ctr
[`cbc`]: ./cbc
[`cfb8`]: ./cfb8
[`cfb-mode`]: ./cfb-mode
[`ctr`]: ./ctr
[`cts`]: ./cts
[`gost-modes`]: ./gost-modes
[`ige`]: ./ige
[`ofb`]: ./ofb
[`pcbc`]: ./pcbc

[//]: # (links)

[block modes]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
[RustCrypto/AEADs]: https://github.com/RustCrypto/AEADs
[BelT CTR]: https://apmi.bsu.by/assets/files/std/belt-spec371.pdf
[CBC]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_block_chaining_(CBC)
[CFB-8]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CFB-1,_CFB-8,_CFB-64,_CFB-128,_etc.
[CFB]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Full-block_CFB
[CTR]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
[CTS]: https://en.wikipedia.org/wiki/Ciphertext_stealing
[GOST R 34.13-2015]: https://tc26.ru/standard/gost/GOST_R_3413-2015.pdf
[IGE]: https://www.links.org/files/openssl-ige.pdf
[OFB]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)
[PCBC]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Propagating_cipher_block_chaining_(PCBC)
