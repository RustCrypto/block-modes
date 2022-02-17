# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.6.1 (2022-02-17)
### Fixed
- Minimal versions build ([#9])

[#9]: https://github.com/RustCrypto/block-modes/pull/9

## 0.6.0 (2022-02-10)
### Changed
- Update `cipher` dependency to v0.4 and move crate
to the [RustCrypto/block-modes] repository ([#2])

[#2]: https://github.com/RustCrypto/block-modes/pull/2
[RustCrypto/block-modes]: https://github.com/RustCrypto/block-modes

## 0.5.1 (2021-04-30)
### Changed
- Removed redundant `NewBlockCipher` bound from `FromBlockCipher` implementation ([#236])

[#236]: https://github.com/RustCrypto/stream-ciphers/pull/236

## 0.5.0 (2021-04-29)
### Changed
- Bump `cipher` dependency to v0.3 release ([#226])
- Bump `aes` dev dependency to v0.7 release ([#232])

[#226]: https://github.com/RustCrypto/stream-ciphers/pull/226
[#232]: https://github.com/RustCrypto/stream-ciphers/pull/232

## 0.4.0 (2020-10-16)
### Changed
- Replace `block-cipher`/`stream-cipher` with `cipher` crate ([#177])

[#177]: https://github.com/RustCrypto/stream-ciphers/pull/177

## 0.3.0 (2020-08-25)
### Changed
- Bump `stream-cipher` dependency to v0.7, implement the `FromBlockCipher` trait ([#161], [#164])

[#161]: https://github.com/RustCrypto/stream-ciphers/pull/161
[#164]: https://github.com/RustCrypto/stream-ciphers/pull/164

## 0.2.0 (2020-06-08)
### Changed
- Bump `stream-cipher` dependency to v0.4 ([#123])
- Upgrade to Rust 2018 edition ([#123])

[#123]: https://github.com/RustCrypto/stream-ciphers/pull/123

## 0.1.1 (2019-03-11)

## 0.1.0 (2018-12-26)
