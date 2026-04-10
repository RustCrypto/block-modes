# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 (UNRELEASED)
## Added
- `GenericBeltCtr` and `GenericBeltCtrCore` types ([#112])

## Changed
- Bump `cipher` from `0.4` to `0.5` ([#56])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#76])
- Relax MSRV policy and allow MSRV bumps in patch releases
- Use type aliases instead of type defaults to define default `belt-block` implementation ([#112])

[#56]: https://github.com/RustCrypto/block-modes/pull/56
[#76]: https://github.com/RustCrypto/block-modes/pull/76
[#112]: https://github.com/RustCrypto/block-modes/pull/112

## 0.1.0 (2023-04-02)
- Initial release
