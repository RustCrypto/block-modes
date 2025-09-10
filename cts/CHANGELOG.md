# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.7.0 (UNRELEASED)
### Removed 
- `std` feature ([#76])
- `Clone` impl ([#91])

### Changed
- Update to cipher v0.5 ([#72])
- Merge Enc/Dec types, i.e. `CbcCs1Enc` and `CbcCs1Dec` are merged into `CbcCs1` ([#72])
- Edition changed to 2024 and MSRV bumped to 1.85 ([#76])
- Relax MSRV policy and allow MSRV bumps in patch releases

[#72]: https://github.com/RustCrypto/block-modes/pull/72
[#76]: https://github.com/RustCrypto/block-modes/pull/76
[#91]: https://github.com/RustCrypto/block-modes/pull/91

## 0.6.0 (2024-11-01)
- Initial release ([#70])

[#70]: https://github.com/RustCrypto/block-modes/pull/70
