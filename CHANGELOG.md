# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.3.0] - 2025-01-21

### Added
- Added `KeyNode::class_name` ([#4]).
- Added printing a key's class name to the `readhive` example.
- Added support for `core::error::Error`.

### Changed
- Changed `KeyValue::multi_string_data` to return an iterator instead of a `Vec`.
- Changed project to Rust 2021 edition and MSRV to Rust 1.81.
- Replaced displaydoc dependency by thiserror.
- Upgraded to bitflags 2.8.0, enumn 0.1.14, memoffset 0.9.1, zerocopy 0.8.14.

### Fixed
- Fixed validating the cell size against the remaining data length.
- Fixed `KeyNode::subkey` and `KeyNode::subpath` nesting the lifetimes instead of using the single lifetime of `Hive`.

[#4]: https://github.com/ColinFinck/nt-hive/pull/4


## [0.2.0] - 2021-11-10

### Added
- Added `Hive::without_validation` to accept hives failing header validation ([#1]).

### Changed
- Updated to bitflags 1.3.2, byteorder 1.4.3, displaydoc 0.2.3, memoffset 0.6.4, zerocopy 0.6.1.

### Fixed
- Fixed example in `README.md` ([#1]).
- Fixed `PartialOrd` implementations for comparing `NtHiveString` and `str`.

[#1]: https://github.com/ColinFinck/nt-hive/issues/1


## [0.1.0] - 2021-02-21
- Initial release
