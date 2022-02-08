# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

The crates in this repository do not adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) at this time.

## [Unreleased]
## [1.1.3] - 2021-12-16

- Postgres automatically retries
- Configurable Oram Size.

## [1.1.2] - 2021-12-16

- Fog ingest, view, report have configurable timeouts for SQL connections
- More informative logging for fog ingest
- Avoid log spam due to PERMISSION_DENIED and other events that don't require action
- Go grpc gateway was moved to this repo

## [1.1.1] - 2021-11-18

### Changed

 - Fog view returns PERMISSION_DENIED instead of INTERNAL_ERROR on attestation errors,
   matching the other attested services. (This caused bugs on clients would not
   reattest in this case.)
 - Fog ingest is refactored so that it updates the report cache less frequently.
 - Fog distro (an internal testing tool) rebuilds and resubmits transactions
   that fail due to tombstone block errors.

## [1.1.0] - 2021-06-03

### Added

 - Unified fog URI
 - Cookie support for fog enclave connections

### Changed

 - Update SGX to 2.13.3.
 - Upgrade Rust to nightly-2021-03-25

#### Rust Dependencies

 - Update `aligned-cmov` to 2.0.0
 - Update `arrayvec` to 0.5.2
 - Update `balanced-tree-index` to 2.0.0
 - Update `merlin` to 3.0.0
 - Update `packed_simd` to 0.3.4
 - Update `pv-lite86` to 0.2.10
 - Update `protobuf` to 2.22.1
 - Update `rand_chacha` to 0.3.0
 - Update `rand_core` to 0.6.2
 - Update `rand_hc` to 0.3.0
 - Update `rand` to 0.8.3
 - Update `schnorrkel` to 0.10.1
 - Update `sha2` to 0.9.3
 - Update `x25519-dalek` to 1.1.1

### Fixed

 - Improve conformance test
 - Fixed symbol-stripping when compiling libmobilecoin.

### Security

 - Add threat model document

## [1.0.0] - 2021-04-05

Initial release.
