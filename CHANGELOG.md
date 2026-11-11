# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-11-10

### Security
- `ExchangeVault.import_record` (and `MemoryBackend::import_record`/`hydrate_generation` in the Rust core) now refuse generation 0 with `VaultError`. A version-1 object carries generation 0, so trusting an imported generation 0 let such an object pass the rollback check.

## [0.1.0] - 2026-09-28

First public release, published for the maivn 2.0.0 SDK.

### Added
- Sealed local storage for private documents and redacted values, with the key held in the operating system keyring.
- abi3 wheels for CPython 3.10 and later on Linux x86_64 and aarch64, macOS x86_64 and arm64, and Windows x64, plus a source distribution.
