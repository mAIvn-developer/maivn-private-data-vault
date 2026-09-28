# private-data-vault

Sealed local storage for private documents and the values redacted out of them, used by the `maivn` SDK. The vault keeps the sealed bytes on disk and the key in the operating system keyring, so a copied folder is unreadable on its own.

Wheels are built for CPython 3.10 and later on Linux (x86_64, aarch64), macOS (x86_64, arm64) and Windows (x64). The extension is written in Rust; a source distribution is published for other platforms and needs a Rust toolchain to build.

```bash
pip install private-data-vault
```

The SDK depends on this package and calls it for you. Direct use is documented in the type stubs shipped with the wheel (`private_data_vault/__init__.pyi`).

Licensed under Apache-2.0. Third-party licenses are listed in THIRD_PARTY_NOTICES.
