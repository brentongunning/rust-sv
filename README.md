# Rust-SV

A library to build Bitcoin SV applications in Rust.

[Documentation](https://docs.rs/sv/)

Features

* P2P protocol messages (construction and serialization)
* Address encoding and decoding
* Transaction signing
* Script evaluation
* Node connections and basic message handling
* Wallet key derivation and mnemonic parsing
* Mainnet and testnet support
* Various Bitcoin primitives
* Genesis upgrade support

# Installation

Add ```sv = "0.2"``` to Cargo.toml

# Known limitations

This library should not be used for consensus code because its validation checks are incomplete.

# Comparison with other Rust libraries

*rust-bitcoin* - rust-sv has no ties to rust-bitcoin. This library can do everything rust-bitcoin can do and more for Bitcoin SV.

*parity-bitcoin* - The parity Bitcoin client is a full node in Rust. Its code is more full-featured and also more complex.

*bitcrust* - The bitcrust project is strong in some areas and lacking in others. The two projects could be used together.

# License

rust-sv is licensed under the MIT license.
