# Rust-SV

A library to build Bitcoin SV applications and infrastructure in Rust.

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

# License

rust-sv is licensed under the MIT license.
