# FHE Workshop
[![CI](https://github.com/auryn-macmillan/fhe-workshop/workflows/CI/badge.svg)](https://github.com/auryn-macmillan/fhe-workshop/actions)

This repository contains a simple secret ballot implementation using Fully Homomorphic Encryption (FHE) to tally encrypted votes and only decrypt the output. It leverages [fhe.rs](https://github.com/tlepoint/fhe.rs) and is intended as a simple and practical demonstration developing an FHE application.

This code was originally written for a workshop at [FHE Summit 2024, in Brussels](https://www.fhesummit.com/). As such, you'll find extensive comments in [main.rs](/src/main.rs) which served as a script for the workshop and give a high-level overview of FHE, what the various parameters mean, and each of the phases of the computation.

*Note: while the encryption scheme used in this repo, Brakerski/Fan-Vercauteren (BFV), is fully homomorphic, the secret ballot implementation only performs additions on the ciphertext inputs, so it it not a true demonstration of the fully homomorphic properties of the scheme.*

## Usage

1. Install the Rust toolchain to have cargo installed by following [this guide](https://www.rust-lang.org/tools/install).
2. Clone this repo

    `git clone https://github.com/auryn-macmillan/fhe-workshop.git`

    `cd fhe-workshop`

3. Run run the application

    `cargo run`

## License

This project is licensed under either of the following, at your choice:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

## Contributing

Contributions are welcome! Please see our [contribution guide](CONTRIBUTING.md) for details.