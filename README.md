# E-Voting Verifier in Rust

## Introduction

This crate is the main library for the E-Voting system of Swiss Post.

It is based on the specifications of Swiss Post, according to the following document versions:

- [Crypo-primitives Specifications](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/blob/master/Crypto-Primitives-Specification.pdf?ref_type=heads)
- [System Specifications](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/blob/master/System/System_Specification.pdf)
- [Verifier Specifications](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/blob/master/System/Verifier_Specification.pdf?ref_type=heads)

The verifier is implemented for the version 1.5.4 of the E-Voting system of Swiss Post.

This crate is used as basis for a GUI application.

Following application are implemented:
- A console application [rust_ev_verifier_console](https://github.com/de-mo/rust_ev_verifier_console)
- A GUI application based on tauri ([backend](https://github.com/de-mo/rust_ev_verifier_gui_backend) / [frontend](https://github.com/de-mo/rust_ev_verifier_gui))

## Information about the project

###  Difference to the Swiss Post implementation

The implementation don't use any code of Swiss Post. It is only based on the published documentation.

A major difference with the Swiss Post Verifier is that the verifications does not return true or false, but return all the errors and failures found, with the necessary information in regard to the position of the element, which generates the error. In this case it helps a better granularity for the analysis of the errors and failures.

The algorithm `VerifyECH0222` uses a complete different implementation as specified by Swiss Post (see [README](src/data_structures/tally/ech_0222/README.md)). The reason is that it is complex and unnecessary to generate an XML file that match the hash value (spaces, tabs, prefix must be exactly the same). We prefer to compare the business relevant data.

## Usage

See the [crate documentation](https://docs.rs/crate/rust_ev_verifier_lib/latest)

## Licence

rust_ev_verifier_lib is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE)
