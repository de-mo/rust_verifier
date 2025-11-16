// Copyright © 2025 Denis Morel
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License and
// a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.

//! # Library for all the functionalities of the E-Voting Verifier
//!
//! ## Introduction
//!
//! This crate is the main library for the E-Voting system of Swiss Post.
//!
//! It is based on the specifications of Swiss Post, according to the following document versions:
//!
//! - [Crypo-primitives Specifications](https://gitlab.com/swisspost-evoting/crypto-primitives/crypto-primitives/-/blob/master/Crypto-Primitives-Specification.pdf?ref_type=heads)
//! - [System Specifications](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/blob/master/System/System_Specification.pdf)
//! - [Verifier Specifications](https://gitlab.com/swisspost-evoting/e-voting/e-voting-documentation/-/blob/master/System/Verifier_Specification.pdf?ref_type=heads)
//!
//! The verifier is implemented for the version 1.4.4 of the E-Voting system of Swiss Post.
//!
//! This crate is used as basis for a GUI application.
//!
//! ##  Structure of the project
//!
//! The library contains the following modules:
//!
//! - `data_structures`: The implementation of structure of the data used for the Verifier. The data are reading from the files using [serde](https://docs.rs/serde/latest/serde/)
//! - [`file_structure`]: The necessary functions to implement the files and directories
//! - [`verification`]: The implementation of each verification.
//!
//! The library depends from the following crates
//! - [rust_ev_crypto_primitives](https://github.com/de-mo/rust_ev_crypto_primitives)
//! - [rust_ev_system_library](https://github.com/de-mo/rust_ev_system_library)
//!
//! ## Development guide
//!
//! Copy the directoy `/datasets/direct-trust` to the root.
//!
//! The build on Windows must be done with MSYS2 (see [Crypto Primitives](https://github.com/de-mo/rust_ev_crypto_primitives) for details)
//!
//! ## Integration Guide
//!
//! ### Environment Variables
//! The configuration used some environment variables, the can/must be integrated using the crate [dotenvy](https://crates.io/crates/dotenvy)
//! | Variable                  | Description                                            | Required | default |
//! | ------------------------- | ------------------------------------------------------ | :------: | ------- |
//! | VERIFIER_DATASET_PASSWORD | The password of the encrypted zip files                | X        | n/a |
//! | TXT_REPORT_TAB_SIZE       | The tab size for the text reports                      |          | 2 |
//! | REPORT_FORMAT_DATE        | The format of the date in the report                   |          | `%d.%m.%Y %H:%M:%S.%3f` |
//! | DIRECT_TRUST_DIR_PATH     | The path to the direct trust keystore for the verifier |          | The path `./direct-trust` where `.` is the installation directory |
//!
//! The environment variables are retrieved using the static instance of [`VerifierConfig`]
//!
//!

//pub mod application_runner;
mod config;
mod consts;
mod data_structures;
pub mod dataset;
pub mod direct_trust;
mod error_utils;
pub mod file_structure;
mod resources;
pub mod startup_checks;
pub mod verification;

pub use config::{VerifierConfig, VerifierConfigError};
pub use data_structures::{DatasetType, VerifierDataDecode, dataset::DatasetTypeKind};
pub mod election_event_configuration {
    pub use crate::data_structures::context::election_event_configuration::*;
}
pub mod ech_0222 {
    pub use crate::data_structures::tally::ech_0222::*;
}
pub use error_utils::{ErrorChain, Report};
