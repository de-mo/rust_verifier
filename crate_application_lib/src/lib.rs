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

//! Crate implementing common functionalities for all Verifier applications (console and GUI)
//!
//! Following functionalities are provided
//! - [runner::Runner] provides the possibility to run all the verifications
//! - `extract` provides the functionalities to extract the zip files
//! - [run_information::RunInformation] stores all the information about the current running
//! - [report] provides the possibility to report the actual stituation

mod extract;
pub mod report;
mod results;
mod run_information;
mod runner;

pub use extract::*;
use std::path::Path;
//pub use report::*;
pub use results::*;
pub use run_information::RunInformation;
pub use runner::{
    RunParallel, RunSequential, Runner, RunnerInformation, VerificationRunInformation,
    no_action_after_fn, no_action_after_runner_fn, no_action_before_fn, no_action_before_runner_fn,
};
use rust_ev_verifier_lib::{
    dataset::DatasetError,
    file_structure::{
        ContextDirectoryTrait, FileStructureError, VerificationDirectory,
        VerificationDirectoryTrait,
    },
    verification::{VerificationError, VerificationPeriod},
};
use thiserror::Error;

#[derive(Error, Debug)]
#[error(transparent)]
/// Error during the runner
pub struct RunnerError(#[from] RunnerErrorImpl);

#[derive(Error, Debug)]
enum RunnerErrorImpl {
    #[error("Error reading election event context (in prepare_fixed_based_optimization)")]
    EEContextPrepareFixedBased { source: FileStructureError },
    #[error("Extract dataset: For {period}, the dataset for {period} must be delivered")]
    ExtractFileMissing { period: &'static str },
    #[error("Error extracting the dataset {name}")]
    ExtractError {
        name: &'static str,
        source: Box<DatasetError>,
    },
    #[error("Error collecting the verifications for {period}")]
    CollectVerifications {
        period: VerificationPeriod,
        source: Box<VerificationError>,
    },
    #[error(
        "Not possible to create the manual verifications: The run information must be prepared"
    )]
    ManualRunInformationNotPrepared,
    #[error("Error creating the manual verifications")]
    Manual { source: Box<VerificationError> },
    #[error("Check error during {function}: {msg}")]
    CheckError { function: &'static str, msg: String },
    #[error("Error prepare_fixed_based_optimization creating the runner")]
    RunnerFixBased { source: Box<RunnerError> },
    #[error("Error creating the verifications suite in {function}")]
    Suite {
        function: &'static str,
        source: Box<VerificationError>,
    },
    #[error("Runner is already running. Cannot be started")]
    IsRunning,
    #[error("Runner has already run. Cannot be started before resetting it")]
    HasAlreadyRun,
    #[error("Error collectiong the election event id")]
    ElectionEventIdCollection { source: Box<FileStructureError> },
}

fn prepare_fixed_based_optimization(dir: &VerificationDirectory) -> Result<(), RunnerError> {
    let context_dir = dir.context();
    let context = context_dir
        .election_event_context_payload()
        .map_err(|e| RunnerErrorImpl::EEContextPrepareFixedBased { source: e })?;
    let _ =
        rust_ev_verifier_lib::rust_ev_crypto_primitives::prelude::prepare_fixed_based_optimization(
            context.encryption_group.g(),
            context.encryption_group.p(),
        );
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn canonicalize_path_os_dependent<P: AsRef<Path>>(p: P) -> String {
    p.as_ref()
        .canonicalize()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

#[cfg(target_os = "windows")]
fn canonicalize_path_os_dependent<P: AsRef<Path>>(p: P) -> String {
    const VERBATIM_PREFIX: &str = r#"\\?\"#;
    let p = p
        .as_ref()
        .canonicalize()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    if p.starts_with(VERBATIM_PREFIX) {
        p.replace(VERBATIM_PREFIX, "")
    } else {
        p.to_string()
    }
}
