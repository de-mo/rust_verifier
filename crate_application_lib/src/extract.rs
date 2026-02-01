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

use crate::RunnerErrorImpl;

use super::RunnerError;
use rust_ev_verifier_lib::{
    DatasetTypeKind, VerifierConfig, dataset::DatasetMetadata, verification::VerificationPeriod,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use tracing::{info, instrument};

#[derive(Debug, Clone)]
pub struct ExtractDataSetResults {
    metadata_hm: HashMap<DatasetTypeKind, DatasetMetadata>,
    location: PathBuf,
}

impl ExtractDataSetResults {
    pub fn location(&self) -> &Path {
        &self.location
    }

    pub fn dataset_metadata(&self, kind: &DatasetTypeKind) -> Option<&DatasetMetadata> {
        self.metadata_hm.get(kind)
    }

    #[instrument(skip(password, config))]
    pub fn extract_datasets(
        period: VerificationPeriod,
        context_zip_file: &Path,
        tally_zip_file: Option<&Path>,
        password: &str,
        config: &'static VerifierConfig,
    ) -> Result<Self, RunnerError> {
        Self::extract_datasets_impl(period, context_zip_file, tally_zip_file, password, config)
            .map_err(RunnerError::from)
    }

    fn extract_datasets_impl(
        period: VerificationPeriod,
        context_zip_file: &Path,
        tally_zip_file: Option<&Path>,
        password: &str,
        config: &'static VerifierConfig,
    ) -> Result<Self, RunnerErrorImpl> {
        let dataset_root_path = config.create_dataset_dir_path();
        let mut hm = HashMap::new();
        match period {
            VerificationPeriod::Setup => {}
            VerificationPeriod::Tally => {
                if let Some(tally_zip_file) = tally_zip_file {
                    let md = DatasetMetadata::extract_dataset_kind_with_inputs(
                        DatasetTypeKind::Tally,
                        tally_zip_file,
                        password,
                        &dataset_root_path,
                        &config.zip_temp_dir_path(),
                    )
                    .map_err(|e| RunnerErrorImpl::ExtractError {
                        name: "tally",
                        source: Box::new(e),
                    })?;
                    info!(
                        "Tally extracted by {} (fingerprint: {}",
                        md.extracted_dir_path().to_str().unwrap(),
                        md.fingerprint_str()
                    );
                    hm.insert(DatasetTypeKind::Tally, md);
                } else {
                    return Err(RunnerErrorImpl::ExtractFileMissing { period: "tally" });
                }
            }
        }
        let md = DatasetMetadata::extract_dataset_kind_with_inputs(
            DatasetTypeKind::Context,
            context_zip_file,
            password,
            &dataset_root_path,
            &config.zip_temp_dir_path(),
        )
        .map_err(|e| RunnerErrorImpl::ExtractError {
            name: "context",
            source: Box::new(e),
        })?;
        info!(
            "Context extracted by {} (fingerprint: {}",
            md.extracted_dir_path().to_str().unwrap(),
            md.fingerprint_str()
        );
        hm.insert(DatasetTypeKind::Context, md);
        Ok(Self {
            metadata_hm: hm,
            location: dataset_root_path,
        })
    }
}
