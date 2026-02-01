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

use crate::{
    VerifierConfig,
    file_structure::{CompletnessTestTrait, VerificationDirectory, VerificationDirectoryTrait},
    verification::{VerificationMetaDataList, VerificationPeriod},
};
use std::path::Path;

/// Check some elements before starting the verifications.
///
/// Must be called by the application at the beginning. If error, then cannot continue
pub fn start_check(config: &'static VerifierConfig) -> Result<(), String> {
    let md_list_check = VerificationMetaDataList::load(config.get_verification_list_str());
    if let Err(e) = md_list_check {
        return Err(format!("List of verifications has an error: {}", e));
    }
    config
        .keystore()
        .map_err(|e| format!("Cannot read keystore: {e}"))?;
    Ok(())
}

/// Check that the verification directory correct ist
pub fn check_verification_dir(period: &VerificationPeriod, path: &Path) -> Result<(), String> {
    if !path.is_dir() {
        return Err(format!("Given directory {path:?} does not exist"));
    };
    if !path.join(VerifierConfig::context_dir_name()).is_dir() {
        return Err(format!(
            "Directory {} does not exist in directory {:?}",
            VerifierConfig::context_dir_name(),
            path
        ));
    };
    match period {
        VerificationPeriod::Setup => {}
        VerificationPeriod::Tally => {
            let dir_name = VerifierConfig::tally_dir_name();
            if !path.join(dir_name).is_dir() {
                return Err(format!(
                    "Directory {dir_name} does not exist in directory {path:?}"
                ));
            }
        }
    }
    Ok(())
}

/// Check that the directory is complete
pub fn check_complete(
    period: &VerificationPeriod,
    dir: &VerificationDirectory,
) -> Result<(), String> {
    let context_complete = dir
        .context()
        .test_completness()
        .map_err(|e| e.to_string())?;
    if !context_complete.is_empty() {
        return Err(format!(
            "Context directory not complete: {}",
            context_complete.join(" / ")
        ));
    }
    let complete = match period {
        VerificationPeriod::Setup => vec![],
        VerificationPeriod::Tally => dir
            .unwrap_tally()
            .test_completness()
            .map_err(|e| e.to_string())?,
    };
    if !complete.is_empty() {
        return Err(format!(
            "{} directory not complete: {}",
            period.as_ref(),
            complete.join(" / ")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::{VerificationPeriod, *};
    use crate::config::test::test_datasets_path;
    use std::path::Path;

    #[test]
    fn test_check_verification_dir() {
        assert!(check_verification_dir(&VerificationPeriod::Setup, Path::new("./toto")).is_err());
        assert!(check_verification_dir(&VerificationPeriod::Tally, Path::new("./toto")).is_err());
        assert!(check_verification_dir(&VerificationPeriod::Setup, Path::new(".")).is_err());
        assert!(check_verification_dir(&VerificationPeriod::Tally, Path::new(".")).is_err());
        assert!(check_verification_dir(&VerificationPeriod::Setup, &test_datasets_path()).is_ok());
        assert!(check_verification_dir(&VerificationPeriod::Tally, &test_datasets_path()).is_ok());
    }
}
