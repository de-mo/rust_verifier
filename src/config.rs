//! Module containing the contstants and the way to access them

use super::consts;
use super::resources::VERIFICATION_LIST;
use anyhow::{Context, Result};
use rust_ev_crypto_primitives::{CertificateExtension, Keystore};
use std::path::{Path, PathBuf};

// Directory structure
pub const SETUP_DIR_NAME: &str = "setup";
pub const TALLY_DIR_NAME: &str = "tally";
const VCS_DIR_NAME: &str = "verification_card_sets";
const BB_DIR_NAME: &str = "ballot_boxes";

// Program structure
const LOG_DIR_NAME: &str = "log";
const LOG_FILE_NAME: &str = "log.txt";
const DIRECT_TRUST_DIR_NAME: &str = "direct-trust";
// const KEYSTORE_FILE_NAME: &str = "public_keys_keystore_verifier.p12";
// const KEYSTORE_PASSWORD_FILE_NAME: &str = "public_keys_keystore_verifier_pw.txt";

/// Structuring getting all the configuration information relevant for the
/// verifier
///
/// The structure get only the root directory of the running application. The structure
/// can be defined as static using lazy_static crate:
/// ```ignore
/// use lazy_static::lazy_static;
/// lazy_static! {
///     static ref CONFIG: Config = Config::new("..");
///  }
/// ```
pub struct Config(&'static str);

/// New config with root_dir equal "."
impl Default for Config {
    fn default() -> Self {
        Self::new(".")
    }
}

impl Config {
    /// New Config
    pub fn new(root_dir: &'static str) -> Self {
        Config(root_dir)
    }

    /// Path of the root directory of the programm
    pub fn root_dir_path(&self) -> PathBuf {
        Path::new(self.0).to_path_buf()
    }

    /// Maximum number of voting options according to the specification
    pub fn maximum_number_of_voting_options() -> usize {
        consts::MAXIMUM_NUMBER_OF_VOTING_OPTIONS
    }

    /// Maximum number of selectable voting options according to the specification
    pub fn maximum_number_of_selectable_voting_options() -> usize {
        consts::MAXIMUM_NUMBER_OF_SELECTABLE_VOTING_OPTIONS
    }

    /// Maximum number of write-in options according to the specification
    #[allow(dead_code)]
    pub fn maximum_number_of_write_in_options() -> usize {
        consts::MAXIMUM_NUMBER_OF_WRITE_IN_OPTIONS
    }

    #[allow(dead_code)]
    pub fn maximum_write_in_option_length() -> usize {
        consts::MAXIMUM_WRITE_IN_OPTION_LENGTH
    }

    #[allow(dead_code)]
    pub fn maximum_actual_voting_option_length() -> usize {
        consts::MAXIMUM_ACTUAL_VOTING_OPTION_LENGTH
    }

    /// The name of the setup directory
    pub fn setup_dir_name() -> &'static str {
        SETUP_DIR_NAME
    }

    /// The name of the tally directory
    pub fn tally_dir_name() -> &'static str {
        TALLY_DIR_NAME
    }

    /// The name of the vcs (voting card sets) directories
    pub fn vcs_dir_name() -> &'static str {
        VCS_DIR_NAME
    }

    /// The name of the bb (ballot boxes) directories
    pub fn bb_dir_name() -> &'static str {
        BB_DIR_NAME
    }

    /// The path to the log file
    pub fn log_file_path(&self) -> PathBuf {
        self.root_dir_path().join(LOG_DIR_NAME).join(LOG_FILE_NAME)
    }

    /// The path to the directory where direct trust keystore is stored
    fn direct_trust_dir_path(&self) -> PathBuf {
        self.root_dir_path().join(DIRECT_TRUST_DIR_NAME)
    }

    /*
    pub fn direct_trust_keystore_path(&self) -> PathBuf {
        self.direct_trust_dir_path().join(KEYSTORE_FILE_NAME)
    }

    pub fn direct_trust_keystore_password_path(&self) -> PathBuf {
        self.direct_trust_dir_path()
            .join(KEYSTORE_PASSWORD_FILE_NAME)
    } */

    /// Get the relative path of the file containing the configuration of the verifications
    pub fn get_verification_list_str(&self) -> &'static str {
        VERIFICATION_LIST
    }

    /// Get the keystore
    pub fn keystore(&self) -> Result<Keystore> {
        Keystore::from_directory(&self.direct_trust_dir_path(), &CertificateExtension::Cer)
            .context("Problem reading the keystore")
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{file_structure::VerificationDirectory, verification::VerificationPeriod};
    use lazy_static::lazy_static;

    lazy_static! {
        pub(crate) static ref CONFIG_TEST: Config = Config::new(".");
    }

    pub(crate) fn test_datasets_path() -> PathBuf {
        CONFIG_TEST.root_dir_path().join("datasets")
    }

    pub(crate) fn test_dataset_setup_path() -> PathBuf {
        test_datasets_path().join("dataset-setup")
    }

    pub(crate) fn test_dataset_tally_path() -> PathBuf {
        test_datasets_path().join("dataset-tally")
    }

    pub(crate) fn test_ballot_box_path() -> PathBuf {
        test_dataset_tally_path()
            .join("tally")
            .join("ballot_boxes")
            .join("5E70613C80C92E6AC48227492099DF7D")
    }

    pub(crate) fn test_verification_card_set_path() -> PathBuf {
        test_dataset_setup_path()
            .join("setup")
            .join("verification_card_sets")
            .join("1B3775CB351C64AC33B754BA3A02AED2")
    }

    pub(crate) fn test_xml_path() -> PathBuf {
        test_datasets_path().join("xml")
    }

    pub(crate) fn get_test_verifier_tally_dir() -> VerificationDirectory {
        VerificationDirectory::new(&VerificationPeriod::Tally, &test_dataset_tally_path())
    }

    pub(crate) fn get_test_verifier_setup_dir() -> VerificationDirectory {
        VerificationDirectory::new(&VerificationPeriod::Setup, &test_dataset_setup_path())
    }

    #[test]
    fn test_config() {
        let c = Config::default();
        assert_eq!(c.root_dir_path(), Path::new("."));
        assert_eq!(c.log_file_path(), Path::new("./log/log.txt"));
        assert_eq!(c.direct_trust_dir_path(), Path::new("./direct-trust"));
        assert!(!c.get_verification_list_str().is_empty());
    }
}
