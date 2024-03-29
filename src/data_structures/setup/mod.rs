//! Module implementing the data structures of the setup directory

pub mod control_component_code_shares_payload;
pub mod control_component_public_keys_payload;
pub mod election_event_configuration;
pub mod election_event_context_payload;
pub mod setup_component_public_keys_payload;
pub mod setup_component_tally_data_payload;
pub mod setup_component_verification_data_payload;

use self::{
    control_component_code_shares_payload::ControlComponentCodeSharesPayload,
    control_component_public_keys_payload::ControlComponentPublicKeysPayload,
    election_event_configuration::ElectionEventConfiguration,
    election_event_context_payload::ElectionEventContextPayload,
    setup_component_public_keys_payload::SetupComponentPublicKeysPayload,
    setup_component_tally_data_payload::SetupComponentTallyDataPayload,
    setup_component_verification_data_payload::SetupComponentVerificationDataPayload,
};
use super::{VerifierDataDecode, VerifierSetupDataTrait};
use crate::file_structure::{file::File, FileReadMode, FileType};
use enum_kinds::EnumKind;

/// Types of the setup directory
/// An enum VerifierSetupDataType is automatically creating
#[derive(Clone, EnumKind)]
#[enum_kind(VerifierSetupDataType)]
pub enum VerifierSetupData {
    ElectionEventContextPayload(ElectionEventContextPayload),
    SetupComponentPublicKeysPayload(SetupComponentPublicKeysPayload),
    ControlComponentPublicKeysPayload(ControlComponentPublicKeysPayload),
    SetupComponentVerificationDataPayload(SetupComponentVerificationDataPayload),
    ControlComponentCodeSharesPayload(ControlComponentCodeSharesPayload),
    SetupComponentTallyDataPayload(SetupComponentTallyDataPayload),
    ElectionEventConfiguration(ElectionEventConfiguration),
}

impl VerifierSetupDataType {
    /// Get the type of the file for the [VerifierSetupData]
    pub fn get_file_type(&self) -> FileType {
        match self {
            Self::ElectionEventContextPayload => FileType::Json,
            Self::SetupComponentPublicKeysPayload => FileType::Json,
            Self::ControlComponentPublicKeysPayload => FileType::Json,
            Self::SetupComponentVerificationDataPayload => FileType::Json,
            Self::ControlComponentCodeSharesPayload => FileType::Json,
            Self::SetupComponentTallyDataPayload => FileType::Json,
            Self::ElectionEventConfiguration => FileType::Xml,
        }
    }

    /// Get the read mode of the file for the [VerifierSetupData]
    pub fn get_file_read_mode(&self) -> FileReadMode {
        match self {
            Self::ElectionEventContextPayload => FileReadMode::Memory,
            Self::SetupComponentPublicKeysPayload => FileReadMode::Memory,
            Self::ControlComponentPublicKeysPayload => FileReadMode::Memory,
            Self::SetupComponentVerificationDataPayload => FileReadMode::Memory,
            Self::ControlComponentCodeSharesPayload => FileReadMode::Memory,
            Self::SetupComponentTallyDataPayload => FileReadMode::Memory,
            Self::ElectionEventConfiguration => FileReadMode::Streaming,
        }
    }

    /// Read from String as json or xml
    ///
    /// All the types have to oimplement the trait [VerifierDataDecode]
    pub fn verifier_data_from_file(&self, f: &File) -> anyhow::Result<VerifierSetupData> {
        match self {
            VerifierSetupDataType::ElectionEventContextPayload => {
                ElectionEventContextPayload::from_file(
                    f,
                    &self.get_file_type(),
                    &self.get_file_read_mode(),
                )
                .map(VerifierSetupData::ElectionEventContextPayload)
            }
            VerifierSetupDataType::SetupComponentPublicKeysPayload => {
                SetupComponentPublicKeysPayload::from_file(
                    f,
                    &self.get_file_type(),
                    &self.get_file_read_mode(),
                )
                .map(VerifierSetupData::SetupComponentPublicKeysPayload)
            }
            VerifierSetupDataType::ControlComponentPublicKeysPayload => {
                ControlComponentPublicKeysPayload::from_file(
                    f,
                    &self.get_file_type(),
                    &self.get_file_read_mode(),
                )
                .map(VerifierSetupData::ControlComponentPublicKeysPayload)
            }
            VerifierSetupDataType::SetupComponentVerificationDataPayload => {
                SetupComponentVerificationDataPayload::from_file(
                    f,
                    &self.get_file_type(),
                    &self.get_file_read_mode(),
                )
                .map(VerifierSetupData::SetupComponentVerificationDataPayload)
            }
            VerifierSetupDataType::ControlComponentCodeSharesPayload => {
                ControlComponentCodeSharesPayload::from_file(
                    f,
                    &self.get_file_type(),
                    &self.get_file_read_mode(),
                )
                .map(VerifierSetupData::ControlComponentCodeSharesPayload)
            }
            VerifierSetupDataType::SetupComponentTallyDataPayload => {
                SetupComponentTallyDataPayload::from_file(
                    f,
                    &self.get_file_type(),
                    &self.get_file_read_mode(),
                )
                .map(VerifierSetupData::SetupComponentTallyDataPayload)
            }
            VerifierSetupDataType::ElectionEventConfiguration => {
                ElectionEventConfiguration::from_file(
                    f,
                    &self.get_file_type(),
                    &self.get_file_read_mode(),
                )
                .map(VerifierSetupData::ElectionEventConfiguration)
            }
        }
    }
}

impl VerifierSetupDataTrait for VerifierSetupData {
    fn setup_component_public_keys_payload(&self) -> Option<&SetupComponentPublicKeysPayload> {
        if let VerifierSetupData::SetupComponentPublicKeysPayload(d) = self {
            return Some(d);
        }
        None
    }

    fn election_event_context_payload(&self) -> Option<&ElectionEventContextPayload> {
        if let VerifierSetupData::ElectionEventContextPayload(d) = self {
            return Some(d);
        }
        None
    }

    fn setup_component_tally_data_payload(&self) -> Option<&SetupComponentTallyDataPayload> {
        if let VerifierSetupData::SetupComponentTallyDataPayload(d) = self {
            return Some(d);
        }
        None
    }

    fn control_component_public_keys_payload(&self) -> Option<&ControlComponentPublicKeysPayload> {
        if let VerifierSetupData::ControlComponentPublicKeysPayload(d) = self {
            return Some(d);
        }
        None
    }

    fn setup_component_verification_data_payload(
        &self,
    ) -> Option<&SetupComponentVerificationDataPayload> {
        if let VerifierSetupData::SetupComponentVerificationDataPayload(d) = self {
            return Some(d);
        }
        None
    }

    fn control_component_code_shares_payload(&self) -> Option<&ControlComponentCodeSharesPayload> {
        if let VerifierSetupData::ControlComponentCodeSharesPayload(d) = self {
            return Some(d);
        }
        None
    }

    fn election_event_configuration(&self) -> Option<&ElectionEventConfiguration> {
        if let VerifierSetupData::ElectionEventConfiguration(d) = self {
            return Some(d);
        }
        None
    }
}
