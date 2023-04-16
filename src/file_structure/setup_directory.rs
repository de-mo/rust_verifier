use super::{
    file::{create_file, File},
    file_group::{impl_iterator_over_data_payload, FileGroup, FileGroupIter},
    FileStructureError,
};
use crate::{
    constants::{SETUP_DIR_NAME, VCS_DIR_NAME},
    data_structures::{
        create_verifier_data_type,
        setup::{
            control_component_code_shares_payload::ControlComponentCodeSharesPayload,
            control_component_public_keys_payload::ControlComponentPublicKeysPayload,
            election_event_configuration::ElectionEventConfiguration,
            election_event_context_payload::ElectionEventContextPayload,
            encryption_parameters_payload::EncryptionParametersPayload,
            setup_component_public_keys_payload::SetupComponentPublicKeysPayload,
            setup_component_tally_data_payload::SetupComponentTallyDataPayload,
            setup_component_verification_data_payload::SetupComponentVerificationDataPayload,
            VerifierSetupDataType,
        },
        VerifierDataType, VerifierSetupDataTrait,
    },
};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub struct SetupDirectory {
    location: PathBuf,
    encryption_parameters_payload_file: File,
    setup_component_public_keys_payload_file: File,
    election_event_context_payload_file: File,
    election_event_configuration_file: File,
    control_component_public_keys_payload_group: FileGroup,
    vcs_directories: Vec<VCSDirectory>,
}

#[derive(Clone)]
pub struct VCSDirectory {
    location: PathBuf,
    setup_component_tally_data_payload_file: File,
    setup_component_verification_data_payload_group: FileGroup,
    control_component_code_shares_payload_group: FileGroup,
}

/// Trait to set the necessary functions for the struct [SetupDirectory] that
/// are used during the tests
///
/// The trait is used as parameter of the verification functions to allow mock of
/// test (negative tests)
pub trait SetupDirectoryTrait<T>
where
    T: VCSDirectoryTrait,
{
    fn encryption_parameters_payload_file(&self) -> &File;
    fn setup_component_public_keys_payload_file(&self) -> &File;
    fn election_event_context_payload_file(&self) -> &File;
    fn election_event_configuration_file(&self) -> &File;
    fn control_component_public_keys_payload_group(&self) -> &FileGroup;
    fn vcs_directories(&self) -> &Vec<T>;
    fn encryption_parameters_payload(
        &self,
    ) -> Result<Box<EncryptionParametersPayload>, FileStructureError>;
    fn setup_component_public_keys_payload(
        &self,
    ) -> Result<Box<SetupComponentPublicKeysPayload>, FileStructureError>;

    fn election_event_context_payload(
        &self,
    ) -> Result<Box<ElectionEventContextPayload>, FileStructureError>;
    fn election_event_configuration(
        &self,
    ) -> Result<Box<ElectionEventConfiguration>, FileStructureError>;

    fn control_component_public_keys_payload_iter(
        &self,
    ) -> ControlComponentPublicKeysPayloadReadIter;
}

/// Trait to set the necessary functions for the struct [VCSDirectory] that
/// are used during the tests
///
/// The trait is used as parameter of the verification functions to allow mock of
/// test (negative tests)
pub trait VCSDirectoryTrait {
    fn setup_component_tally_data_payload_file(&self) -> &File;
    fn setup_component_verification_data_payload_group(&self) -> &FileGroup;
    fn control_component_code_shares_payload_group(&self) -> &FileGroup;
    fn setup_component_tally_data_payload(
        &self,
    ) -> Result<Box<SetupComponentTallyDataPayload>, FileStructureError>;
    fn setup_component_verification_data_payload_iter(
        &self,
    ) -> SetupComponentVerificationDataPayloadReadIter;

    fn control_component_code_shares_payload_iter(
        &self,
    ) -> ControlComponentCodeSharesPayloadReadIter;
    fn get_name(&self) -> String;
}

impl_iterator_over_data_payload!(
    ControlComponentPublicKeysPayload,
    control_component_public_keys_payload,
    ControlComponentPublicKeysPayloadRead,
    ControlComponentPublicKeysPayloadReadIter
);

impl_iterator_over_data_payload!(
    SetupComponentVerificationDataPayload,
    setup_component_verification_data_payload,
    SetupComponentVerificationDataPayloadRead,
    SetupComponentVerificationDataPayloadReadIter
);

impl_iterator_over_data_payload!(
    ControlComponentCodeSharesPayload,
    control_component_code_shares_payload,
    ControlComponentCodeSharesPayloadRead,
    ControlComponentCodeSharesPayloadReadIter
);

impl SetupDirectory {
    pub fn new(data_location: &Path) -> Self {
        let location = data_location.join(SETUP_DIR_NAME);
        let mut res = Self {
            location: location.to_path_buf(),
            encryption_parameters_payload_file: create_file!(
                location,
                Setup,
                VerifierSetupDataType::EncryptionParametersPayload
            ),
            setup_component_public_keys_payload_file: create_file!(
                location,
                Setup,
                VerifierSetupDataType::SetupComponentPublicKeysPayload
            ),
            election_event_context_payload_file: create_file!(
                location,
                Setup,
                VerifierSetupDataType::ElectionEventContextPayload
            ),
            election_event_configuration_file: create_file!(
                location,
                Setup,
                VerifierSetupDataType::ElectionEventConfiguration
            ),
            control_component_public_keys_payload_group: FileGroup::new(
                &location,
                create_verifier_data_type!(Setup, ControlComponentPublicKeysPayload),
            ),
            vcs_directories: vec![],
        };
        let vcs_path = location.join(VCS_DIR_NAME);
        if vcs_path.is_dir() {
            for re in fs::read_dir(&vcs_path).unwrap() {
                let e = re.unwrap().path();
                if e.is_dir() {
                    res.vcs_directories.push(VCSDirectory::new(&e))
                }
            }
        }
        res
    }

    pub fn get_location(&self) -> &Path {
        self.location.as_path()
    }
}

impl SetupDirectoryTrait<VCSDirectory> for SetupDirectory {
    fn encryption_parameters_payload_file(&self) -> &File {
        &self.encryption_parameters_payload_file
    }
    fn setup_component_public_keys_payload_file(&self) -> &File {
        &self.setup_component_public_keys_payload_file
    }
    fn election_event_context_payload_file(&self) -> &File {
        &self.election_event_context_payload_file
    }
    fn election_event_configuration_file(&self) -> &File {
        &self.election_event_configuration_file
    }
    fn control_component_public_keys_payload_group(&self) -> &FileGroup {
        &self.control_component_public_keys_payload_group
    }
    fn vcs_directories(&self) -> &Vec<VCSDirectory> {
        &self.vcs_directories
    }
    fn encryption_parameters_payload(
        &self,
    ) -> Result<Box<EncryptionParametersPayload>, FileStructureError> {
        self.encryption_parameters_payload_file
            .get_data()
            .map(|d| Box::new(d.encryption_parameters_payload().unwrap().clone()))
    }

    fn setup_component_public_keys_payload(
        &self,
    ) -> Result<Box<SetupComponentPublicKeysPayload>, FileStructureError> {
        self.setup_component_public_keys_payload_file
            .get_data()
            .map(|d| Box::new(d.setup_component_public_keys_payload().unwrap().clone()))
    }

    fn election_event_context_payload(
        &self,
    ) -> Result<Box<ElectionEventContextPayload>, FileStructureError> {
        self.election_event_context_payload_file
            .get_data()
            .map(|d| Box::new(d.election_event_context_payload().unwrap().clone()))
    }

    fn election_event_configuration(
        &self,
    ) -> Result<Box<ElectionEventConfiguration>, FileStructureError> {
        self.election_event_configuration_file
            .get_data()
            .map(|d| Box::new(d.election_event_configuration().unwrap().clone()))
    }

    fn control_component_public_keys_payload_iter(
        &self,
    ) -> ControlComponentPublicKeysPayloadReadIter {
        FileGroupIter::new(&self.control_component_public_keys_payload_group)
    }
}

impl VCSDirectory {
    pub fn new(location: &Path) -> Self {
        Self {
            location: location.to_path_buf(),
            setup_component_tally_data_payload_file: create_file!(
                location,
                Setup,
                VerifierSetupDataType::SetupComponentTallyDataPayload
            ),
            setup_component_verification_data_payload_group: FileGroup::new(
                &location,
                create_verifier_data_type!(Setup, SetupComponentVerificationDataPayload),
            ),
            control_component_code_shares_payload_group: FileGroup::new(
                &location,
                create_verifier_data_type!(Setup, ControlComponentCodeSharesPayload),
            ),
        }
    }

    pub fn get_location(&self) -> &Path {
        self.location.as_path()
    }
}

impl VCSDirectoryTrait for VCSDirectory {
    fn setup_component_tally_data_payload_file(&self) -> &File {
        &self.setup_component_tally_data_payload_file
    }
    fn setup_component_verification_data_payload_group(&self) -> &FileGroup {
        &self.setup_component_verification_data_payload_group
    }
    fn control_component_code_shares_payload_group(&self) -> &FileGroup {
        &self.control_component_code_shares_payload_group
    }
    fn setup_component_tally_data_payload(
        &self,
    ) -> Result<Box<SetupComponentTallyDataPayload>, FileStructureError> {
        self.setup_component_tally_data_payload_file
            .get_data()
            .map(|d| Box::new(d.setup_component_tally_data_payload().unwrap().clone()))
    }

    fn setup_component_verification_data_payload_iter(
        &self,
    ) -> SetupComponentVerificationDataPayloadReadIter {
        FileGroupIter::new(&self.setup_component_verification_data_payload_group)
    }

    fn control_component_code_shares_payload_iter(
        &self,
    ) -> ControlComponentCodeSharesPayloadReadIter {
        FileGroupIter::new(&self.control_component_code_shares_payload_group)
    }
    fn get_name(&self) -> String {
        self.location
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::path::{Path, PathBuf};

    fn get_location() -> PathBuf {
        Path::new(".").join("datasets").join("dataset-setup1")
    }

    #[test]
    fn test_setup_dir() {
        let location = get_location();
        let setup_location = location.join("setup");
        let vcs_location = setup_location.join("verification_card_sets");
        let dir = SetupDirectory::new(&location);
        assert_eq!(dir.get_location(), setup_location);
        assert!(dir.encryption_parameters_payload().is_ok());
        assert!(dir.setup_component_public_keys_payload().is_ok());
        assert!(dir.election_event_context_payload().is_ok());
        for (i, p) in dir.control_component_public_keys_payload_iter() {
            assert!(p.is_ok());
            assert_eq!(
                usize::from(p.unwrap().control_component_public_keys.node_id),
                i
            )
        }
        let expected = vec![
            "7e8ce00c2c164c268c11cfa7066e3d9f",
            "517e62879eb44ef8bc1292bcf0b5b787",
            "eb98875b06c841529632cb8edd585f32",
            "37d2f678ee21425b997ba1dc50ae2c91",
        ];
        for (i, d) in dir.vcs_directories().iter().enumerate() {
            assert_eq!(d.get_location(), vcs_location.join(expected[i]))
        }
    }

    #[test]
    fn test_vcs_dir() {
        let location = get_location()
            .join("setup")
            .join("verification_card_sets")
            .join("7e8ce00c2c164c268c11cfa7066e3d9f");
        let dir = VCSDirectory::new(&location);
        assert_eq!(dir.get_location(), location);
        assert!(dir.setup_component_tally_data_payload().is_ok());
        for (i, p) in dir.control_component_code_shares_payload_iter() {
            assert!(p.is_ok());
            for k in p.unwrap().iter() {
                assert_eq!(k.chunk_id, i)
            }
        }
        for (i, p) in dir.setup_component_verification_data_payload_iter() {
            assert!(p.is_ok());
            assert_eq!(usize::from(p.unwrap().chunk_id), i)
        }
    }
}
