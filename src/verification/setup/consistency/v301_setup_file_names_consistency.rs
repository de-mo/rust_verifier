use super::super::super::{
    error::{create_verification_failure, VerificationFailureType},
    verification::VerificationResult,
};
use crate::{
    error::{create_verifier_error, VerifierError},
    file_structure::{
        file::File,
        setup_directory::{SetupDirectoryTrait, VCSDirectoryTrait},
        tally_directory::{BBDirectoryTrait, TallyDirectoryTrait},
        VerificationDirectoryTrait,
    },
};

fn test_file_exists(file: &File, result: &mut VerificationResult) {
    if !file.exists() {
        result.push_failure(create_verification_failure!(format!(
            "File {} does not exist",
            file.to_str()
        )))
    }
}

pub(super) fn fn_verification<
    B: BBDirectoryTrait,
    V: VCSDirectoryTrait,
    S: SetupDirectoryTrait<V>,
    T: TallyDirectoryTrait<B>,
>(
    dir: &dyn VerificationDirectoryTrait<B, V, S, T>,
    result: &mut VerificationResult,
) {
    let setup_dir = dir.unwrap_setup();
    test_file_exists(&setup_dir.encryption_parameters_payload_file(), result);
    test_file_exists(&setup_dir.election_event_context_payload_file(), result);
    test_file_exists(
        &setup_dir.setup_component_public_keys_payload_file(),
        result,
    );
    let mut cc_group_numbers = setup_dir
        .control_component_public_keys_payload_group()
        .get_numbers();
    cc_group_numbers.sort();
    if cc_group_numbers != vec![1, 2, 3, 4] {
        result.push_failure(create_verification_failure!(format!(
            "controlComponentPublicKeysPayload must have file from 1 to 4. But actually: {:?}",
            cc_group_numbers
        )))
    }
    for (_, f) in setup_dir
        .control_component_public_keys_payload_group()
        .iter()
    {
        test_file_exists(&f, result);
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::super::super::{verification::VerificationResultTrait, VerificationPeriod},
        *,
    };
    use crate::file_structure::VerificationDirectory;
    use std::path::Path;

    fn get_verifier_dir() -> VerificationDirectory {
        let location = Path::new(".").join("datasets").join("dataset-setup1");
        VerificationDirectory::new(&VerificationPeriod::Setup, &location)
    }

    #[test]
    fn test_ok() {
        let dir = get_verifier_dir();
        let mut result = VerificationResult::new();
        fn_verification(&dir, &mut result);
        assert!(result.is_ok().unwrap());
    }
}
