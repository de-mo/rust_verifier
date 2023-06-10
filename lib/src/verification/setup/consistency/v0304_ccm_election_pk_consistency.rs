use super::super::super::result::{
    create_verification_error, create_verification_failure, VerificationEvent, VerificationResult,
};
use crate::{
    data_structures::{
        setup::control_component_public_keys_payload::ControlComponentPublicKeys,
        VerifierSetupDataTrait,
    },
    file_structure::{setup_directory::SetupDirectoryTrait, VerificationDirectoryTrait},
};
use anyhow::anyhow;
use log::debug;

fn validate_cc_ccm_pk<S: SetupDirectoryTrait>(
    setup_dir: &S,
    setup: &ControlComponentPublicKeys,
    node_id: usize,
    result: &mut VerificationResult,
) {
    let f = setup_dir
        .control_component_public_keys_payload_group()
        .get_file_with_number(node_id);
    let cc_pk = match f
        .get_data()
        .map(|d| Box::new(d.control_component_public_keys_payload().unwrap().clone()))
    {
        Ok(d) => d.control_component_public_keys,
        Err(e) => {
            result.push(create_verification_error!(
                format!("Cannot read data from file {}", f.to_str()),
                e
            ));
            return;
        }
    };
    if setup.ccmj_election_public_key.len() != cc_pk.ccmj_election_public_key.len() {
        result.push(create_verification_failure!(format!("The length of CCM public keys for control component {} are identical from both sources", node_id)));
    } else if setup.ccrj_choice_return_codes_encryption_public_key
        != cc_pk.ccrj_choice_return_codes_encryption_public_key
    {
        result.push(create_verification_failure!(format!(
            "The CCM public keys for control component {} are identical from both sources",
            node_id
        )));
    }
}

pub(super) fn fn_verification<D: VerificationDirectoryTrait>(
    dir: &D,
    result: &mut VerificationResult,
) {
    let setup_dir = dir.unwrap_setup();
    let sc_pk = match setup_dir.setup_component_public_keys_payload() {
        Ok(o) => o,
        Err(e) => {
            result.push(create_verification_error!(
                "Cannot extract setup_component_public_keys_payload",
                e
            ));
            return;
        }
    };
    for node in sc_pk
        .setup_component_public_keys
        .combined_control_component_public_keys
    {
        validate_cc_ccm_pk(setup_dir, &node, node.node_id, result)
    }
}

#[cfg(test)]
mod test {
    use super::{super::super::super::result::VerificationResultTrait, *};
    use crate::constants::test::get_verifier_setup_dir as get_verifier_dir;

    #[test]
    fn test_ok() {
        let dir = get_verifier_dir();
        let mut result = VerificationResult::new();
        fn_verification(&dir, &mut result);
        assert!(result.is_ok().unwrap());
    }
}
