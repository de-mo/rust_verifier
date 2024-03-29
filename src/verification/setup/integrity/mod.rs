use super::super::{
    result::{create_verification_failure, VerificationEvent, VerificationResult},
    suite::VerificationList,
    verifications::Verification,
};
use crate::{
    config::Config,
    file_structure::{
        setup_directory::{SetupDirectoryTrait, VCSDirectoryTrait},
        VerificationDirectoryTrait,
    },
    verification::meta_data::VerificationMetaDataList,
};
use anyhow::anyhow;
use log::debug;
use rust_ev_crypto_primitives::VerifyDomainTrait;

pub fn get_verifications<'a>(
    metadata_list: &'a VerificationMetaDataList,
    config: &'static Config,
) -> VerificationList<'a> {
    VerificationList(vec![Verification::new(
        "04.01",
        "VerifySetupIntegrity",
        fn_0401_verify_setup_integrity,
        metadata_list,
        config,
    )
    .unwrap()])
}

fn validate_vcs_dir<V: VCSDirectoryTrait>(dir: &V, result: &mut VerificationResult) {
    match dir.setup_component_tally_data_payload() {
        Ok(d) => {
            for e in d.verifiy_domain() {
                result.push(create_verification_failure!(
                    format!(
                        "Error verifying domain for {}/setup_component_tally_data_payload",
                        dir.get_name()
                    ),
                    e
                ))
            }
        }
        Err(e) => result.push(create_verification_failure!(
            format!(
                "{}/setup_component_tally_data_payload has wrong format",
                dir.get_name()
            ),
            e
        )),
    }
    for (i, f) in dir.control_component_code_shares_payload_iter() {
        match f {
            Ok(d) => {
                for (j, p) in d.iter().enumerate() {
                    for e in p.verifiy_domain() {
                        result.push(create_verification_failure!(
                            format!(
                                "Error verifying domain for {}/control_component_public_keys_payload.{} at entry {}",
                                dir.get_name(),
                                i, j
                            ),
                            e
                        ))
                    }
                }
            }
            Err(e) => result.push(create_verification_failure!(
                format!(
                    "{}/control_component_code_shares_payload.{} has wrong format",
                    dir.get_name(),
                    i
                ),
                e
            )),
        }
    }
    for (i, f) in dir.setup_component_verification_data_payload_iter() {
        match f {
            Ok(d) => {
                for e in d.verifiy_domain() {
                    result.push(create_verification_failure!(
                        format!(
                            "Error verifying domain for {}/setup_component_verification_data_payload.{}",
                            dir.get_name(),
                            i
                        ),
                        e
                    ))
                }
            }
            Err(e) => result.push(create_verification_failure!(
                format!(
                    "{}/setup_component_verification_data_payload.{} has wrong format",
                    dir.get_name(),
                    i
                ),
                e
            )),
        }
    }
}

fn fn_0401_verify_setup_integrity<D: VerificationDirectoryTrait>(
    dir: &D,
    _config: &'static Config,
    result: &mut VerificationResult,
) {
    let setup_dir = dir.unwrap_setup();
    match setup_dir.election_event_context_payload() {
        Ok(d) => {
            for e in d.verifiy_domain() {
                result.push(create_verification_failure!(
                    "Error verifying domain for election_event_context_payload",
                    e
                ))
            }
        }
        Err(e) => result.push(create_verification_failure!(
            "election_event_context_payload has wrong format",
            e
        )),
    }
    match setup_dir.setup_component_public_keys_payload() {
        Ok(d) => {
            for e in d.verifiy_domain() {
                result.push(create_verification_failure!(
                    "Error verifying domain for setup_component_public_keys_payload",
                    e
                ))
            }
        }
        Err(e) => result.push(create_verification_failure!(
            "setup_component_public_keys_payload has wrong format",
            e
        )),
    }
    match setup_dir.election_event_configuration() {
        Ok(d) => {
            for e in d.verifiy_domain() {
                result.push(create_verification_failure!(
                    "Error verifying domain for election_event_configuration",
                    e
                ))
            }
        }
        Err(e) => result.push(create_verification_failure!(
            "election_event_configuration has wrong format",
            e
        )),
    }
    for (i, f) in setup_dir.control_component_public_keys_payload_iter() {
        match f {
            Ok(d) => {
                for e in d.verifiy_domain() {
                    result.push(create_verification_failure!(
                        format!(
                            "Error verifying domain for control_component_public_keys_payload.{}",
                            i
                        ),
                        e
                    ))
                }
            }
            Err(e) => result.push(create_verification_failure!(
                format!(
                    "control_component_public_keys_payload.{} has wrong format",
                    i
                ),
                e
            )),
        }
    }
    for d in setup_dir.vcs_directories().iter() {
        validate_vcs_dir(d, result);
    }
}

#[cfg(test)]
mod test {
    use super::{super::super::result::VerificationResultTrait, *};
    use crate::config::test::{get_test_verifier_setup_dir as get_verifier_dir, CONFIG_TEST};

    #[test]
    fn test_ok() {
        let dir = get_verifier_dir();
        let mut result = VerificationResult::new();
        fn_0401_verify_setup_integrity(&dir, &CONFIG_TEST, &mut result);
        println!("{:?}", result);
        assert!(result.is_ok().unwrap());
    }
}
