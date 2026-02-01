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

use super::super::{
    result::{VerificationEvent, VerificationResult},
    suite::VerificationList,
    verifications::Verification,
};
use crate::{
    config::VerifierConfig,
    file_structure::{
        VerificationDirectoryTrait,
        tally_directory::{BBDirectoryTrait, TallyDirectoryTrait},
    },
    verification::{VerificationError, VerificationErrorImpl, meta_data::VerificationMetaDataList},
};
use rust_ev_system_library::rust_ev_crypto_primitives::prelude::{EmptyContext, VerifyDomainTrait};

pub fn get_verifications<'a>(
    metadata_list: &'a VerificationMetaDataList,
    config: &'static VerifierConfig,
) -> Result<VerificationList<'a>, VerificationError> {
    Ok(VerificationList(vec![
        Verification::new(
            "09.01",
            "VerifyTallyIntegrity",
            fn_0901_verify_tally_integrity,
            metadata_list,
            config,
        )
        .map_err(|e| VerificationErrorImpl::GetVerification {
            name: "VerifyTallyIntegrity",
            source: Box::new(e),
        })?,
    ]))
}

fn validate_bb_dir<B: BBDirectoryTrait>(dir: &B, result: &mut VerificationResult) {
    match dir.tally_component_votes_payload() {
        Ok(d) => {
            for e in d.verifiy_domain(&EmptyContext) {
                result.push(
                    VerificationEvent::new_failure(&e)
                        .add_context("Error verifying domain for tally_component_votes_payload"),
                )
            }
        }
        Err(e) => result.push(
            VerificationEvent::new_failure(&e)
                .add_context("tally_component_votes_payload has wrong format"),
        ),
    }
    match dir.tally_component_shuffle_payload() {
        Ok(d) => {
            for e in d.verifiy_domain(&EmptyContext) {
                result.push(
                    VerificationEvent::new_failure(&e)
                        .add_context("Error verifying domain for tally_component_shuffle_payload"),
                )
            }
        }
        Err(e) => result.push(
            VerificationEvent::new_failure(&e)
                .add_context("tally_component_shuffle_payload has wrong format"),
        ),
    }

    for (i, f) in dir.control_component_ballot_box_payload_iter() {
        match f {
            Ok(d) => {
                for e in d.verifiy_domain(&EmptyContext) {
                    result.push(VerificationEvent::new_failure(&e)
                    .add_context(
                        format!(
                             "Error verifying domain for {}/control_component_ballot_box_payload_iter.{}",
                    dir.name(),
                    i
                        )

                    ))
                }
            }
            Err(e) => result.push(VerificationEvent::new_failure(&e).add_context(format!(
                "{}/control_component_ballot_box_payload_iter.{} has wrong format",
                dir.name(),
                i
            ))),
        }
    }

    for (i, f) in dir.control_component_shuffle_payload_iter() {
        match f {
            Ok(d) => {
                for e in d.verifiy_domain(&EmptyContext) {
                    result.push(VerificationEvent::new_failure(&e).add_context(format!(
                        "Error verifying domain for {}/control_component_shuffle_payload_iter.{}",
                        dir.name(),
                        i
                    )))
                }
            }
            Err(e) => result.push(VerificationEvent::new_failure(&e).add_context(format!(
                "{}/control_component_shuffle_payload_iter.{} has wrong format",
                dir.name(),
                i
            ))),
        }
    }
}

fn fn_0901_verify_tally_integrity<D: VerificationDirectoryTrait>(
    dir: &D,
    _config: &'static VerifierConfig,
    result: &mut VerificationResult,
) {
    let setup_dir = dir.unwrap_tally();
    for d in setup_dir.bb_directories().iter() {
        validate_bb_dir(d, result);
    }
}

#[cfg(test)]
mod test {
    use super::{super::super::result::VerificationResult, *};
    use crate::config::test::{CONFIG_TEST, get_test_verifier_tally_dir as get_verifier_dir};

    #[test]
    fn test_ok() {
        let dir = get_verifier_dir();
        let mut result = VerificationResult::new();
        fn_0901_verify_tally_integrity(&dir, &CONFIG_TEST, &mut result);
        assert!(result.is_ok());
    }
}
