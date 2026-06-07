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

mod verify_online_control_components_ballot_box;

use crate::{
    VerifierConfig,
    data_structures::{
        ElectionEventContextPayload,
        context::setup_component_public_keys_payload::SetupComponentPublicKeys,
    },
    file_structure::{
        ContextDirectoryTrait, TallyDirectoryTrait, VerificationDirectoryTrait,
        context_directory::ContextVCSDirectoryTrait, tally_directory::BBDirectoryTrait,
    },
    verification::{VerificationEvent, VerificationResult},
};
use rayon::prelude::*;
use rust_ev_system_library::rust_ev_crypto_primitives::prelude::mix_net::ShuffleArgument as CryptoShuffleArgument;
use verify_online_control_components_ballot_box::{
    ContextAlgorithm41, InputsAlgorithm41, verify_online_control_components_ballot_box,
};

pub(super) fn fn_verification<D: VerificationDirectoryTrait>(
    dir: &D,
    _config: &'static VerifierConfig,
    result: &mut VerificationResult,
) {
    let context_dir = dir.context();
    let tally_dir = dir.unwrap_tally();

    let ee_context_payload = match context_dir.election_event_context_payload() {
        Ok(p) => p,
        Err(e) => {
            result.push(
                VerificationEvent::new_error_from_error(&e)
                    .add_context("election_event_context_payload cannot be read"),
            );
            return;
        }
    };

    let setup_pk_payload = match context_dir.setup_component_public_keys_payload() {
        Ok(p) => p,
        Err(e) => {
            result.push(
                VerificationEvent::new_error_from_error(&e)
                    .add_context("setup_component_public_keys_payload cannot be read"),
            );
            return;
        }
    };

    result.append(&mut tally_dir
        .bb_directories()
        .par_iter()
        .map(|bb_dir| {
            (
                bb_dir.name(),
                match ee_context_payload
                    .election_event_context
                    .find_verification_card_set_context_with_bb_id(&bb_dir.name())
                {
                    Some(vcs) => {
                        let vcs_id = vcs.verification_card_set_id.as_str();
                        match context_dir
                            .vcs_directories()
                            .iter()
                            .find(|d| d.name() == vcs_id)
                        {
                            Some(vcs_dir) => verify_for_ballotbox(
                                &ee_context_payload,
                                &setup_pk_payload.setup_component_public_keys,
                                bb_dir,
                                vcs_dir,
                            ),
                            None => VerificationResult::from(&VerificationEvent::new_error(&format!(
                                "The vcs_directory not found for the verification card set {} associated to the ballot box {}",vcs_id,
                                bb_dir.name()
                            ))),
                        }
                    }
                    None => {
                        VerificationResult::from(&VerificationEvent::new_error(&format!(
                            "No verification card set found for ballot box {}",
                            bb_dir.name()
                        )))
                    }
                },
            )
        })
        .collect::<Vec<_>>()
        .iter()
        .fold(VerificationResult::new(), |acc, (name, result)| {
            let mut res = acc.clone();
            res.append_with_context(result, format!("Ballot box {name}"));
            res
        }));
}

fn verify_for_ballotbox<B: BBDirectoryTrait, S: ContextVCSDirectoryTrait>(
    ee_context_payload: &ElectionEventContextPayload,
    setup_pk: &SetupComponentPublicKeys,
    bb_dir: &B,
    vcs_dir: &S,
) -> VerificationResult {
    let bb_id = bb_dir.name();
    let vcs_context = match ee_context_payload
        .election_event_context
        .find_verification_card_set_context_with_bb_id(&bb_id)
    {
        Some(vcs) => vcs,
        None => {
            return VerificationResult::from(&VerificationEvent::new_error(&format!(
                "No verification card set found for ballot box {bb_id}"
            )));
        }
    };

    let mut ccm_el_pk_with_node = setup_pk
        .combined_control_component_public_keys
        .iter()
        .map(|cc| (cc.node_id, cc.ccmj_election_public_key.as_slice()))
        .collect::<Vec<_>>();
    ccm_el_pk_with_node.sort_by_key(|(i, _)| *i);
    let ccm_el_pk = ccm_el_pk_with_node
        .iter()
        .map(|(_, el_pk)| *el_pk)
        .collect::<Vec<_>>();

    let cc_bb_payload_1 = match bb_dir
        .control_component_ballot_box_payload_iter()
        .find(|(i, _)| *i == 1)
    {
        Some((_, p)) => match p {
            Ok(p) => p,
            Err(e) => {
                return VerificationResult::from(
                    &VerificationEvent::new_error_from_error(&e).add_context(format!(
                        "{bb_id}/control_component_ballot_box_payload_iter_1 cannot be read"
                    )),
                );
            }
        },
        None => {
            return VerificationResult::from(&VerificationEvent::new_error(&format!(
                "{bb_id}/control_component_ballot_box_payload_iter_1 not found"
            )));
        }
    };

    let vc_1 = cc_bb_payload_1
        .confirmed_encrypted_votes
        .iter()
        .map(|ev| ev.context_ids.verification_card_id.as_str())
        .collect::<Vec<_>>();

    let upper_e1_1 = cc_bb_payload_1
        .confirmed_encrypted_votes
        .iter()
        .map(|ev| &ev.encrypted_vote)
        .collect::<Vec<_>>();

    let upper_e1_1_tilde = cc_bb_payload_1
        .confirmed_encrypted_votes
        .iter()
        .map(|ev| {
            (
                &ev.exponentiated_encrypted_vote.gamma,
                &ev.exponentiated_encrypted_vote.phis[0],
            )
        })
        .collect::<Vec<_>>();

    let upper_e2_1 = cc_bb_payload_1
        .confirmed_encrypted_votes
        .iter()
        .map(|ev| &ev.encrypted_partial_choice_return_codes)
        .collect::<Vec<_>>();

    let pi_exp_1 = cc_bb_payload_1
        .confirmed_encrypted_votes
        .iter()
        .map(|ev| &ev.exponentiation_proof)
        .collect::<Vec<_>>();

    let pi_eq_enc_1 = cc_bb_payload_1
        .confirmed_encrypted_votes
        .iter()
        .map(|ev| &ev.plaintext_equality_proof)
        .collect::<Vec<_>>();

    let mut control_component_shuffle_payloads = match bb_dir
        .control_component_shuffle_payload_iter()
        .map(|(j, payload)| match payload {
            Ok(p) => Ok((p.node_id, p)),
            Err(e) => Err(
                VerificationEvent::new_error_from_error(&e).add_context(format!(
                    "control_component_shuffle_payload_{j} cannot be read"
                )),
            ),
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(data) => data,
        Err(e) => return VerificationResult::from(&e),
    };
    control_component_shuffle_payloads.sort_by_key(|(i, _)| *i);

    let cs_mix = control_component_shuffle_payloads
        .iter()
        .map(|(_, d)| d.verifiable_shuffle.shuffled_ciphertexts.as_slice())
        .collect::<Vec<_>>();

    let pi_mix = match control_component_shuffle_payloads
        .iter()
        .map(|(_, d)| CryptoShuffleArgument::try_from(&d.verifiable_shuffle.shuffle_argument))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(v) => v,
        Err(e) => {
            return VerificationResult::from(
                &VerificationEvent::new_error_from_error(&e)
                    .add_context("Error creating Shuffle Argument"),
            );
        }
    };
    let cs_dec = control_component_shuffle_payloads
        .iter()
        .map(|(_, d)| d.verifiable_decryptions.ciphertexts.as_slice())
        .collect::<Vec<_>>();
    let pi_dec = control_component_shuffle_payloads
        .iter()
        .map(|(_, d)| d.verifiable_decryptions.decryption_proofs.as_slice())
        .collect::<Vec<_>>();

    let setup_tally_data_payload = match vcs_dir.setup_component_tally_data_payload() {
        Ok(p) => p,
        Err(e) => {
            return VerificationResult::from(
                &VerificationEvent::new_error_from_error(&e)
                    .add_context("setup_component_tally_data_payload cannot be read"),
            );
        }
    };

    let vcs = setup_tally_data_payload
        .verification_card_ids
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>();
    let upper_k = setup_tally_data_payload
        .verification_card_public_keys
        .iter()
        .map(|v| &v[0])
        .collect::<Vec<_>>();

    verify_online_control_components_ballot_box(
        &ContextAlgorithm41 {
            eg: &ee_context_payload.encryption_group,
            ee_id: &ee_context_payload.election_event_context.election_event_id,
            vcs_id: &vcs_context.verification_card_set_id,
            bb_id: &bb_id,
            upper_n_upper_e: vcs_context.number_of_eligible_voters,
            p_table: &vcs_context.primes_mapping_table.p_table,
            el_pk: &setup_pk.election_public_key,
            ccm_el_pk: &ccm_el_pk,
            eb_pk: &setup_pk.electoral_board_public_key,
            pk_ccr: &setup_pk.choice_return_codes_encryption_public_key,
        },
        &InputsAlgorithm41 {
            vc_1: vc_1.as_slice(),
            upper_e1_1: &upper_e1_1,
            upper_e1_1_tilde: &upper_e1_1_tilde,
            upper_e2_1: &upper_e2_1,
            pi_exp_1: &pi_exp_1,
            pi_eq_enc_1: &pi_eq_enc_1,
            cs_mix: &cs_mix,
            pi_mix: pi_mix.as_slice(),
            cs_dec: &cs_dec,
            pi_dec: &pi_dec,
            vcs: &vcs,
            upper_k: &upper_k,
        },
    )
    .clone_add_context(format!(
        "VerifyOnlineControlComponentsBallotBox for bb_id {}",
        bb_dir.name()
    ))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::test::{
        CONFIG_TEST, get_test_verifier_mock_tally_dir,
        get_test_verifier_tally_dir as get_verifier_dir,
    };

    #[test]
    fn test_ok() {
        let dir = get_verifier_dir();
        let mut result = VerificationResult::new();
        fn_verification(&dir, &CONFIG_TEST, &mut result);
        if !result.is_ok() {
            for r in result.errors_to_string() {
                println!("{r:?}")
            }
            for r in result.failures_to_string() {
                println!("{r:?}")
            }
        }
        assert!(result.is_ok());
    }

    #[test]
    fn change_vc1() {
        let dir = get_verifier_dir();
        let nb = dir.unwrap_tally().bb_directories().len();
        for i in 0..nb {
            let bb = &dir.unwrap_tally().bb_directories()[i];
            if bb
                .control_component_ballot_box_payload_iter()
                .next()
                .unwrap()
                .1
                .unwrap()
                .confirmed_encrypted_votes
                .is_empty()
            {
                continue;
            }
            let mut result = VerificationResult::new();
            let mut mock_dir = get_test_verifier_mock_tally_dir();
            mock_dir.unwrap_tally_mut().bb_directories_mut()[i]
                .mock_control_component_ballot_box_payload(1, |d| {
                    d.confirmed_encrypted_votes[0]
                        .context_ids
                        .verification_card_id = "corrupted_vc_id".to_string();
                });
            fn_verification(&mock_dir, &CONFIG_TEST, &mut result);
            assert!(!result.is_ok(), "Failed for vote 0 for bb {}", bb.name());
        }
    }

    #[test]
    fn change_c_mix() {
        let dir = get_verifier_dir();
        let nb = dir.unwrap_tally().bb_directories().len();
        for i in 0..nb {
            let bb = &dir.unwrap_tally().bb_directories()[i];
            let mut result = VerificationResult::new();
            let mut mock_dir = get_test_verifier_mock_tally_dir();
            mock_dir.unwrap_tally_mut().bb_directories_mut()[i]
                .mock_control_component_shuffle_payload(2, |d| {
                    d.verifiable_shuffle.shuffled_ciphertexts[0].gamma = 1.into();
                });
            fn_verification(&mock_dir, &CONFIG_TEST, &mut result);
            assert!(!result.is_ok(), "Failed for vote 0 for bb {}", bb.name());
        }
    }
}
