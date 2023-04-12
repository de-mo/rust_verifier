use std::iter::zip;

use super::super::super::{
    error::{
        create_verification_error, create_verification_failure, VerificationErrorType,
        VerificationFailureType,
    },
    verification::VerificationResult,
};
use crate::{
    crypto_primitives::zero_knowledge_proof::verify_schnorr,
    data_structures::common_types::Proof,
    error::{create_verifier_error, VerifierError},
    file_structure::VerificationDirectory,
};

pub(super) fn fn_verification(dir: &VerificationDirectory, result: &mut VerificationResult) {
    let setup_dir = dir.unwrap_setup();
    let eg = match setup_dir.encryption_parameters_payload() {
        Ok(eg) => eg,
        Err(e) => {
            result.push_error(create_verification_error!(
                "encryption_parameters_payload cannot be read",
                e
            ));
            return;
        }
    };
    let ee_context = match setup_dir.election_event_context_payload() {
        Ok(eg) => eg,
        Err(e) => {
            result.push_error(create_verification_error!(
                "election_event_context_payload cannot be read",
                e
            ));
            return;
        }
    };
    let setup_ppk = match setup_dir.setup_component_public_keys_payload() {
        Ok(eg) => eg,
        Err(e) => {
            result.push_error(create_verification_error!(
                "setup_component_public_keys_payload cannot be read",
                e
            ));
            return;
        }
    };

    // CC proofs
    for combined_cc_pk in setup_ppk
        .setup_component_public_keys
        .combined_control_component_public_keys
    {
        let j = combined_cc_pk.node_id;

        // CCRj Schnorr Proofs
        let i_aux_ccr_j = vec![
            ee_context.election_event_context.election_event_id.clone(),
            "GenKeysCCR".to_string(),
            j.to_string(),
        ];
        for (i, (pk_ccr_j_i, pi_pk_ccr_j_i)) in zip(
            combined_cc_pk.ccrj_choice_return_codes_encryption_public_key,
            combined_cc_pk.ccrj_schnorr_proofs,
        )
        .enumerate()
        {
            if !verify_schnorr(
                &eg.encryption_group,
                &Proof::from(&pi_pk_ccr_j_i),
                &pk_ccr_j_i,
                &i_aux_ccr_j,
            ) {
                result.push_failure(create_verification_failure!(format!(
                    "VerifSchnorrCCRji: Verifiy CCR_j Schnorrproof not ok at pos {} for cc {}",
                    i, j
                )))
            }
        }

        // CCMj Schnorr Proofs
        let i_aux_ccm_j = vec![
            ee_context.election_event_context.election_event_id.clone(),
            "SetupTallyCCM".to_string(),
            j.to_string(),
        ];
        for (i, (el_pk_j_i, pi_el_pk_j_i)) in zip(
            combined_cc_pk.ccmj_election_public_key,
            combined_cc_pk.ccmj_schnorr_proofs,
        )
        .enumerate()
        {
            if !verify_schnorr(
                &eg.encryption_group,
                &Proof::from(&pi_el_pk_j_i),
                &el_pk_j_i,
                &i_aux_ccm_j,
            ) {
                result.push_failure(create_verification_failure!(format!(
                    "VerifSchnorrCCMji: Verifiy CCM_j Schnorrproof not ok at pos {} for cc {}",
                    i, j
                )))
            }
        }
    }

    // EB proofs
    let i_aux_eb = vec![
        ee_context.election_event_context.election_event_id.clone(),
        "SetupTallyEB".to_string(),
    ];
    for (i, (eb_pk_i, pi_eb_i)) in zip(
        setup_ppk
            .setup_component_public_keys
            .electoral_board_public_key,
        setup_ppk
            .setup_component_public_keys
            .electoral_board_schnorr_proofs,
    )
    .enumerate()
    {
        if !verify_schnorr(
            &eg.encryption_group,
            &Proof::from(&pi_eb_i),
            &eb_pk_i,
            &i_aux_eb,
        ) {
            result.push_failure(create_verification_failure!(format!(
                "VerifSchnorrCCRji: Verifiy Electoral board Schnorr proofs not ok at pos {}",
                i
            )))
        }
    }
}

#[cfg(test)]
mod test {

    use crate::verification::VerificationPeriod;

    use super::super::super::super::verification::VerificationResultTrait;
    use super::*;
    use std::path::Path;

    fn get_verifier_dir() -> VerificationDirectory {
        let location = Path::new(".").join("datasets").join("dataset-setup1");
        VerificationDirectory::new(VerificationPeriod::Setup, &location)
    }

    #[test]
    #[ignore]
    fn test_ok() {
        let dir = get_verifier_dir();
        let mut result = VerificationResult::new();
        fn_verification(&dir, &mut result);
        assert!(result.is_ok().unwrap());
    }
}
