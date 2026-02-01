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
    DataStructureError, DataStructureErrorImpl, VerifierDataDecode,
    common_types::{EncryptionParametersDef, Signature},
    deserialize_string_to_datetime, implement_trait_verifier_data_json_decode,
};
use crate::{
    config::VerifierConfig,
    data_structures::{VerifierDataType, verifiy_domain_length_unique_id},
    direct_trust::VerifiySignatureTrait,
};
use crate::{
    data_structures::VerifierDataToTypeTrait,
    direct_trust::{CertificateAuthority, VerifiyJSONSignatureTrait},
};
use chrono::NaiveDate;
use chrono::NaiveDateTime;
use regex::Regex;
use rust_ev_system_library::rust_ev_crypto_primitives::prelude::{
    ByteArray, DomainVerifications, HashableMessage, VerifyDomainTrait,
    elgamal::EncryptionParameters,
};
use rust_ev_system_library::{
    preliminaries::{
        GetHashElectionEventContextContext, PTable, PTableElement,
        VerificationCardSetContext as VerificationCardSetContextInSystemLibrary,
    },
    rust_ev_crypto_primitives::prelude::EmptyContext,
};
use serde::Deserialize;
use serde::de::{Deserializer, Error as SerdeError};
use std::sync::Arc;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ElectionEventContextPayload {
    #[serde(with = "EncryptionParametersDef")]
    pub encryption_group: EncryptionParameters,
    pub seed: String,
    pub small_primes: Vec<usize>,
    pub election_event_context: ElectionEventContext,
    pub tenant_id: String,
    pub signature: Option<Signature>,
}

impl VerifierDataToTypeTrait for ElectionEventContextPayload {
    fn data_type() -> crate::data_structures::VerifierDataType {
        VerifierDataType::Context(super::VerifierContextDataType::ElectionEventContextPayload)
    }
}

implement_trait_verifier_data_json_decode!(ElectionEventContextPayload);

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ElectionEventContext {
    pub election_event_id: String,
    pub election_event_alias: String,
    pub election_event_description: String,
    pub verification_card_set_contexts: Vec<VerificationCardSetContext>,
    #[serde(deserialize_with = "deserialize_string_to_datetime")]
    pub start_time: NaiveDateTime,
    #[serde(deserialize_with = "deserialize_string_to_datetime")]
    pub finish_time: NaiveDateTime,
    pub maximum_number_of_voting_options: usize,
    pub maximum_number_of_selections: usize,
    pub maximum_number_of_write_ins_plus_one: usize,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[warn(dead_code)]
pub struct VerificationCardSetContext {
    pub verification_card_set_id: String,
    pub verification_card_set_alias: String,
    pub verification_card_set_description: String,
    pub ballot_box_id: String,
    #[serde(deserialize_with = "deserialize_string_to_datetime")]
    pub ballot_box_start_time: NaiveDateTime,
    #[serde(deserialize_with = "deserialize_string_to_datetime")]
    pub ballot_box_finish_time: NaiveDateTime,
    pub test_ballot_box: bool,
    pub number_of_eligible_voters: usize,
    pub grace_period: usize,
    pub primes_mapping_table: PrimesMappingTable,
    pub domains_of_influence: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PrimesMappingTable {
    #[serde(deserialize_with = "deserialize_p_table")]
    pub p_table: Vec<PTableElement>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
#[warn(dead_code)]
pub struct PTableElementDef {
    pub actual_voting_option: String,
    pub encoded_voting_option: usize,
    pub semantic_information: String,
    pub correctness_information: String,
}

impl From<PTableElementDef> for PTableElement {
    fn from(def: PTableElementDef) -> Self {
        Self {
            actual_voting_option: def.actual_voting_option,
            encoded_voting_option: def.encoded_voting_option,
            semantic_information: def.semantic_information,
            correctness_information: def.correctness_information,
        }
    }
}

fn deserialize_p_table<'de, D>(deserializer: D) -> Result<Vec<PTableElement>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Visitor;

    impl<'de> ::serde::de::Visitor<'de> for Visitor {
        type Value = Vec<PTableElement>;

        fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            write!(f, "a sequence of string")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut vec = <Self::Value>::new();

            while let Some(v) = (seq.next_element())? {
                let r_b = PTableElement::from(
                    serde_json::from_value::<PTableElementDef>(v).map_err(A::Error::custom)?,
                );
                vec.push(r_b);
            }
            Ok(vec)
        }
    }
    deserializer.deserialize_seq(Visitor)
}

impl VerificationCardSetContext {
    pub fn number_of_voting_options(&self) -> usize {
        self.primes_mapping_table.p_table.len()
    }
}

impl ElectionEventContext {
    /// Find the verification card set context with the id
    ///
    /// Return None if not found
    pub fn find_verification_card_set_context<'a>(
        &'a self,
        vcs_id: &str,
    ) -> Option<&'a VerificationCardSetContext> {
        self.verification_card_set_contexts
            .iter()
            .find(|c| c.verification_card_set_id == vcs_id)
    }

    /// Find the verification card set context with the ballot box id
    ///
    /// Return None if not found
    pub fn find_verification_card_set_context_with_bb_id<'a>(
        &'a self,
        bb_id: &str,
    ) -> Option<&'a VerificationCardSetContext> {
        self.verification_card_set_contexts
            .iter()
            .find(|c| c.ballot_box_id == bb_id)
    }

    /// Get the list of all verification card set ids
    pub fn vcs_ids(&self) -> Vec<&str> {
        self.verification_card_set_contexts
            .iter()
            .map(|c| c.verification_card_set_id.as_str())
            .collect()
    }

    /// Get the list of all ballot box ids
    pub fn bb_ids(&self) -> Vec<&str> {
        self.verification_card_set_contexts
            .iter()
            .map(|c| c.ballot_box_id.as_str())
            .collect()
    }

    /// Find the id of the ballot box using the id of the verification card set
    ///
    /// Return None if not found
    pub fn find_ballot_box_id<'a>(&'a self, vcs_id: &str) -> Option<&'a str> {
        self.find_verification_card_set_context(vcs_id)
            .map(|c| c.ballot_box_id.as_str())
    }
}

/// Validate seed according to the specifications of Swiss Post
///
/// seed = <Canton>_<Date>_<TT|TP|PP>_nn
fn validate_seed(seed: &str) -> Vec<String> {
    let mut res = vec![];
    if seed.len() != 16 {
        return vec![format!(
            "The seed {} must be of size 16, actual ist {}",
            seed,
            seed.len(),
        )];
    }
    let re = Regex::new(r"[A-Z]{2}_\d{8}_(TT|TP|PP)\d{2}").unwrap();
    if !re.is_match(seed) {
        return vec![format!(
            "The seed {} does not match the format  CT_YYYYMMDD_XYnm",
            seed,
        )];
    }
    let date = seed.get(3..11).unwrap();
    if let Err(e) = NaiveDate::parse_from_str(date, "%Y%m%d") {
        res.push(format!(
            "the date {seed} of the seed {date} is not valid: {e}"
        ))
    }
    let event_type = seed.get(12..14).unwrap();
    if event_type != "TT" && event_type != "TP" && event_type != "PP" {
        res.push(format!(
            "the event type {seed} of the seed {event_type} is not valid. Must be TT, TP or PP"
        ))
    }
    res
}

/// Validate small primes are correct
///
/// - Size is equal to the max. supported voting options
/// - Is sorted correctly (for 05.02)
/// - The first is greater or equal than 5 (for 05.02)
fn validate_small_primes(small_primes: &[usize]) -> Vec<String> {
    let mut res = vec![];
    // Len is correct
    if !small_primes.len() == VerifierConfig::maximum_number_of_supported_voting_options_n_sup() {
        res.push(format!(
            "The list of small primes {} is not equal to the maximal number of voting options {}",
            small_primes.len(),
            VerifierConfig::maximum_number_of_supported_voting_options_n_sup()
        ));
    }
    // is sorted
    if !small_primes.windows(2).all(|p| p[0] < p[1]) {
        res.push("Small primes list is not in ascending order".to_string());
    }
    // for 5.02
    if small_primes[0] < 5 {
        res.push("The small primes contain 2 or 3, what is not allowed".to_string());
    };
    res
}

/// Validate n_total
///
/// - Number of distinct voting options across all verification card sets (n_total) is greater than 0 (05.03)
/// - Number of distinct voting options across all verification card sets (n_total) is less or equal than n_sup (05.03)
fn validate_n_total(context: &ElectionEventContext) -> Vec<String> {
    let mut encoded_options = context
        .verification_card_set_contexts
        .iter()
        .flat_map(|vcs| {
            vcs.primes_mapping_table
                .p_table
                .iter()
                .map(|el| el.encoded_voting_option)
        })
        .collect::<Vec<_>>();
    encoded_options.sort();
    encoded_options.dedup();
    let n_total = encoded_options.len();
    match     n_total {
        0 => vec!["The number of distinct voting options across all verification card sets (n_total) must be greater than 0".to_string()],
        n if n > VerifierConfig::maximum_number_of_supported_voting_options_n_sup() => vec![format!(
            "The number of distinct voting options across all verification card sets (n_total) expected {} must be smaller or equal the the max. supported voting options {}",
            n,
            VerifierConfig::maximum_number_of_supported_voting_options_n_sup()
        )],
        _ => vec![],
    }
}

/// Validate if the number of voting option in the verification card set context is correct
///
/// - The number is greater than 0 and less than the maximum supported voting options (for 05.03)
fn validate_voting_options_number(p_table: &PrimesMappingTable) -> Vec<String> {
    let mut res = vec![];
    let nb_voting_options = p_table.p_table.len();
    // number of voting options must be greater that 0
    if nb_voting_options == 0 {
        res.push("The  number of voting options must be greater than 0".to_string());
    }
    // number of voting options must be smaller or equal than max. supported voting options
    if nb_voting_options > VerifierConfig::maximum_number_of_supported_voting_options_n_sup() {
        res.push(format!(
            "The  number of voting options expected {} must be smaller or equal the the max. supported voting options {}",
            nb_voting_options,
            VerifierConfig::maximum_number_of_supported_voting_options_n_sup()
        ));
    }
    res
}

/// Validate the maximum number of selections to the number of write-ins plus one
///
/// Requirement 05.04
fn validate_max_selections_vs_write_ins(context: &ElectionEventContext) -> Vec<String> {
    let mut res = vec![];
    if context.maximum_number_of_selections < context.maximum_number_of_write_ins_plus_one - 1 {
        res.push(format!(
            "The maximum number of selections {} must be greater or equal to the maximum number of write-ins plus one {} minus one",
            context.maximum_number_of_selections,
            context.maximum_number_of_write_ins_plus_one
        ));
    }
    res
}

impl VerifyDomainTrait<EmptyContext, String> for ElectionEventContextPayload {
    fn new_domain_verifications() -> DomainVerifications<EmptyContext, Self, String> {
        let mut res = DomainVerifications::default();
        // Add verification for encryption group
        res.add_verification(|v: &Self, c| {
            v.encryption_group
                .verifiy_domain(c)
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        });

        res.add_verification(|v: &Self, _c| validate_seed(&v.seed));
        res.add_verification(|v: &Self, _c| validate_small_primes(&v.small_primes));
        res.add_verification(|v: &Self, _c| validate_n_total(&v.election_event_context));
        res.add_verification(|v: &Self, _c| {
            validate_max_selections_vs_write_ins(&v.election_event_context)
        });
        res.add_verification(|v, _c| {
            // 05.01
            verifiy_domain_length_unique_id(
                &v.election_event_context.election_event_id,
                "election event id",
            )
        });
        // Add verification for each verification card set context
        res.add_verification_with_vec_of_vec_errors(|v, c| {
            v.election_event_context
                .verification_card_set_contexts
                .iter()
                .map(|vcs| {
                    vcs.verifiy_domain(c)
                        .iter()
                        .map(|e| format!("{} (vcs_id{})", e, vcs.verification_card_set_id))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        });
        res
    }
}

impl VerifyDomainTrait<EmptyContext, String> for VerificationCardSetContext {
    fn new_domain_verifications() -> DomainVerifications<EmptyContext, Self, String> {
        let mut res = DomainVerifications::default();
        res.add_verification(|v: &Self, _c| {
            validate_voting_options_number(&v.primes_mapping_table)
        });
        res.add_verification(|v, _c| {
            // 05.01
            verifiy_domain_length_unique_id(&v.ballot_box_id, "ballot_box_id")
        });
        res.add_verification(|v, _c| {
            // 05.01
            verifiy_domain_length_unique_id(&v.verification_card_set_id, "verification_card_set_id")
        });
        res
    }
}

impl<'a> From<&'a ElectionEventContextPayload> for HashableMessage<'a> {
    fn from(value: &'a ElectionEventContextPayload) -> Self {
        let ee_context_hash = GetHashElectionEventContextContext::from(value);
        Self::from(vec![
            Self::from(&value.encryption_group),
            Self::from(&value.seed),
            Self::from(
                value
                    .small_primes
                    .iter()
                    .map(HashableMessage::from)
                    .collect::<Vec<_>>(),
            ),
            Self::from(&ee_context_hash),
            Self::from(&value.tenant_id),
        ])
    }
}

impl<'a> VerifiyJSONSignatureTrait<'a> for ElectionEventContextPayload {
    fn get_hashable(&'a self) -> Result<HashableMessage<'a>, DataStructureError> {
        Ok(HashableMessage::from(self))
    }

    fn get_context_data(&'a self) -> Vec<HashableMessage<'a>> {
        vec![
            HashableMessage::from("election event context"),
            HashableMessage::from(&self.election_event_context.election_event_id),
        ]
    }

    fn get_certificate_authority(&self) -> Option<CertificateAuthority> {
        Some(CertificateAuthority::SdmConfig)
    }

    fn get_signature(&self) -> Option<ByteArray> {
        self.signature.as_ref().map(|s| s.get_signature())
    }
}

impl<'a> VerifiySignatureTrait<'a> for ElectionEventContextPayload {
    fn verifiy_signature(
        &'a self,
        keystore: &crate::direct_trust::Keystore,
    ) -> Result<bool, crate::direct_trust::VerifySignatureError> {
        self.verifiy_json_signature(keystore)
    }
}

impl PrimesMappingTable {
    pub fn to_ptable(&self) -> &PTable {
        &self.p_table
    }
}

impl<'a> From<&'a ElectionEventContextPayload> for GetHashElectionEventContextContext<'a> {
    fn from(value: &'a ElectionEventContextPayload) -> Self {
        Self {
            encryption_parameters: &value.encryption_group,
            ee: &value.election_event_context.election_event_id,
            ee_alias: &value.election_event_context.election_event_alias,
            ee_descr: &value.election_event_context.election_event_description,
            vcs_contexts: value
                .election_event_context
                .verification_card_set_contexts
                .iter()
                .map(VerificationCardSetContextInSystemLibrary::from)
                .collect::<Vec<_>>(),
            t_s_ee: &value.election_event_context.start_time,
            t_f_ee: &value.election_event_context.finish_time,
            n_max: value
                .election_event_context
                .maximum_number_of_voting_options,
            psi_max: value.election_event_context.maximum_number_of_selections,
            delta_max: value
                .election_event_context
                .maximum_number_of_write_ins_plus_one,
        }
    }
}

impl<'a> From<&'a VerificationCardSetContext> for VerificationCardSetContextInSystemLibrary<'a> {
    fn from(value: &'a VerificationCardSetContext) -> Self {
        Self {
            vcs: &value.verification_card_set_id,
            vcs_alias: &value.verification_card_set_alias,
            vcs_desc: &value.verification_card_set_description,
            bb: &value.ballot_box_id,
            t_s_bb: &value.ballot_box_start_time,
            t_f_bb: &value.ballot_box_finish_time,
            test_ballot_box: value.test_ballot_box,
            upper_n_upper_e: value.number_of_eligible_voters,
            grace_period: value.grace_period,
            p_table: &value.primes_mapping_table.p_table,
            dois: &value.domains_of_influence,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::super::test::{
            file_to_test_cases, json_to_hashable_message, json_to_testdata, test_data_structure,
            test_data_structure_read_data_set, test_data_structure_verify_domain,
            test_data_structure_verify_signature, test_hash_json,
        },
        *,
    };
    use crate::config::test::{
        get_keystore, test_data_signature_hash_path, test_datasets_context_path,
    };
    use rust_ev_system_library::rust_ev_crypto_primitives::prelude::{
        EncodeTrait, RecursiveHashTrait,
    };
    use std::fs;

    test_data_structure!(
        ElectionEventContextPayload,
        "electionEventContextPayload.json",
        test_datasets_context_path
    );

    test_hash_json!(
        ElectionEventContextPayload,
        "verify-signature-election-event-context.json"
    );

    #[test]
    fn test_validate_seed() {
        assert!(validate_seed("SG_20230101_TT01").is_empty());
        assert!(!validate_seed("SG_20230101_TT0").is_empty());
        assert!(!validate_seed("Sg_20230101_TT01").is_empty());
        assert!(!validate_seed("SG_202301a1_TT01").is_empty());
        assert!(!validate_seed("SG_20230101_tt01").is_empty());
        assert!(!validate_seed("SG_20230101_TT0a").is_empty());
        assert!(!validate_seed("SG_20231301_TT01").is_empty());
        assert!(!validate_seed("SG_20231201_AA01").is_empty());
    }

    #[test]
    fn error_election_event_id() {
        let mut ee = get_data_res().unwrap();
        ee.election_event_context.election_event_id = "1234345".to_string();
        assert!(!ee.verifiy_domain(&EmptyContext).is_empty());
    }
}

#[cfg(test)]
mod test_domain {
    use super::*;
    use crate::{
        config::test::{get_test_verifier_mock_setup_dir, get_test_verifier_setup_dir},
        file_structure::{ContextDirectoryTrait, VerificationDirectoryTrait},
    };

    #[test]
    fn ok() {
        let dir = get_test_verifier_setup_dir();
        let res = dir
            .context()
            .election_event_context_payload()
            .unwrap()
            .verifiy_domain(&EmptyContext);
        assert!(res.is_empty(), "{:?}", res);
    }

    #[test]
    fn eeid() {
        let mut mock_dir = get_test_verifier_mock_setup_dir();
        mock_dir
            .context_mut()
            .mock_election_event_context_payload(|d| {
                d.election_event_context.election_event_id = "mocked_id".to_string()
            });
        let res = mock_dir
            .context()
            .election_event_context_payload()
            .unwrap()
            .verifiy_domain(&EmptyContext);
        assert!(!res.is_empty());
    }

    #[test]
    fn bbid() {
        let nb = get_test_verifier_setup_dir()
            .context()
            .election_event_context_payload()
            .unwrap()
            .election_event_context
            .verification_card_set_contexts
            .len();
        for i in 0..nb {
            let mut mock_dir = get_test_verifier_mock_setup_dir();
            mock_dir
                .context_mut()
                .mock_election_event_context_payload(|d| {
                    d.election_event_context.verification_card_set_contexts[i].ballot_box_id =
                        "mocked_id".to_string()
                });
            let res = mock_dir
                .context()
                .election_event_context_payload()
                .unwrap()
                .verifiy_domain(&EmptyContext);
            assert!(!res.is_empty());
        }
    }

    #[test]
    fn vcsid() {
        let nb = get_test_verifier_setup_dir()
            .context()
            .election_event_context_payload()
            .unwrap()
            .election_event_context
            .verification_card_set_contexts
            .len();
        for i in 0..nb {
            let mut mock_dir = get_test_verifier_mock_setup_dir();
            mock_dir
                .context_mut()
                .mock_election_event_context_payload(|d| {
                    d.election_event_context.verification_card_set_contexts[i]
                        .verification_card_set_id = "mocked_id".to_string()
                });
            let res = mock_dir
                .context()
                .election_event_context_payload()
                .unwrap()
                .verifiy_domain(&EmptyContext);
            assert!(!res.is_empty());
        }
    }

    #[test]
    fn p() {
        let mut mock_dir = get_test_verifier_mock_setup_dir();
        mock_dir
            .context_mut()
            .mock_election_event_context_payload(|d| d.encryption_group.set_p(&1234.into()));
        let res = mock_dir
            .context()
            .election_event_context_payload()
            .unwrap()
            .verifiy_domain(&EmptyContext);
        assert!(!res.is_empty());
    }

    #[test]
    fn q() {
        let mut mock_dir = get_test_verifier_mock_setup_dir();
        mock_dir
            .context_mut()
            .mock_election_event_context_payload(|d| d.encryption_group.set_q(&1234.into()));
        let res = mock_dir
            .context()
            .election_event_context_payload()
            .unwrap()
            .verifiy_domain(&EmptyContext);
        assert!(!res.is_empty());
    }

    #[test]
    fn g() {
        let mut mock_dir = get_test_verifier_mock_setup_dir();
        mock_dir
            .context_mut()
            .mock_election_event_context_payload(|d| d.encryption_group.set_g(&1.into()));
        let res = mock_dir
            .context()
            .election_event_context_payload()
            .unwrap()
            .verifiy_domain(&EmptyContext);
        assert!(!res.is_empty());
    }

    #[test]
    fn phi_max() {
        let mut mock_dir = get_test_verifier_mock_setup_dir();
        mock_dir
            .context_mut()
            .mock_election_event_context_payload(|d| {
                d.election_event_context.maximum_number_of_selections = d
                    .election_event_context
                    .maximum_number_of_write_ins_plus_one
                    - 2
            });
        let res = mock_dir
            .context()
            .election_event_context_payload()
            .unwrap()
            .verifiy_domain(&EmptyContext);
        assert!(!res.is_empty());
    }

    #[test]
    fn seed() {
        let seeds = vec![
            "invalid_seed",
            "SG_2023010_TT01",
            "Sg_20230101_TT01",
            "SG_202301a1_TT01",
            "SG_20230101_tt01",
            "SG_20230101_TT0a",
            "SG_20231301_TT01",
            "SG_20231201_AA01",
        ];
        for seed in seeds {
            let mut mock_dir = get_test_verifier_mock_setup_dir();
            mock_dir
                .context_mut()
                .mock_election_event_context_payload(|d| d.seed = seed.to_string());
            let res = mock_dir
                .context()
                .election_event_context_payload()
                .unwrap()
                .verifiy_domain(&EmptyContext);
            assert!(!res.is_empty(), "Seed tested: {}", seed);
        }
    }
}
