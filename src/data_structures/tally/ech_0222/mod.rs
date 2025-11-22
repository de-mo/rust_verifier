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

//! Module to read, calculated and compare eCH-0222
//!
//! See [README](README.md) for the details of the implementation

mod ech_0222_data;
mod election;
mod votations;

use super::{
    super::{DataStructureError, VerifierDataDecode},
    VerifierTallyDataType,
};
use crate::{
    data_structures::{
        DataStructureErrorImpl, VerifierDataToTypeTrait, VerifierDataType, xml::XMLData,
    },
    direct_trust::{CertificateAuthority, VerifiySignatureTrait, VerifiyXMLSignatureTrait},
    file_structure::FileStructureError,
};
pub use ech_0222_data::*;
use roxmltree::Document;
use std::{fmt::Display, sync::Arc};
use thiserror::Error;

/// Data structure containing the eCH0222
pub type ECH0222 = XMLData<ECH0222Data, DataStructureError>;

#[derive(Error, Debug)]
#[error(transparent)]
/// Error calculating the eCH-0222
pub struct ECH0222CalculatedError(#[from] ECH0222CalculatedErrorImpl);

#[derive(Error, Debug)]
pub enum ECH0222CalculatedErrorImpl {
    #[error("Error getting tally_component_votes_payload for ballot box {bb_id}: {source}")]
    TallyVoteMissing {
        bb_id: String,
        source: Box<FileStructureError>,
    },
    #[error("Unexpected list id {0} in {1}")]
    UnexpectedList(String, &'static str),
    #[error("The write-in option id {0} found without having an answer")]
    WriteInOptionWithoutVote(String),
    #[error("Type_of_id for the option given with id {id} is empty (list {list_id:?}")]
    TypeOfIdNone { id: String, list_id: Option<String> },
    #[error("Error by adding election groups for cc {cc_id}: {source}")]
    ElectionCC { cc_id: String, source: Box<Self> },
    #[error("The question id {q_id} not found in the decoded ballot")]
    QuestionIdMissing { q_id: String },
    #[error("Error with the decoded vote at position {i}: {source}")]
    ErrorOnDecodedVote { i: usize, source: Box<Self> },
    #[error("Answer id {a_id} for the question id {q_id} not found")]
    AnswerIdMissing { a_id: String, q_id: String },
    #[error("The decoded vote {decoded_vote} is malformed: {msg}")]
    MalformedDecodedVote {
        decoded_vote: String,
        msg: &'static str,
    },
}

/// The difference between two [ECH0222Data]
#[derive(Debug, Clone)]
pub struct ECH0222Difference {
    message: String,
    reason: Option<Box<ECH0222Difference>>,
}

pub trait ECh0222differencesTrait {
    /// Calculate the difference between the calculated value (self) and the expected value
    fn calculate_differences(&self, expected: &Self) -> Vec<ECH0222Difference>;
}

impl ECH0222Difference {
    /// New difference with message
    fn new_with_messsage(msg: String) -> Self {
        Self {
            message: msg,
            reason: None,
        }
    }

    /// New difference with a message and the reason as deeper [ECH0222Difference]
    fn new_with_reason(reason: Self, msg: String) -> Self {
        Self {
            message: msg,
            reason: Some(Box::new(reason)),
        }
    }

    /// New difference with a message and the reason as deeper [ECH0222Difference]
    fn new_vector_with_reason(reason: Vec<Self>, msg: String) -> Vec<Self> {
        reason
            .into_iter()
            .map(|e| Self::new_with_reason(e, msg.clone()))
            .collect()
    }

    /// The difference with all the reasons
    fn to_vec_string(&self) -> Vec<&str> {
        let mut res = vec![self.message.as_str()];
        if let Some(reason) = &self.reason {
            res.append(&mut reason.to_vec_string());
        }
        res
    }
}

impl Display for ECH0222Difference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_vec_string().join("\n"))
    }
}

impl VerifierDataToTypeTrait for ECH0222 {
    fn data_type() -> VerifierDataType {
        VerifierDataType::Tally(VerifierTallyDataType::ECH0222)
    }
}

fn decode_xml(s: &str) -> Result<ECH0222Data, DataStructureError> {
    let doc = Document::parse(s).map_err(|e| DataStructureErrorImpl::ParseRoXML {
        msg: "Parsing the input string".to_string(),
        source: e,
    })?;
    let root = doc.root();
    let delivery = root.first_element_child().unwrap();
    Ok(ECH0222Data::from_node(&delivery))
}

impl VerifierDataDecode for ECH0222 {
    fn decode_xml<'a>(s: String) -> Result<Self, DataStructureError> {
        Ok(XMLData::new(s.as_str(), decode_xml))
    }
}

impl<'a> VerifiyXMLSignatureTrait<'a> for ECH0222 {
    fn get_certificate_authority(&self) -> Option<CertificateAuthority> {
        Some(CertificateAuthority::SdmTally)
    }

    fn get_data_str(&self) -> Option<Arc<String>> {
        self.get_raw()
    }
}

impl<'a> VerifiySignatureTrait<'a> for ECH0222 {
    fn verifiy_signature(
        &'a self,
        keystore: &crate::direct_trust::Keystore,
    ) -> Result<bool, crate::direct_trust::VerifySignatureError> {
        self.verifiy_xml_signature(keystore)
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        config::test::{
            get_keystore, get_test_verifier_tally_dir, test_data_path, test_datasets_tally_path,
        },
        file_structure::{
            ContextDirectoryTrait, TallyDirectoryTrait, VerificationDirectory,
            VerificationDirectoryTrait,
        },
        verification::VerificationPeriod,
    };
    use std::fs;

    fn get_data_res() -> Result<ECH0222, DataStructureError> {
        ECH0222::decode_xml(
            fs::read_to_string(
                test_datasets_tally_path().join("eCH-0222_v3-0_NE_20231124_TT05.xml"),
            )
            .unwrap(),
        )
    }

    #[test]
    fn read_data_set() {
        let data_res = get_data_res();
        assert!(data_res.is_ok(), "{:?}", data_res.unwrap_err());
        let data_res = data_res.unwrap().get_data();
        assert!(data_res.is_ok(), "{:?}", data_res.unwrap_err());
    }

    #[test]
    fn verify_signature() {
        let data = get_data_res().unwrap();
        let ks = get_keystore();
        let sign_validate_res = data.verify_signatures(&ks);
        for r in sign_validate_res {
            assert!(
                r.is_ok(),
                "error validating signature: {:?}",
                r.as_ref().unwrap_err()
            );
            assert!(r.unwrap())
        }
    }

    #[test]
    fn calculate_ech0222() {
        let dir = get_test_verifier_tally_dir();
        let ech_res = ECH0222Data::create_ech0222_data(
            &dir.context()
                .election_event_context_payload()
                .as_ref()
                .unwrap()
                .election_event_context,
            dir.context()
                .election_event_configuration()
                .as_ref()
                .unwrap()
                .get_data()
                .unwrap()
                .as_ref(),
            dir.unwrap_tally().bb_directories(),
        );
        assert!(ech_res.is_ok(), "{:?}", ech_res.unwrap_err());
    }

    #[test]
    fn compare_ech0222() {
        let dir = get_test_verifier_tally_dir();
        let loaded = get_data_res().unwrap().get_data().unwrap();
        let calculated = ECH0222Data::create_ech0222_data(
            &dir.context()
                .election_event_context_payload()
                .as_ref()
                .unwrap()
                .election_event_context,
            dir.context()
                .election_event_configuration()
                .as_ref()
                .unwrap()
                .get_data()
                .unwrap()
                .as_ref(),
            dir.unwrap_tally().bb_directories(),
        )
        .unwrap();
        let diff = loaded.as_ref().calculate_differences(&calculated);
        assert!(
            diff.is_empty(),
            "{:?}",
            diff.iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    #[test]
    fn compare_ech0222_with_writeins() {
        let test_dir_path = test_data_path().join("ech_0222_with_write_ins");
        let dir = VerificationDirectory::new(&VerificationPeriod::Tally, &test_dir_path);
        let loaded = ECH0222::decode_xml(
            fs::read_to_string(
                test_dir_path
                    .join("tally")
                    .join("eCH-0222_v3-0_SG_20251110_TT01.xml"),
            )
            .unwrap(),
        )
        .unwrap()
        .get_data()
        .unwrap();
        let calculated = ECH0222Data::create_ech0222_data(
            &dir.context()
                .election_event_context_payload()
                .as_ref()
                .unwrap()
                .election_event_context,
            dir.context()
                .election_event_configuration()
                .as_ref()
                .unwrap()
                .get_data()
                .unwrap()
                .as_ref(),
            dir.unwrap_tally().bb_directories(),
        )
        .unwrap();
        let diff = loaded.as_ref().calculate_differences(&calculated);
        assert!(
            diff.is_empty(),
            "{:?}",
            diff.iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("\n")
        )
    }
}
