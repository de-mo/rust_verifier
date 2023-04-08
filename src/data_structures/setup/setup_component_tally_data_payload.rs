use super::super::deserialize_seq_seq_string_hex_to_seq_seq_bigunit;
use super::super::{
    error::{DeserializeError, DeserializeErrorType},
    implement_trait_data_structure, DataStructureTrait, Signature,
};
use super::encryption_parameters_payload::EncryptionGroup;
use crate::error::{create_verifier_error, VerifierError};
use num_bigint::BigUint;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SetupComponentTallyDataPayload {
    pub election_event_id: String,
    pub verification_card_set_id: String,
    pub ballot_box_default_title: String,
    pub encryption_group: EncryptionGroup,
    pub verification_card_ids: Vec<String>,
    #[serde(deserialize_with = "deserialize_seq_seq_string_hex_to_seq_seq_bigunit")]
    pub verification_card_public_keys: Vec<Vec<BigUint>>,
    pub signature: Signature,
}

implement_trait_data_structure!(SetupComponentTallyDataPayload);

#[cfg(test)]
mod test {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn read_data_set() {
        let path = Path::new(".")
            .join("datasets")
            .join("dataset-setup1")
            .join("setup")
            .join("verification_card_sets")
            .join("7e8ce00c2c164c268c11cfa7066e3d9f")
            .join("setupComponentTallyDataPayload.json");
        let json = fs::read_to_string(&path).unwrap();
        let r_eec = SetupComponentTallyDataPayload::from_json(&json);
        assert!(r_eec.is_ok())
    }
}
