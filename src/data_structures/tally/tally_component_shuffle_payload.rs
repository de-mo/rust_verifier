use super::super::{
    common_types::{EncryptionParametersDef, ExponentiatedEncryptedElement, Signature},
    deserialize_seq_string_base64_to_seq_integer, deserialize_string_base64_to_integer,
    implement_trait_verifier_data_json_decode, VerifierDataDecode,
};
use crate::data_structures::common_types::DecryptionProof;
use anyhow::anyhow;
use rug::Integer;
use rust_ev_crypto_primitives::EncryptionParameters;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TallyComponentShufflePayload {
    #[serde(with = "EncryptionParametersDef")]
    pub encryption_group: EncryptionParameters,
    pub election_event_id: String,
    pub ballot_box_id: String,
    pub verifiable_shuffle: VerifiableShuffle,
    pub verifiable_plaintext_decryption: VerifiablePlaintextDecryption,
    pub signature: Signature,
}
implement_trait_verifier_data_json_decode!(TallyComponentShufflePayload);

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiableShuffle {
    pub shuffled_ciphertexts: Vec<ExponentiatedEncryptedElement>,
    pub shuffle_argument: ShuffleArgument,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifiablePlaintextDecryption {
    pub decrypted_votes: Vec<DecryptedVote>,
    pub decryption_proofs: Vec<DecryptionProof>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ShuffleArgument {
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    #[serde(rename = "c_A")]
    pub c_a: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    #[serde(rename = "c_B")]
    pub c_b: Vec<Integer>,
    #[serde(rename = "productArgument")]
    pub product_argument: ProductArgument,
    #[serde(rename = "multiExponentiationArgument")]
    pub multi_exponentiation_argument: MultiExponentiationArgument,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ProductArgument {
    pub single_value_product_argument: SingleValueProductArgument,
}

#[derive(Deserialize, Debug, Clone)]
pub struct SingleValueProductArgument {
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub c_d: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub c_delta: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    #[serde(rename = "c_Delta")]
    pub c_delta_upper: Integer,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    pub a_tilde: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    pub b_tilde: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub r_tilde: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub s_tilde: Integer,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MultiExponentiationArgument {
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    #[serde(rename = "c_A_0")]
    pub c_a_0: Integer,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    #[serde(rename = "c_B")]
    pub c_b: Vec<Integer>,
    #[serde(rename = "E")]
    pub e: Vec<ExponentiatedEncryptedElement>,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    pub a: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub r: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub b: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub s: Integer,
    #[serde(deserialize_with = "deserialize_string_base64_to_integer")]
    pub tau: Integer,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DecryptedVote {
    pub message: Vec<String>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::test::test_ballot_box_path;
    use std::fs;

    #[test]
    fn read_data_set() {
        let path = test_ballot_box_path().join("tallyComponentShufflePayload.json");
        let json = fs::read_to_string(path).unwrap();
        let r_eec = TallyComponentShufflePayload::from_json(&json);
        println!("{:?}", r_eec.as_ref().err());
        assert!(r_eec.is_ok())
    }
}
