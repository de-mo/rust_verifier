use super::super::{
    common_types::{EncryptionParametersDef, ExponentiatedEncryptedElement, Proof, Signature},
    deserialize_seq_string_base64_to_seq_integer, implement_trait_verifier_data_json_decode,
    VerifierDataDecode,
};
use crate::direct_trust::{CertificateAuthority, VerifiySignatureTrait};
use anyhow::{anyhow, Context};
use rug::Integer;
use rust_ev_crypto_primitives::{
    ByteArray, EncryptionParameters, HashableMessage, VerifyDomainTrait,
};
use serde::Deserialize;

pub type ControlComponentCodeSharesPayload = Vec<ControlComponentCodeSharesPayloadInner>;

implement_trait_verifier_data_json_decode!(ControlComponentCodeSharesPayload);

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ControlComponentCodeSharesPayloadInner {
    pub election_event_id: String,
    pub verification_card_set_id: String,
    pub chunk_id: usize,
    pub control_component_code_shares: Vec<ControlComponentCodeShare>,
    #[serde(with = "EncryptionParametersDef")]
    pub encryption_group: EncryptionParameters,
    pub node_id: usize,
    pub signature: Signature,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ControlComponentCodeShare {
    pub verification_card_id: String,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    pub voter_choice_return_code_generation_public_key: Vec<Integer>,
    #[serde(deserialize_with = "deserialize_seq_string_base64_to_seq_integer")]
    pub voter_vote_cast_return_code_generation_public_key: Vec<Integer>,
    pub exponentiated_encrypted_partial_choice_return_codes: ExponentiatedEncryptedElement,
    pub encrypted_partial_choice_return_code_exponentiation_proof: Proof,
    pub exponentiated_encrypted_confirmation_key: ExponentiatedEncryptedElement,
    pub encrypted_confirmation_key_exponentiation_proof: Proof,
}

impl VerifyDomainTrait for ControlComponentCodeSharesPayloadInner {}

impl<'a> From<&'a ControlComponentCodeSharesPayloadInner> for HashableMessage<'a> {
    fn from(value: &'a ControlComponentCodeSharesPayloadInner) -> Self {
        let mut elts = vec![
            Self::from(&value.election_event_id),
            Self::from(&value.verification_card_set_id),
            Self::from(&value.chunk_id),
            Self::from(&value.encryption_group),
        ];
        let l: Vec<HashableMessage> = value
            .control_component_code_shares
            .iter()
            .map(Self::from)
            .collect();
        elts.push(Self::from(l));
        elts.push(Self::from(&value.node_id));
        Self::from(elts)
    }
}

impl<'a> From<&'a ControlComponentCodeShare> for HashableMessage<'a> {
    fn from(value: &'a ControlComponentCodeShare) -> Self {
        Self::from(vec![
            Self::from(&value.verification_card_id),
            Self::from(&value.voter_choice_return_code_generation_public_key),
            Self::from(&value.voter_vote_cast_return_code_generation_public_key),
            Self::from(&value.exponentiated_encrypted_partial_choice_return_codes),
            Self::from(&value.encrypted_partial_choice_return_code_exponentiation_proof),
            Self::from(&value.exponentiated_encrypted_confirmation_key),
            Self::from(&value.encrypted_confirmation_key_exponentiation_proof),
        ])
    }
}

impl<'a> VerifiySignatureTrait<'a> for ControlComponentCodeSharesPayloadInner {
    fn get_hashable(&'a self) -> anyhow::Result<HashableMessage<'a>> {
        Ok(HashableMessage::from(self))
    }

    fn get_context_data(&'a self) -> Vec<HashableMessage<'a>> {
        vec![
            HashableMessage::from("encrypted code shares"),
            HashableMessage::from(&self.node_id),
            HashableMessage::from(&self.election_event_id),
            HashableMessage::from(&self.verification_card_set_id),
        ]
    }

    fn get_certificate_authority(&self) -> anyhow::Result<String> {
        Ok(String::from(
            CertificateAuthority::get_ca_cc(&self.node_id).context(format!(
                "verifiy signature for ControlComponentCodeSharesPayloadInner for node {}",
                self.node_id
            ))?,
        ))
    }

    fn get_signature(&self) -> ByteArray {
        self.signature.get_signature()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::test::test_verification_card_set_path;
    use std::fs;

    #[test]
    fn read_data_set() {
        let path =
            test_verification_card_set_path().join("controlComponentCodeSharesPayload.0.json");
        let json = fs::read_to_string(path).unwrap();
        let r_eec = ControlComponentCodeSharesPayload::from_json(&json);
        //println!("{:?}", r_eec);
        assert!(r_eec.is_ok())
    }
}
