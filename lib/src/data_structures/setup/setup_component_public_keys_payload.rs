use super::{
    super::{
        common_types::{EncryptionGroup, ProofUnderline, SignatureJson},
        deserialize_seq_string_hex_to_seq_bigunit, implement_trait_verifier_data_json_decode,
        VerifierDataDecode,
    },
    control_component_public_keys_payload::ControlComponentPublicKeys,
};
use anyhow::anyhow;
use crypto_primitives::{
    byte_array::ByteArray, direct_trust::CertificateAuthority, hashing::HashableMessage,
    signature::VerifiySignatureTrait,
};
use num_bigint::BigUint;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SetupComponentPublicKeysPayload {
    pub encryption_group: EncryptionGroup,
    pub election_event_id: String,
    pub setup_component_public_keys: SetupComponentPublicKeys,
    pub signature: SignatureJson,
}

implement_trait_verifier_data_json_decode!(SetupComponentPublicKeysPayload);

impl<'a> From<&'a SetupComponentPublicKeysPayload> for HashableMessage<'a> {
    fn from(value: &'a SetupComponentPublicKeysPayload) -> Self {
        Self::from(vec![
            Self::from(&value.encryption_group),
            Self::from(&value.setup_component_public_keys),
        ])
    }
}

impl<'a> VerifiySignatureTrait<'a> for SetupComponentPublicKeysPayload {
    fn get_context_data(&'a self) -> Vec<HashableMessage<'a>> {
        vec![
            HashableMessage::from("public keys"),
            HashableMessage::from("setup"),
            HashableMessage::from(&self.election_event_id),
        ]
    }

    fn get_certificate_authority(&self) -> CertificateAuthority {
        CertificateAuthority::SdmConfig
    }

    fn get_signature(&self) -> ByteArray {
        self.signature.get_signature()
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SetupComponentPublicKeys {
    pub combined_control_component_public_keys: Vec<ControlComponentPublicKeys>,
    #[serde(deserialize_with = "deserialize_seq_string_hex_to_seq_bigunit")]
    pub electoral_board_public_key: Vec<BigUint>,
    pub electoral_board_schnorr_proofs: Vec<ProofUnderline>,
    #[serde(deserialize_with = "deserialize_seq_string_hex_to_seq_bigunit")]
    pub election_public_key: Vec<BigUint>,
    #[serde(deserialize_with = "deserialize_seq_string_hex_to_seq_bigunit")]
    pub choice_return_codes_encryption_public_key: Vec<BigUint>,
}

impl<'a> From<&'a SetupComponentPublicKeys> for HashableMessage<'a> {
    fn from(value: &'a SetupComponentPublicKeys) -> Self {
        let mut elts = vec![];
        let cc: Vec<HashableMessage> = value
            .combined_control_component_public_keys
            .iter()
            .map(Self::from)
            .collect();
        elts.push(Self::from(cc));
        elts.push(Self::from(&value.electoral_board_public_key));
        let el_sp: Vec<HashableMessage> = value
            .electoral_board_schnorr_proofs
            .iter()
            .map(Self::from)
            .collect();
        elts.push(Self::from(el_sp));
        elts.push(Self::from(&value.election_public_key));
        elts.push(Self::from(&value.choice_return_codes_encryption_public_key));
        Self::from(elts)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::config::test::test_dataset_tally_path;
    use std::fs;

    #[test]
    fn read_data_set() {
        let path = test_dataset_tally_path()
            .join("setup")
            .join("setupComponentPublicKeysPayload.json");
        let json = fs::read_to_string(path).unwrap();
        let r_eec = SetupComponentPublicKeysPayload::from_json(&json);
        assert!(r_eec.is_ok())
    }
}
