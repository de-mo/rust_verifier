use super::super::VerifierDataDecode;
use crypto_primitives::{
    byte_array::ByteArray, direct_trust::CertificateAuthority, hashing::HashableMessage,
    signature::VerifiySignatureTrait,
};
use roxmltree::Document;

#[derive(Debug, Clone)]
pub struct EVotingDecrypt {}

impl VerifierDataDecode for EVotingDecrypt {
    fn from_roxmltree<'a>(_: &'a Document<'a>) -> anyhow::Result<Self> {
        Ok(EVotingDecrypt {})
    }
}

impl<'a> From<&'a EVotingDecrypt> for HashableMessage<'a> {
    fn from(_: &'a EVotingDecrypt) -> Self {
        todo!()
    }
}

impl<'a> VerifiySignatureTrait<'a> for EVotingDecrypt {
    fn get_context_data(&self) -> Vec<HashableMessage<'a>> {
        vec![HashableMessage::from("evoting decrypt")]
    }

    fn get_certificate_authority(&self) -> CertificateAuthority {
        CertificateAuthority::Canton
    }
    fn get_signature(&self) -> ByteArray {
        todo!()
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
            .join("tally")
            .join("evoting-decrypt_Post_E2E_DEV.xml");
        let xml = fs::read_to_string(path).unwrap();
        let config = EVotingDecrypt::from_roxmltree(&Document::parse(&xml).unwrap());
        assert!(config.is_ok())
    }
}
