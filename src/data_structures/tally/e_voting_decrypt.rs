use super::super::VerifierDataDecode;
use crate::direct_trust::{CertificateAuthority, VerifiySignatureTrait};
use roxmltree::Document;
use rust_ev_crypto_primitives::{ByteArray, HashableMessage};

#[derive(Debug, Clone)]
pub struct EVotingDecrypt {}

impl VerifierDataDecode for EVotingDecrypt {
    fn from_roxmltree<'a>(_: &'a Document<'a>) -> anyhow::Result<Self> {
        Ok(EVotingDecrypt {})
    }
}

impl<'a> VerifiySignatureTrait<'a> for EVotingDecrypt {

    fn get_hashable(&'a self) -> anyhow::Result<HashableMessage<'a>> {
        //let hashable = XMLFileHashable::new(&self.path, &SchemaKind::config);
        //let hash = hashable.try_hash()?;
        //Ok(HashableMessage::Hashed(hash))
        todo!()
    }

    fn get_context_data(&self) -> Vec<HashableMessage<'a>> {
        vec![HashableMessage::from("evoting decrypt")]
    }

    fn get_certificate_authority(&self) -> anyhow::Result<String> {
        Ok(String::from(CertificateAuthority::Canton))
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
