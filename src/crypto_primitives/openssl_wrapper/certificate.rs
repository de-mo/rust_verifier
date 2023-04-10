//! Wrapper for Certificate functions

use super::{OpensslError, OpensslErrorType};
use crate::error::{create_result_with_error, create_verifier_error, VerifierError};
use openssl::{
    asn1::Asn1Time,
    pkcs12::{ParsedPkcs12_2, Pkcs12},
    pkey::{PKey, Public},
    x509::X509,
};
use std::{fs, path::Path};

/// Wrapper to the keystore
pub struct Keystore {
    pcks12: ParsedPkcs12_2,
}

/// The signing certificate
#[derive(Clone)]
pub struct SigningCertificate {
    authority: String,
    x509: X509,
}

// PublicKey
pub type PublicKey = PKey<Public>;

impl Keystore {
    /// Read the keystore from file with password to open it
    pub fn read_keystore(path: &Path, password: &str) -> Result<Keystore, OpensslError> {
        let bytes = fs::read(path).map_err(|e| {
            create_verifier_error!(
                OpensslErrorType::Keystore,
                format!("Error reading keystore file {:?}", path),
                e
            )
        })?;
        let p12: Pkcs12 = Pkcs12::from_der(&bytes).map_err(|e| {
            create_verifier_error!(
                OpensslErrorType::Keystore,
                format!("Error reading content of keystore file {:?}", path),
                e
            )
        })?;
        p12.parse2(password)
            .map(|p| Keystore { pcks12: p })
            .map_err(|e| {
                create_verifier_error!(
                    OpensslErrorType::Keystore,
                    format!("Error parsing keystore file {:?}", path),
                    e
                )
            })
    }

    /// Get a given certificate from the keystore
    pub fn get_certificate(&self, authority: &str) -> Result<SigningCertificate, OpensslError> {
        let cas = match self.pcks12.ca.as_ref() {
            Some(s) => s,
            None => {
                return create_result_with_error!(
                    OpensslErrorType::Certificate,
                    "List of CA does not exists"
                )
            }
        };
        for x in cas.iter() {
            for e in x.issuer_name().entries() {
                if e.object().to_string() == "commonName".to_string()
                    && e.data().as_slice() == authority.as_bytes()
                {
                    return Ok(SigningCertificate {
                        authority: authority.to_owned(),
                        x509: x.to_owned(),
                    });
                }
            }
        }
        create_result_with_error!(
            OpensslErrorType::Certificate,
            format!("Authority {} not found", authority)
        )
    }
}

impl SigningCertificate {
    /// Get the public key from the certificate
    pub fn get_public_key(&self) -> Result<PublicKey, OpensslError> {
        self.x509.public_key().map_err(|e| {
            create_verifier_error!(OpensslErrorType::PublicKey, "Error reading public key", e)
        })
    }

    /// Get the authority of the certificate
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Check the validity of the date according to now
    pub fn is_valid_time(&self) -> Result<bool, OpensslError> {
        let not_before = self.x509.not_before();
        let not_after = self.x509.not_after();
        let now = Asn1Time::days_from_now(0)
            .map_err(|e| create_verifier_error!(OpensslErrorType::Time, "Error now", e))?;
        Ok(not_before < now && now <= not_after)
    }
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use super::*;

    const PASSWORD: &str = "testPassword";

    fn get_file() -> PathBuf {
        Path::new(".")
            .join("datasets")
            .join("direct-trust")
            .join("public_keys_keystore_verifier.p12")
    }

    #[test]
    fn test_create() {
        let ks = Keystore::read_keystore(&get_file(), PASSWORD);
        assert!(ks.is_ok());
        let ks_err = Keystore::read_keystore(&get_file(), "toto");
        assert!(ks_err.is_err());
        let ks_err2 = Keystore::read_keystore(Path::new("./toto.p12"), PASSWORD);
        assert!(ks_err2.is_err());
    }

    #[test]
    fn get_certificate() {
        let ks = Keystore::read_keystore(&get_file(), PASSWORD).unwrap();
        let cert = ks.get_certificate("canton");
        assert!(cert.is_ok());
        assert_eq!(cert.unwrap().authority(), "canton");
        let cert = ks.get_certificate("sdm_config");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("sdm_tally");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("voting_server");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_1");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_2");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_3");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("control_component_4");
        assert!(cert.is_ok());
        let cert = ks.get_certificate("toto");
        assert!(cert.is_err());
    }
}
