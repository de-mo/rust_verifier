//! Module to define the structure of the data and to read the data from the files into these structures
//!
//! The module is separate in two module: [setup] and [tally]
//!
pub mod common_types;
pub mod setup;
pub mod setup_or_tally;
pub mod tally;
mod xml;

use self::{
    setup::{
        control_component_code_shares_payload::ControlComponentCodeSharesPayload,
        control_component_public_keys_payload::ControlComponentPublicKeysPayload,
        election_event_configuration::ElectionEventConfiguration,
        election_event_context_payload::ElectionEventContextPayload,
        setup_component_public_keys_payload::SetupComponentPublicKeysPayload,
        setup_component_tally_data_payload::SetupComponentTallyDataPayload,
        setup_component_verification_data_payload::SetupComponentVerificationDataPayload,
        VerifierSetupData, VerifierSetupDataType,
    },
    tally::{
        control_component_ballot_box_payload::ControlComponentBallotBoxPayload,
        control_component_shuffle_payload::ControlComponentShufflePayload,
        e_voting_decrypt::EVotingDecrypt, ech_0110::ECH0110, ech_0222::ECH0222,
        tally_component_shuffle_payload::TallyComponentShufflePayload,
        tally_component_votes_payload::TallyComponentVotesPayload, VerifierTallyData,
        VerifierTallyDataType,
    },
};
use crate::file_structure::{file::File, FileReadMode, FileType};
use anyhow::{anyhow, bail};
use chrono::NaiveDateTime;
use roxmltree::Document;
use rug::Integer;
use rust_ev_crypto_primitives::{ByteArray, Decode, Hexa};
use serde::de::{Deserialize, Deserializer, Error};
use setup_or_tally::SetupOrTally;
use std::path::Path;

/// The type VerifierData implement an option between [VerifierSetupData] and [VerifierTallyData]
pub type VerifierData = SetupOrTally<VerifierSetupData, VerifierTallyData>;

/// The type VerifierDataType implement an option between [VerifierSetupDataType] and [VerifierTallyDataType]
pub type VerifierDataType = SetupOrTally<VerifierSetupDataType, VerifierTallyDataType>;

macro_rules! create_verifier_setup_data_type {
    ($p: ident, $s: ident) => {
        VerifierDataType::$p(VerifierSetupDataType::$s)
    };
}
pub(crate) use create_verifier_setup_data_type;

macro_rules! create_verifier_tally_data_type {
    ($p: ident, $s: ident) => {
        VerifierDataType::$p(VerifierTallyDataType::$s)
    };
}
pub(crate) use create_verifier_tally_data_type;

/// Trait implementing the collection of the specific setup data type from the enum object
pub trait VerifierSetupDataTrait {
    fn setup_component_public_keys_payload(&self) -> Option<&SetupComponentPublicKeysPayload> {
        None
    }
    fn election_event_context_payload(&self) -> Option<&ElectionEventContextPayload> {
        None
    }
    fn setup_component_tally_data_payload(&self) -> Option<&SetupComponentTallyDataPayload> {
        None
    }
    fn control_component_public_keys_payload(&self) -> Option<&ControlComponentPublicKeysPayload> {
        None
    }
    fn setup_component_verification_data_payload(
        &self,
    ) -> Option<&SetupComponentVerificationDataPayload> {
        None
    }
    fn control_component_code_shares_payload(&self) -> Option<&ControlComponentCodeSharesPayload> {
        None
    }
    fn election_event_configuration(&self) -> Option<&ElectionEventConfiguration> {
        None
    }
}

/// Trait implementing the collection of the specific tally data type from the enum object
pub trait VerifierTallyDataTrait {
    fn e_voting_decrypt(&self) -> Option<&EVotingDecrypt> {
        None
    }
    fn ech_0110(&self) -> Option<&ECH0110> {
        None
    }
    fn ech_0222(&self) -> Option<&ECH0222> {
        None
    }
    fn tally_component_votes_payload(&self) -> Option<&TallyComponentVotesPayload> {
        None
    }
    fn tally_component_shuffle_payload(&self) -> Option<&TallyComponentShufflePayload> {
        None
    }
    fn control_component_ballot_box_payload(&self) -> Option<&ControlComponentBallotBoxPayload> {
        None
    }

    fn control_component_shuffle_payload(&self) -> Option<&ControlComponentShufflePayload> {
        None
    }
}

/// A trait defining the necessary function to decode to the Verifier Data
pub trait VerifierDataDecode: Sized {
    /// Decode the data from the file
    ///
    /// # Arguments
    /// * `f`: The [File] to read
    /// * `t`: The type of the file (json or xml)
    /// * `mode`: The mode to read the file (memory or streaming)
    ///
    /// # Return
    /// The decoded data or [anyhow::Result] if something wrong
    fn from_file(f: &File, t: &FileType, mode: &FileReadMode) -> anyhow::Result<Self> {
        match mode {
            FileReadMode::Memory => Self::from_file_memory(f, t),
            FileReadMode::Streaming => Self::from_file_stream(f, t),
        }
    }

    /// Decode the data from the file in memory
    ///
    /// # Arguments
    /// * `f`: The [File] to read
    /// * `t`: The type of the file (json or xml)
    ///
    /// # Return
    /// The decoded data or [anyhow::Result] if something wrong
    fn from_file_memory(f: &File, t: &FileType) -> anyhow::Result<Self> {
        let s = f.read_data().map_err(|e| {
            anyhow!(e).context(format!("Error reading data in file {}", f.to_str()))
        })?;
        match t {
            FileType::Json => Self::from_json(&s),
            FileType::Xml => {
                let doc = Document::parse(&s).map_err(|e| {
                    anyhow!(e).context(format!("Cannot parse content of xml file {}", f.to_str()))
                })?;
                Self::from_roxmltree(&doc)
            }
        }
    }

    /// Decode the data from the file streaming
    ///
    /// # Arguments
    /// * `f`: The [File] to read
    /// * `t`: The type of the file (json or xml)
    ///
    /// # Return
    /// The decoded data or [anyhow::Result] if something wrong
    fn from_file_stream(f: &File, t: &FileType) -> anyhow::Result<Self> {
        match t {
            FileType::Json => {
                bail!(format!("from_file not implemented for JSON Files"))
            }
            FileType::Xml => Self::from_xml_file(&f.get_path()),
        }
    }

    /// Decode the data from a json string
    ///
    /// # Return
    /// The decoded data or [anyhow::Result] if something wrong, e.g. if it is not allowed, or if an error
    /// occured during the decoding
    fn from_json(_: &String) -> anyhow::Result<Self> {
        bail!(format!("from_json not implemented now"))
    }

    /// Decode the data from a xml [Document] (roxmltreee)
    ///
    /// # Return
    /// The decoded data or [anyhow::Result] if something wrong, e.g. if it is not allowed, or if an error
    /// occured during the decoding
    fn from_roxmltree<'a>(_: &'a Document<'a>) -> anyhow::Result<Self> {
        bail!(format!("from_roxmltree not implemented now"))
    }

    /// Decode the data from a xml xml file
    ///
    /// # Return
    /// The decoded data or [anyhow::Result] if something wrong, e.g. if it is not allowed, or if an error
    /// occured during the decoding
    fn from_xml_file(_: &Path) -> anyhow::Result<Self> {
        bail!(format!("from_xml_file not implemented now"))
    }
}

/// Macro to automatically implement the DataStructureTrait for a type
macro_rules! implement_trait_verifier_data_json_decode {
    ($s: ty) => {
        impl VerifierDataDecode for $s {
            fn from_json(s: &String) -> anyhow::Result<Self> {
                serde_json::from_str(s)
                    .map_err(|e| anyhow!(e).context(format!("Cannot deserialize json")))
            }
        }
    };
}
use implement_trait_verifier_data_json_decode;

impl VerifierSetupDataTrait for VerifierData {
    fn setup_component_public_keys_payload(&self) -> Option<&SetupComponentPublicKeysPayload> {
        match self {
            VerifierData::Setup(d) => d.setup_component_public_keys_payload(),
            VerifierData::Tally(_) => None,
        }
    }

    fn election_event_context_payload(&self) -> Option<&ElectionEventContextPayload> {
        match self {
            VerifierData::Setup(d) => d.election_event_context_payload(),
            VerifierData::Tally(_) => None,
        }
    }

    fn setup_component_tally_data_payload(&self) -> Option<&SetupComponentTallyDataPayload> {
        match self {
            VerifierData::Setup(d) => d.setup_component_tally_data_payload(),
            VerifierData::Tally(_) => None,
        }
    }

    fn control_component_public_keys_payload(&self) -> Option<&ControlComponentPublicKeysPayload> {
        match self {
            VerifierData::Setup(d) => d.control_component_public_keys_payload(),
            VerifierData::Tally(_) => None,
        }
    }

    fn setup_component_verification_data_payload(
        &self,
    ) -> Option<&SetupComponentVerificationDataPayload> {
        match self {
            VerifierData::Setup(d) => d.setup_component_verification_data_payload(),
            VerifierData::Tally(_) => None,
        }
    }

    fn control_component_code_shares_payload(&self) -> Option<&ControlComponentCodeSharesPayload> {
        match self {
            VerifierData::Setup(d) => d.control_component_code_shares_payload(),
            VerifierData::Tally(_) => None,
        }
    }

    fn election_event_configuration(&self) -> Option<&ElectionEventConfiguration> {
        match self {
            VerifierData::Setup(d) => d.election_event_configuration(),
            VerifierData::Tally(_) => None,
        }
    }
}

impl VerifierTallyDataTrait for VerifierData {
    fn e_voting_decrypt(&self) -> Option<&EVotingDecrypt> {
        match self {
            VerifierData::Setup(_) => None,
            VerifierData::Tally(d) => d.e_voting_decrypt(),
        }
    }
    fn ech_0110(&self) -> Option<&ECH0110> {
        match self {
            VerifierData::Setup(_) => None,
            VerifierData::Tally(d) => d.ech_0110(),
        }
    }
    fn ech_0222(&self) -> Option<&ECH0222> {
        match self {
            VerifierData::Setup(_) => None,
            VerifierData::Tally(d) => d.ech_0222(),
        }
    }
    fn tally_component_votes_payload(&self) -> Option<&TallyComponentVotesPayload> {
        match self {
            VerifierData::Setup(_) => None,
            VerifierData::Tally(d) => d.tally_component_votes_payload(),
        }
    }
    fn tally_component_shuffle_payload(&self) -> Option<&TallyComponentShufflePayload> {
        match self {
            VerifierData::Setup(_) => None,
            VerifierData::Tally(d) => d.tally_component_shuffle_payload(),
        }
    }
    fn control_component_ballot_box_payload(&self) -> Option<&ControlComponentBallotBoxPayload> {
        match self {
            VerifierData::Setup(_) => None,
            VerifierData::Tally(d) => d.control_component_ballot_box_payload(),
        }
    }
    fn control_component_shuffle_payload(&self) -> Option<&ControlComponentShufflePayload> {
        match self {
            VerifierData::Setup(_) => None,
            VerifierData::Tally(d) => d.control_component_shuffle_payload(),
        }
    }
}

impl VerifierDataType {
    /// Read VerifierDataType from a String as JSON
    pub fn verifier_data_from_file(&self, f: &File) -> anyhow::Result<VerifierData> {
        match self {
            VerifierDataType::Setup(t) => t
                .verifier_data_from_file(f)
                .map_err(|e| e.context("in verifier_data_from_file"))
                .map(VerifierData::Setup),
            VerifierDataType::Tally(t) => t
                .verifier_data_from_file(f)
                .map_err(|e| e.context("in verifier_data_from_file"))
                .map(VerifierData::Tally),
        }
    }
}

fn deserialize_string_hex_to_integer<'de, D>(deserializer: D) -> Result<Integer, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;

    Integer::from_hexa_string(&buf).map_err(|e| Error::custom(e.to_string()))
}

fn deserialize_string_base64_to_integer<'de, D>(deserializer: D) -> Result<Integer, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;

    ByteArray::base64_decode(&buf)
        .map_err(|e| Error::custom(e.to_string()))
        .map(|e| e.into_mp_integer())
}

fn deserialize_string_string_to_datetime<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let buf = String::deserialize(deserializer)?;

    NaiveDateTime::parse_from_str(&buf, "%Y-%m-%dT%H:%M:%S")
        .map_err(|e| Error::custom(e.to_string()))
}

fn deserialize_seq_string_hex_to_seq_integer<'de, D>(
    deserializer: D,
) -> Result<Vec<Integer>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Visitor;

    impl<'de> ::serde::de::Visitor<'de> for Visitor {
        type Value = Vec<Integer>;

        fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            write!(f, "a sequence of string")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut vec = <Self::Value>::new();

            while let Some(v) = (seq.next_element())? {
                let r_b = Integer::from_hexa_string(v).map_err(A::Error::custom)?;
                vec.push(r_b);
            }
            Ok(vec)
        }
    }
    deserializer.deserialize_seq(Visitor)
}

#[allow(dead_code)]
fn deserialize_seq_string_base64_to_seq_bytearray<'de, D>(
    deserializer: D,
) -> Result<Vec<ByteArray>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Visitor;

    impl<'de> ::serde::de::Visitor<'de> for Visitor {
        type Value = Vec<ByteArray>;

        fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            write!(f, "a sequence of string")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut vec = <Self::Value>::new();

            while let Some(v) = (seq.next_element())? {
                let r_b = ByteArray::base64_decode(v).map_err(A::Error::custom)?;
                vec.push(r_b);
            }
            Ok(vec)
        }
    }
    deserializer.deserialize_seq(Visitor)
}

#[allow(dead_code)]
fn deserialize_seq_string_base64_to_seq_integer<'de, D>(
    deserializer: D,
) -> Result<Vec<Integer>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Visitor;

    impl<'de> ::serde::de::Visitor<'de> for Visitor {
        type Value = Vec<Integer>;

        fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            write!(f, "a sequence of string")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut vec = <Self::Value>::new();

            while let Some(v) = (seq.next_element())? {
                let r_b = ByteArray::base64_decode(v).map_err(A::Error::custom)?;
                vec.push(r_b.into_mp_integer());
            }
            Ok(vec)
        }
    }
    deserializer.deserialize_seq(Visitor)
}

fn deserialize_seq_seq_string_hex_to_seq_seq_integer<'de, D>(
    deserializer: D,
) -> Result<Vec<Vec<Integer>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Visitor;

    impl<'de> ::serde::de::Visitor<'de> for Visitor {
        type Value = Vec<Vec<Integer>>;

        fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            write!(f, "a sequence of string")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut vec = <Self::Value>::new();

            while let Some(v) = (seq.next_element::<Vec<String>>())? {
                let mut inner_vec = Vec::new();
                for x in v {
                    let r_b = Integer::from_hexa_string(&x).map_err(A::Error::custom)?;
                    inner_vec.push(r_b);
                }
                vec.push(inner_vec.to_owned());
            }
            Ok(vec)
        }
    }
    deserializer.deserialize_seq(Visitor)
}

fn deserialize_seq_seq_string_base64_to_seq_seq_integer<'de, D>(
    deserializer: D,
) -> Result<Vec<Vec<Integer>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Visitor;

    impl<'de> ::serde::de::Visitor<'de> for Visitor {
        type Value = Vec<Vec<Integer>>;

        fn expecting(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            write!(f, "a sequence of string")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut vec = <Self::Value>::new();

            while let Some(v) = (seq.next_element::<Vec<String>>())? {
                let mut inner_vec = Vec::new();
                for x in v {
                    let r_b = ByteArray::base64_decode(&x).map_err(A::Error::custom)?;
                    inner_vec.push(r_b.into_mp_integer());
                }
                vec.push(inner_vec.to_owned());
            }
            Ok(vec)
        }
    }
    deserializer.deserialize_seq(Visitor)
}
