pub mod control_component_ballot_box_payload;
pub mod e_voting_decrypt;
pub mod ech_0110;
pub mod ech_0222;
pub mod tally_component_shuffle_payload;
pub mod tally_component_votes_payload;

use self::{
    control_component_ballot_box_payload::ControlComponentBallotBoxPayload,
    e_voting_decrypt::EVotingDecrypt, ech_0110::ECH0110, ech_0222::ECH0222,
    tally_component_shuffle_payload::TallyComponentShufflePayload,
    tally_component_votes_payload::TallyComponentVotesPayload,
};
use super::{error::DeserializeError, VerifierDataDecode, VerifierTallyDataTrait};
use crate::file_structure::FileType;
use enum_kinds::EnumKind;

#[derive(Clone, EnumKind)]
#[enum_kind(VerifierTallyDataType)]
pub enum VerifierTallyData {
    EVotingDecrypt(EVotingDecrypt),
    ECH0110(ECH0110),
    ECH0222(ECH0222),
    TallyComponentVotesPayload(TallyComponentVotesPayload),
    TallyComponentShufflePayload(TallyComponentShufflePayload),
    ControlComponentBallotBoxPayload(ControlComponentBallotBoxPayload),
}

impl VerifierTallyDataType {
    pub fn get_file_type(&self) -> FileType {
        match self {
            Self::EVotingDecrypt => FileType::Xml,
            Self::ECH0110 => FileType::Xml,
            Self::ECH0222 => FileType::Xml,
            Self::TallyComponentVotesPayload => FileType::Json,
            Self::TallyComponentShufflePayload => FileType::Json,
            Self::ControlComponentBallotBoxPayload => FileType::Json,
        }
    }

    /// Read from String as json or xml
    ///
    /// All the types have to implement the trait [VerifierDataDecode]
    pub fn verifier_data_from_file(
        &self,
        s: &String,
    ) -> Result<VerifierTallyData, DeserializeError> {
        match self {
            VerifierTallyDataType::EVotingDecrypt => {
                EVotingDecrypt::from_string(s, &self.get_file_type())
                    .map(|r| VerifierTallyData::EVotingDecrypt(r))
            }
            VerifierTallyDataType::ECH0110 => ECH0110::from_string(s, &self.get_file_type())
                .map(|r| VerifierTallyData::ECH0110(r)),
            VerifierTallyDataType::ECH0222 => ECH0222::from_string(s, &self.get_file_type())
                .map(|r| VerifierTallyData::ECH0222(r)),
            VerifierTallyDataType::TallyComponentVotesPayload => {
                TallyComponentVotesPayload::from_string(s, &self.get_file_type())
                    .map(|r| VerifierTallyData::TallyComponentVotesPayload(r))
            }
            VerifierTallyDataType::TallyComponentShufflePayload => {
                TallyComponentShufflePayload::from_string(s, &self.get_file_type())
                    .map(|r| VerifierTallyData::TallyComponentShufflePayload(r))
            }
            VerifierTallyDataType::ControlComponentBallotBoxPayload => {
                ControlComponentBallotBoxPayload::from_string(s, &self.get_file_type())
                    .map(|r| VerifierTallyData::ControlComponentBallotBoxPayload(r))
            }
        }
    }
}

impl VerifierTallyDataTrait for VerifierTallyData {
    fn e_voting_decrypt(&self) -> Option<&EVotingDecrypt> {
        if let VerifierTallyData::EVotingDecrypt(d) = self {
            return Some(d);
        }
        None
    }

    fn ech_0110(&self) -> Option<&ECH0110> {
        if let VerifierTallyData::ECH0110(d) = self {
            return Some(d);
        }
        None
    }

    fn ech_0222(&self) -> Option<&ECH0222> {
        if let VerifierTallyData::ECH0222(d) = self {
            return Some(d);
        }
        None
    }
    fn tally_component_votes_payload(&self) -> Option<&TallyComponentVotesPayload> {
        if let VerifierTallyData::TallyComponentVotesPayload(d) = self {
            return Some(d);
        }
        None
    }
    fn tally_component_shuffle_payload(&self) -> Option<&TallyComponentShufflePayload> {
        if let VerifierTallyData::TallyComponentShufflePayload(d) = self {
            return Some(d);
        }
        None
    }
    fn control_component_ballot_box_payload(&self) -> Option<&ControlComponentBallotBoxPayload> {
        if let VerifierTallyData::ControlComponentBallotBoxPayload(d) = self {
            return Some(d);
        }
        None
    }
}
