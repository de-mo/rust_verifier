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
//

mod election;
mod votation;

use chrono::NaiveDate;
use election::ElectionGroupResult;
use rust_ev_verifier_lib::{
    ech_0222::ECH0222Data,
    election_event_configuration::{
        Authorization, ElectionEventConfigurationData, ElectionGroupBallot,
    },
};
use std::collections::HashMap;
use thiserror::Error;
use votation::VotationResult;

#[derive(Error, Debug)]
#[error(transparent)]
/// Error during the runner
pub struct EVotingResultError(#[from] EVotingResultErrorImpl);

#[derive(Error, Debug)]
enum EVotingResultErrorImpl {
    #[error("Failed to convert vote with id {vote_id}")]
    VoteConversionError {
        vote_id: String,
        source: Box<EVotingResultErrorImpl>,
    },
    #[error("Failed to convert election group with id {eg_id}")]
    ElectionConversionError {
        eg_id: String,
        source: Box<EVotingResultErrorImpl>,
    },
    #[error("Failed to convert counting circle with id {cc_id}")]
    CCConversionError {
        cc_id: String,
        source: Box<EVotingResultErrorImpl>,
    },
    #[error("No counting circle found for authorization id {auth_id}")]
    NoCountingCircleFound { auth_id: String },
    #[error("Multiple counting circles found for authorization id {auth_id}")]
    ToManyCountingCirclesFound { auth_id: String },
    #[error("Missing answer with position {answer_position} for question with id {question_id}")]
    MissingAnswer {
        answer_position: usize,
        question_id: String,
    },
    #[error(
        "Invalid election type {election_type} for election with id {election_id}. Only 1 and 2 are accepted"
    )]
    InvalidElectionType {
        election_type: usize,
        election_id: String,
    },
}

#[derive(Debug)]
pub struct ContestResult {
    contest_identification: String,
    contest_date: NaiveDate,
    counting_circle_result: HashMap<String, CountingCircleResult>,
}

#[derive(Debug)]
pub struct CountingCircleResult {
    counting_circle_id: String,
    counting_circle_name: String,
    votation_results: HashMap<String, VotationResult>,
    election_group_results: HashMap<String, ElectionGroupResult>,
}

impl TryFrom<&ElectionEventConfigurationData> for ContestResult {
    type Error = EVotingResultError;

    fn try_from(value: &ElectionEventConfigurationData) -> std::result::Result<Self, Self::Error> {
        Self::try_from_election_event_configuration_data(value)
            .map_err(|e| EVotingResultError::from(e))
    }
}

impl ContestResult {
    fn try_from_election_event_configuration_data(
        value: &ElectionEventConfigurationData,
    ) -> Result<Self, EVotingResultErrorImpl> {
        let votations_with_doi = value
            .contest
            .votes
            .iter()
            .map(|v| {
                VotationResult::try_from_vote(&v.vote)
                    .map(|r| (v.vote.domain_of_influence.clone(), r))
                    .map_err(|e| EVotingResultErrorImpl::VoteConversionError {
                        vote_id: v.vote.vote_identification.clone(),
                        source: Box::new(e),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let election_groups_with_doi = value
            .contest
            .election_groups
            .iter()
            .map(|eg| {
                ElectionGroupResult::try_from_election_group_ballot(&eg)
                    .map(|r| (eg.domain_of_influence.clone(), r))
                    .map_err(|e| EVotingResultErrorImpl::ElectionConversionError {
                        eg_id: eg.election_group_identification.clone(),
                        source: Box::new(e),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let counting_circle_result = value
            .authorizations
            .iter()
            .map(|auth| {
                CountingCircleResult::new_with(auth, &votations_with_doi, &election_groups_with_doi)
                    .map(|r| (r.counting_circle_id.clone(), r))
                    .map_err(|e| EVotingResultErrorImpl::CCConversionError {
                        cc_id: auth.authorization_identification.clone(),
                        source: Box::new(e),
                    })
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        Ok(Self {
            contest_identification: value.contest.contest_identification.clone(),
            contest_date: value.contest.contest_date.clone(),
            counting_circle_result,
        })
    }

    pub fn import_ballots(&mut self, ech0222: &ECH0222Data) -> Result<(), EVotingResultError> {
        self.import_ballots_impl(ech0222)
            .map_err(|e| EVotingResultError::from(e))
    }

    fn import_ballots_impl(&self, ech0222: &ECH0222Data) -> Result<(), EVotingResultErrorImpl> {
        todo!()
    }
}

impl CountingCircleResult {
    fn new_with(
        auth: &Authorization,
        all_votations_with_doi: &[(String, VotationResult)],
        all_election_groups_with_doi: &[(String, ElectionGroupResult)],
    ) -> Result<Self, EVotingResultErrorImpl> {
        let (dois, mut cc_infos): (Vec<_>, Vec<_>) = auth
            .authorization_object
            .iter()
            .map(|o| {
                (
                    &o.domain_of_influence.domain_of_influence_identification,
                    &o.counting_circle,
                )
            })
            .unzip();
        cc_infos.sort_by(|cc1, cc2| {
            cc1.counting_circle_identification
                .cmp(&cc2.counting_circle_identification)
        });
        cc_infos.dedup_by(|cc1, cc2| {
            cc1.counting_circle_identification == cc2.counting_circle_identification
        });
        let (counting_circle_id, counting_circle_name) = match cc_infos.as_slice() {
            s if s.is_empty() => Err(EVotingResultErrorImpl::NoCountingCircleFound {
                auth_id: auth.authorization_identification.clone(),
            }),
            s if s.len() > 1 => Err(EVotingResultErrorImpl::ToManyCountingCirclesFound {
                auth_id: auth.authorization_identification.clone(),
            }),
            s => Ok((
                s[0].counting_circle_identification.clone(),
                s[0].counting_circle_name.clone(),
            )),
        }?;

        let votations_results = all_votations_with_doi
            .iter()
            .filter(|(doi, _)| dois.contains(&doi))
            .map(|(_, vr)| (vr.vote_id.clone(), vr.clone()))
            .collect::<HashMap<_, _>>();

        let election_group_results = all_election_groups_with_doi
            .iter()
            .filter(|(doi, _)| dois.contains(&doi))
            .map(|(_, egr)| (egr.election_group_id.clone(), egr.clone()))
            .collect::<HashMap<_, _>>();

        Ok(Self {
            counting_circle_id,
            counting_circle_name,
            votation_results: votations_results,
            election_group_results: election_group_results,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_ev_verifier_lib::{
        VerifierDataDecode,
        election_event_configuration::{
            ElectionEventConfiguration, ElectionEventConfigurationData,
        },
    };
    use std::{fs, path::PathBuf};

    fn data_dir() -> PathBuf {
        PathBuf::from(".").join("test_data")
    }

    #[test]
    fn test_contest_result_from_eec_data() {
        let config_path = data_dir().join("configuration-anonymized.xml");
        println!("{:?}", config_path.canonicalize().unwrap().display());
        let eec_data =
            ElectionEventConfiguration::decode_xml(fs::read_to_string(&config_path).unwrap())
                .unwrap()
                .get_data()
                .unwrap();
        let result = ContestResult::try_from(eec_data.as_ref());
        assert!(result.is_ok(), "{:?}", result.err());
    }
}
