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
    ech_0222::{CountingCircleRawData, ECH0222Data, VotingCardsInformation},
    election_event_configuration::{Authorization, ElectionEventConfigurationData},
};
use std::collections::HashMap;
use thiserror::Error;
use votation::VotationResult;

#[derive(Error, Debug)]
#[error(transparent)]
/// Error during the runner
pub struct ContestResultError(#[from] ContestResultErrorImpl);

#[derive(Error, Debug)]
enum ContestResultErrorImpl {
    #[error("Failed to convert {object} with id {id}")]
    ConversionError {
        id: String,
        object: &'static str,
        source: Box<ContestResultErrorImpl>,
    },
    #[error("Failed to import {import_object} for {goal_object} with id {id}")]
    ImportError {
        id: String,
        import_object: &'static str,
        goal_object: &'static str,
        source: Box<ContestResultErrorImpl>,
    },
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
    #[error("{object} with {id} not found in ECH0222 data")]
    ObjectNotFound { id: String, object: &'static str },
    #[error("No writeins for proportional elections are supported")]
    NoWriteInPropotional,
    #[error("Question id mismatch: expected {expected_question_id}, found {found_question_id}")]
    MismatchedQuestionId {
        expected_question_id: String,
        found_question_id: String,
    },
}

#[derive(Debug)]
pub struct ContestResult {
    pub contest_identification: String,
    pub contest_date: NaiveDate,
    pub counting_circle_result: HashMap<String, CountingCircleResult>,
}

#[derive(Debug)]
pub struct CountingCircleResult {
    pub counting_circle_id: String,
    pub counting_circle_name: String,
    pub voting_card_results: VotingCardsInformation,
    pub votation_results: HashMap<String, VotationResult>,
    pub election_group_results: HashMap<String, ElectionGroupResult>,
}

impl TryFrom<&ElectionEventConfigurationData> for ContestResult {
    type Error = ContestResultError;

    fn try_from(value: &ElectionEventConfigurationData) -> std::result::Result<Self, Self::Error> {
        Self::try_from_election_event_configuration_data(value)
            .map_err(|e| ContestResultError::from(e))
    }
}

impl ContestResult {
    fn try_from_election_event_configuration_data(
        value: &ElectionEventConfigurationData,
    ) -> Result<Self, ContestResultErrorImpl> {
        let votations_with_doi = value
            .contest
            .votes
            .iter()
            .map(|v| {
                VotationResult::try_from_vote(&v.vote)
                    .map(|r| (v.vote.domain_of_influence.clone(), r))
                    .map_err(|e| ContestResultErrorImpl::ConversionError {
                        id: v.vote.vote_identification.clone(),
                        object: "Votation",
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
                    .map_err(|e| ContestResultErrorImpl::ConversionError {
                        id: eg.election_group_identification.clone(),
                        object: "Election Group",
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
                    .map_err(|e| ContestResultErrorImpl::ConversionError {
                        id: auth.authorization_identification.clone(),
                        object: "Counting Circle",
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

    pub fn import_ech02222(&mut self, ech0222: &ECH0222Data) -> Result<(), ContestResultError> {
        self.import_ech02222_impl(ech0222)
            .map_err(|e| ContestResultError::from(e))
    }

    fn import_ech02222_impl(
        &mut self,
        ech0222: &ECH0222Data,
    ) -> Result<(), ContestResultErrorImpl> {
        for (cc_id, cc) in ech0222.raw_data.counting_circle_raw_data.iter() {
            let cc_result = self.counting_circle_result.get_mut(cc_id).ok_or(
                ContestResultErrorImpl::ObjectNotFound {
                    id: cc_id.clone(),
                    object: "Counting Circle",
                },
            )?;
            cc_result.import_counting_circle_raw_data(cc).map_err(|e| {
                ContestResultErrorImpl::ImportError {
                    id: cc_id.clone(),
                    goal_object: "Counting Circle Result",
                    import_object: "ECH0222 Counting Circle Raw Data",
                    source: Box::new(e),
                }
            })?;
        }
        Ok(())
    }
}

impl CountingCircleResult {
    fn new_with(
        auth: &Authorization,
        all_votations_with_doi: &[(String, VotationResult)],
        all_election_groups_with_doi: &[(String, ElectionGroupResult)],
    ) -> Result<Self, ContestResultErrorImpl> {
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
            s if s.is_empty() => Err(ContestResultErrorImpl::ObjectNotFound {
                id: auth.authorization_identification.clone(),
                object: "Counting Circle",
            }),
            s if s.len() > 1 => Err(ContestResultErrorImpl::ToManyCountingCirclesFound {
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
            voting_card_results: VotingCardsInformation::default(),
            votation_results: votations_results,
            election_group_results: election_group_results,
        })
    }

    fn import_counting_circle_raw_data(
        &mut self,
        cc_raw_data: &CountingCircleRawData,
    ) -> Result<(), ContestResultErrorImpl> {
        // Votation
        for (vote_id, vote_raw_data) in cc_raw_data.vote_raw_data.iter() {
            self.votation_results
                .get_mut(vote_id)
                .ok_or(ContestResultErrorImpl::ObjectNotFound {
                    id: vote_id.clone(),
                    object: "Votation",
                })?
                .import_vote_raw_data(vote_raw_data)
                .map_err(|e| ContestResultErrorImpl::ImportError {
                    id: vote_id.clone(),
                    goal_object: "Votation Result",
                    import_object: "ECH0222 Vote Raw Data",
                    source: Box::new(e),
                })?;
        }

        // Election group
        for eg_raw_data in cc_raw_data.election_group_ballot_raw_data.iter() {
            let eg_id = &eg_raw_data.election_group_identification;
            self.election_group_results
                .get_mut(eg_id)
                .ok_or(ContestResultErrorImpl::ObjectNotFound {
                    id: eg_id.clone(),
                    object: "Election Group",
                })?
                .import_election_group_raw_data(eg_raw_data)
                .map_err(|e| ContestResultErrorImpl::ImportError {
                    id: eg_id.clone(),
                    goal_object: "Election Group Result",
                    import_object: "ECH0222 Election Group Ballot Raw Data",
                    source: Box::new(e),
                })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_ev_verifier_lib::{
        VerifierDataDecode, ech_0222::ECH0222,
        election_event_configuration::ElectionEventConfiguration,
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

    #[test]
    fn test_import_ech0222() {
        let config_path = data_dir().join("configuration-anonymized.xml");
        println!("{:?}", config_path.canonicalize().unwrap().display());
        let eec_data =
            ElectionEventConfiguration::decode_xml(fs::read_to_string(&config_path).unwrap())
                .unwrap()
                .get_data()
                .unwrap();
        let mut results = ContestResult::try_from(eec_data.as_ref()).unwrap();
        let ech0222_path = data_dir().join("eCH-0222_v3-0_NE_20231124_TT05.xml");
        let ech0222_data = ECH0222::decode_xml(fs::read_to_string(&ech0222_path).unwrap())
            .unwrap()
            .get_data()
            .unwrap();
        let res_import = results.import_ech02222(&ech0222_data);
        assert!(res_import.is_ok(), "{:?}", res_import.err());
    }
}
