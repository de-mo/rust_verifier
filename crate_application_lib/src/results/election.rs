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

use std::collections::HashMap;

use rust_ev_verifier_lib::{
    ech_0222::{CandidateEnum, CandidateOrIsEmpty, ElectionGroupBallotRawData, ElectionRawData},
    election_event_configuration::{Candidate, ElectionGroupBallot, ElectionInformation, List},
};
use tracing::field::Empty;

use crate::results::ContestResultErrorImpl;

#[derive(Debug, Clone)]
pub struct ElectionGroupResult {
    pub election_group_id: String,
    election_results: HashMap<String, ElectionResult>,
}

#[derive(Debug, Clone)]
pub struct ElectionResult {
    election_id: String,
    election_result: ElectionResultType,
}

#[derive(Debug, Clone)]
pub enum ElectionResultType {
    Majority(MajorityElectionResult),
    Proportional(ProportionalElectionResult),
}

#[derive(Debug, Clone)]
pub struct MajorityElectionResult {
    write_ins_allowed: bool,
    candidate_result: HashMap<String, CandidateResult>,
    write_ins: Vec<String>,
    empty_positions: usize,
    empty_ballots: usize,
}

#[derive(Debug, Clone)]
pub struct ProportionalElectionResult {
    emtpy_list_id: String,
    list_results: HashMap<String, ListResult>,
    candidate_result: HashMap<String, CandidateResult>,
    empty_ballots: usize,
}

#[derive(Debug, Clone)]
pub struct CandidateResult {
    candidate_id: String,
    candidate_number: String,
    candidate_name: String,
    result: usize,
}

#[derive(Debug, Clone)]
pub struct CandidateForListResult {
    candidate_id: String,
    candidate_reference_on_pos: String,
}

#[derive(Debug, Clone)]
pub struct ListResult {
    list_id: String,
    list_number: String,
    list_text: HashMap<String, String>,
    candidates: HashMap<String, CandidateForListResult>,
    additional_vote: usize,
}

impl ElectionGroupResult {
    pub(super) fn try_from_election_group_ballot(
        value: &ElectionGroupBallot,
    ) -> Result<Self, ContestResultErrorImpl> {
        let election_results = value
            .election_informations
            .iter()
            .map(|election| {
                let election_result = ElectionResult::try_from_election_information(election)?;
                Ok((election_result.election_id.clone(), election_result))
            })
            .collect::<Result<HashMap<_, _>, ContestResultErrorImpl>>()?;
        Ok(Self {
            election_group_id: value.election_group_identification.clone(),
            election_results,
        })
    }

    pub(super) fn import_election_group_raw_data(
        &mut self,
        eg_raw_data: &ElectionGroupBallotRawData,
    ) -> Result<(), ContestResultErrorImpl> {
        for el_raw_data in &eg_raw_data.election_raw_data {
            if let Some(election_result) = self
                .election_results
                .get_mut(&el_raw_data.election_identification)
            {
                election_result.import_election_raw_data(el_raw_data)?;
            } else {
                return Err(ContestResultErrorImpl::ObjectNotFound {
                    id: el_raw_data.election_identification.clone(),
                    object: "Election",
                });
            }
        }
        Ok(())
    }
}

impl ElectionResult {
    pub(super) fn try_from_election_information(
        value: &ElectionInformation,
    ) -> Result<Self, ContestResultErrorImpl> {
        let election_result = match value.election.type_of_election {
            1 => ElectionResultType::Proportional(
                ProportionalElectionResult::try_from_election_election_information(value)?,
            ),
            2 => ElectionResultType::Majority(
                MajorityElectionResult::try_from_election_information(value)?,
            ),
            n => {
                return Err(ContestResultErrorImpl::InvalidElectionType {
                    election_type: n,
                    election_id: value.election.election_identification.clone(),
                });
            }
        };
        Ok(Self {
            election_id: value.election.election_identification.clone(),
            election_result,
        })
    }

    pub(super) fn import_election_raw_data(
        &mut self,
        el_raw_data: &ElectionRawData,
    ) -> Result<(), ContestResultErrorImpl> {
        match &mut self.election_result {
            ElectionResultType::Majority(majority_result) => {
                majority_result.import_election_raw_data(el_raw_data)
            }
            ElectionResultType::Proportional(proportional_result) => {
                proportional_result.import_election_raw_data(el_raw_data)
            }
        }
    }
}

impl MajorityElectionResult {
    pub(super) fn try_from_election_information(
        value: &ElectionInformation,
    ) -> Result<Self, ContestResultErrorImpl> {
        Ok(Self {
            write_ins_allowed: value.election.write_ins_allowed,
            candidate_result: value
                .candidates
                .iter()
                .map(|candidate| {
                    let candidate_result = CandidateResult::try_from_candidate(candidate)?;
                    Ok((candidate_result.candidate_id.clone(), candidate_result))
                })
                .collect::<Result<HashMap<_, _>, ContestResultErrorImpl>>()?,
            write_ins: vec![],
            empty_positions: 0,
            empty_ballots: 0,
        })
    }

    pub(super) fn import_election_raw_data(
        &mut self,
        el_raw_data: &ElectionRawData,
    ) -> Result<(), ContestResultErrorImpl> {
        let mut nb_empty_positions = 0;
        for ballot_position in el_raw_data.ballot_positions.iter() {
            match &ballot_position.0 {
                CandidateOrIsEmpty::Candidate(CandidateEnum::Candidate {
                    candidate_identification: id,
                    candidate_reference_on_position: _,
                }) => {
                    self.candidate_result
                        .get_mut(id)
                        .ok_or(ContestResultErrorImpl::ObjectNotFound {
                            id: id.clone(),
                            object: "Candidate",
                        })?
                        .result += 1;
                }
                CandidateOrIsEmpty::Candidate(CandidateEnum::WriteIn(wi)) => {
                    self.write_ins.push(wi.clone());
                }
                CandidateOrIsEmpty::IsEmpty(_) => {
                    self.empty_positions += 1;
                    nb_empty_positions += 1;
                }
            }
        }
        if nb_empty_positions == el_raw_data.ballot_positions.len() {
            self.empty_ballots += 1;
        }
        Ok(())
    }
}

impl ProportionalElectionResult {
    pub(super) fn try_from_election_election_information(
        value: &ElectionInformation,
    ) -> Result<Self, ContestResultErrorImpl> {
        Ok(Self {
            emtpy_list_id: value.empty_list.list_identification.clone(),
            list_results: value
                .lists
                .iter()
                .map(|l| {
                    let list_result = ListResult::try_from_list(l)?;
                    Ok((list_result.list_id.clone(), list_result))
                })
                .collect::<Result<HashMap<_, _>, ContestResultErrorImpl>>()?,
            candidate_result: value
                .candidates
                .iter()
                .map(|candidate| {
                    let candidate_result = CandidateResult::try_from_candidate(candidate)?;
                    Ok((candidate_result.candidate_id.clone(), candidate_result))
                })
                .collect::<Result<HashMap<_, _>, ContestResultErrorImpl>>()?,
            empty_ballots: 0,
        })
    }

    pub(super) fn import_election_raw_data(
        &mut self,
        el_raw_data: &ElectionRawData,
    ) -> Result<(), ContestResultErrorImpl> {
        let list_id = el_raw_data
            .list_raw_data
            .as_ref()
            .map(|l| l.list_identification.as_str());
        let mut nb_empty_positions = 0;
        let mut is_empty_list = match list_id {
            Some(id) if id == self.emtpy_list_id => true,
            _ => false,
        };
        let mut list = match is_empty_list {
            false => match list_id {
                Some(id) => Some(self.list_results.get_mut(id).ok_or(
                    ContestResultErrorImpl::ObjectNotFound {
                        id: id.to_string(),
                        object: "Election",
                    },
                )?),
                None => None,
            },
            true => None,
        };
        for ballot_position in el_raw_data.ballot_positions.iter() {
            match &ballot_position.0 {
                CandidateOrIsEmpty::Candidate(CandidateEnum::Candidate {
                    candidate_identification: id,
                    candidate_reference_on_position: _,
                }) => {
                    self.candidate_result
                        .get_mut(id)
                        .ok_or(ContestResultErrorImpl::ObjectNotFound {
                            id: id.clone(),
                            object: "Candidate",
                        })?
                        .result += 1;
                }
                CandidateOrIsEmpty::Candidate(CandidateEnum::WriteIn(_)) => {
                    return Err(ContestResultErrorImpl::NoWriteInPropotional);
                }
                CandidateOrIsEmpty::IsEmpty(_) => {
                    if let Some(list) = &mut list {
                        list.additional_vote += 1;
                    }
                    if is_empty_list {
                        nb_empty_positions += 1;
                    }
                }
            }
        }
        if is_empty_list && nb_empty_positions == el_raw_data.ballot_positions.len() {
            self.empty_ballots += 1;
        }
        Ok(())
    }
}

impl CandidateResult {
    pub(super) fn try_from_candidate(value: &Candidate) -> Result<Self, ContestResultErrorImpl> {
        Ok(Self {
            candidate_id: value.candidate_identification.clone(),
            candidate_number: value.reference_on_position.clone(),
            candidate_name: format!("{} {}", value.family_name, value.call_name),
            result: 0,
        })
    }
}

impl ListResult {
    pub(super) fn try_from_list(value: &List) -> Result<Self, ContestResultErrorImpl> {
        Ok(Self {
            list_id: value.list_identification.clone(),
            list_number: value.list_indenture_number.clone(),
            list_text: value
                .list_description
                .list_description_info
                .iter()
                .map(|text_info| {
                    Ok((
                        text_info.language.clone(),
                        text_info.list_description.clone(),
                    ))
                })
                .collect::<Result<HashMap<_, _>, ContestResultErrorImpl>>()?,
            candidates: value
                .candidate_positions
                .iter()
                .map(|candidate| {
                    let candidate_for_list_result = CandidateForListResult {
                        candidate_id: candidate.candidate_identification.clone(),
                        candidate_reference_on_pos: candidate
                            .candidate_reference_on_position
                            .clone(),
                    };
                    Ok((
                        candidate_for_list_result.candidate_id.clone(),
                        candidate_for_list_result,
                    ))
                })
                .collect::<Result<HashMap<_, _>, ContestResultErrorImpl>>()?,
            additional_vote: 0,
        })
    }
}
