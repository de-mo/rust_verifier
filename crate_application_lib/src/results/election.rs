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

use rust_ev_verifier_lib::election_event_configuration::{
    Candidate, Election, ElectionGroupBallot, ElectionInformation, List,
};

use crate::results::EVotingResultErrorImpl;

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
    empty: usize,
}

#[derive(Debug, Clone)]
pub struct ProportionalElectionResult {
    list_results: HashMap<String, ListResult>,
    candidate_result: HashMap<String, CandidateResult>,
    empty: usize,
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
    ) -> Result<Self, EVotingResultErrorImpl> {
        let election_results = value
            .election_informations
            .iter()
            .map(|election| {
                let election_result = ElectionResult::try_from_election_information(election)?;
                Ok((election_result.election_id.clone(), election_result))
            })
            .collect::<Result<HashMap<_, _>, EVotingResultErrorImpl>>()?;
        Ok(Self {
            election_group_id: value.election_group_identification.clone(),
            election_results,
        })
    }
}

impl ElectionResult {
    pub(super) fn try_from_election_information(
        value: &ElectionInformation,
    ) -> Result<Self, EVotingResultErrorImpl> {
        let election_result = match value.election.type_of_election {
            1 => ElectionResultType::Proportional(
                ProportionalElectionResult::try_from_election_election_information(value)?,
            ),
            2 => ElectionResultType::Majority(
                MajorityElectionResult::try_from_election_information(value)?,
            ),
            n => {
                return Err(EVotingResultErrorImpl::InvalidElectionType {
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
}

impl MajorityElectionResult {
    pub(super) fn try_from_election_information(
        value: &ElectionInformation,
    ) -> Result<Self, EVotingResultErrorImpl> {
        Ok(Self {
            write_ins_allowed: value.election.write_ins_allowed,
            candidate_result: value
                .candidates
                .iter()
                .map(|candidate| {
                    let candidate_result = CandidateResult::try_from_candidate(candidate)?;
                    Ok((candidate_result.candidate_id.clone(), candidate_result))
                })
                .collect::<Result<HashMap<_, _>, EVotingResultErrorImpl>>()?,
            write_ins: vec![],
            empty: 0,
        })
    }
}

impl ProportionalElectionResult {
    pub(super) fn try_from_election_election_information(
        value: &ElectionInformation,
    ) -> Result<Self, EVotingResultErrorImpl> {
        Ok(Self {
            list_results: value
                .lists
                .iter()
                .map(|l| {
                    let list_result = ListResult::try_from_list(l)?;
                    Ok((list_result.list_id.clone(), list_result))
                })
                .collect::<Result<HashMap<_, _>, EVotingResultErrorImpl>>()?,
            candidate_result: value
                .candidates
                .iter()
                .map(|candidate| {
                    let candidate_result = CandidateResult::try_from_candidate(candidate)?;
                    Ok((candidate_result.candidate_id.clone(), candidate_result))
                })
                .collect::<Result<HashMap<_, _>, EVotingResultErrorImpl>>()?,
            empty: 0,
        })
    }
}

impl CandidateResult {
    pub(super) fn try_from_candidate(value: &Candidate) -> Result<Self, EVotingResultErrorImpl> {
        Ok(Self {
            candidate_id: value.candidate_identification.clone(),
            candidate_number: value.reference_on_position.clone(),
            candidate_name: format!("{} {}", value.family_name, value.call_name),
            result: 0,
        })
    }
}

impl ListResult {
    pub(super) fn try_from_list(value: &List) -> Result<Self, EVotingResultErrorImpl> {
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
                .collect::<Result<HashMap<_, _>, EVotingResultErrorImpl>>()?,
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
                .collect::<Result<HashMap<_, _>, EVotingResultErrorImpl>>()?,
            additional_vote: 0,
        })
    }
}
