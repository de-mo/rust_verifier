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

use std::hash::Hash;

use crate::data_structures::{
    context::election_event_configuration::{
        ElectionGroupBallot, ElectionInformation, TypeOfIdInElection,
    },
    tally::ech_0222::ECH0222CalculatedErrorImpl,
    xml::ElementChildren,
};
use roxmltree::Node;

#[derive(Debug, Clone)]
pub struct ElectionGroupBallotRawData {
    pub election_group_identification: String,
    pub election_raw_data: Vec<ElectionRawData>,
}

#[derive(Debug, Clone, Hash)]
pub struct ElectionRawData {
    pub election_identification: String,
    pub list_raw_data: Option<ListRawData>,
    pub ballot_positions: Vec<BallotPosition>,
    pub is_unchanged_ballot: Option<bool>,
}

#[derive(Debug, Clone, Hash)]
pub struct ListRawData {
    pub list_identification: String,
}

#[derive(Debug, Clone, Hash)]
pub struct BallotPosition(pub CandidateOrIsEmpty);

#[derive(Debug, Clone, Hash)]
pub enum CandidateOrIsEmpty {
    Candidate(CandidateEnum),
    IsEmpty(bool),
}

#[derive(Debug, Clone, Hash)]
pub enum CandidateEnum {
    Candidate {
        candidate_identification: String,
        candidate_reference_on_position: String,
    },
    WriteIn(String),
}

#[derive(Debug)]
/// Structure containung the positions of the decoded vote and the associated write-in
pub struct DecodedVoteWithWriteIn<'a> {
    pub first_position: &'a str,
    pub second_position: &'a str,
    pub third_position: Option<&'a str>,
    pub write_in: Option<&'a str>,
}

impl ElectionGroupBallotRawData {
    pub(super) fn from_node(node: &Node) -> Self {
        Self {
            election_group_identification: node
                .first_element_child()
                .unwrap()
                .text()
                .unwrap()
                .to_string(),
            election_raw_data: node
                .element_children()
                .filter(|n| n.has_tag_name("electionRawData"))
                .map(|n| ElectionRawData::from_node(&n))
                .collect::<Vec<_>>(),
        }
    }

    pub(super) fn collect_election_group_ballot_raw_data(
        relevant_election_groups: &[&ElectionGroupBallot],
        decoded_votes: &[Vec<String>],
        write_ins: &[Vec<String>],
    ) -> Result<Vec<ElectionGroupBallotRawData>, ECH0222CalculatedErrorImpl> {
        let mut res = vec![];
        for (i, (votes, write_ins)) in decoded_votes.iter().zip(write_ins.iter()).enumerate() {
            res.append(
                &mut Self::collect_election_group_ballot_raw_data_for_one_ballot(
                    relevant_election_groups,
                    votes,
                    write_ins,
                )
                .map_err(|e| ECH0222CalculatedErrorImpl::ErrorOnDecodedVote {
                    i,
                    source: Box::new(e),
                })?,
            );
        }
        Ok(res)
    }

    fn collect_election_group_ballot_raw_data_for_one_ballot(
        relevant_election_groups: &[&ElectionGroupBallot],
        decoded_votes: &[String],
        write_ins: &[String],
    ) -> Result<Vec<ElectionGroupBallotRawData>, ECH0222CalculatedErrorImpl> {
        let write_ins_ids = relevant_election_groups
            .iter()
            .flat_map(|eg| eg.write_in_position_ids())
            .collect::<Vec<_>>();
        let mut write_ins_iter = write_ins.iter();
        let decoded_votes_with_write_ins = decoded_votes
            .iter()
            .enumerate()
            .map(
                |(i, dv)| -> Result<DecodedVoteWithWriteIn, ECH0222CalculatedErrorImpl> {
                    let mut split = dv.split('|');
                    let first_position = split.next().unwrap();
                    let second_position =
                        split
                            .next()
                            .ok_or(ECH0222CalculatedErrorImpl::ErrorOnDecodedVote {
                                i,
                                source: Box::new(
                                    ECH0222CalculatedErrorImpl::MalformedDecodedVote {
                                        decoded_vote: dv.clone(),
                                        msg: "Missing second element",
                                    },
                                ),
                            })?;
                    let third_position = split.next();
                    if write_ins_ids.contains(&second_position) {
                        Ok(DecodedVoteWithWriteIn {
                            first_position,
                            second_position,
                            third_position,
                            write_in: write_ins_iter.next().map(|wi| wi.as_str()),
                        })
                    } else {
                        Ok(DecodedVoteWithWriteIn {
                            first_position,
                            second_position,
                            third_position,
                            write_in: None,
                        })
                    }
                },
            )
            .collect::<Result<Vec<_>, _>>()?;
        relevant_election_groups
            .iter()
            .map(|eg| {
                match eg
                    .election_informations
                    .iter()
                    .map(|el| {
                        ElectionRawData::new_with(
                            el,
                            decoded_votes_with_write_ins
                                .iter()
                                .filter(|&dvwi| {
                                    dvwi.first_position == el.election.election_identification
                                })
                                .collect::<Vec<_>>()
                                .as_slice(),
                        )
                    })
                    .collect::<Result<_, _>>()
                {
                    Ok(res) => Ok(Self {
                        election_group_identification: eg.election_group_identification.clone(),
                        election_raw_data: res,
                    }),
                    Err(e) => Err(e),
                }
            })
            .collect::<Result<_, _>>()
    }

    pub(super) fn difference_found_text(&self) -> String {
        format!(
            "electionGroupIdentification: {}\n election: {:#?}",
            self.election_group_identification, &self.election_raw_data[0]
        )
    }
}

impl Hash for ElectionGroupBallotRawData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.election_group_identification.hash(state);
        let election_raw_data_sorted = {
            let mut erd = self.election_raw_data.iter().collect::<Vec<_>>();
            erd.sort_by(|e1, e2| e1.election_identification.cmp(&e2.election_identification));
            erd
        };
        election_raw_data_sorted.hash(state);
    }
}

impl ElectionRawData {
    pub(super) fn from_node(node: &Node) -> Self {
        Self {
            election_identification: node
                .first_element_child()
                .unwrap()
                .text()
                .unwrap()
                .to_string(),
            list_raw_data: node
                .element_children()
                .find(|n| n.has_tag_name("listRawData"))
                .map(|n| ListRawData::from_node(&n)),
            ballot_positions: node
                .element_children()
                .filter(|n| n.has_tag_name("ballotPosition"))
                .map(|n| BallotPosition::from_node(&n))
                .collect::<Vec<_>>(),
            is_unchanged_ballot: node
                .element_children()
                .find(|n| n.has_tag_name("isUnchangedBallot"))
                .map(|n| n.text().unwrap() == "true"),
        }
    }

    pub(super) fn new_with(
        election_information: &ElectionInformation,
        relevant_decode_votes_with_write_ins: &[&DecodedVoteWithWriteIn],
    ) -> Result<Self, ECH0222CalculatedErrorImpl> {
        let list_raw_data = relevant_decode_votes_with_write_ins
            .iter()
            .find(|&dvwi| election_information.is_list(dvwi.second_position))
            .map(|dvwi| ListRawData::new_with(dvwi.second_position))
            .transpose()?;
        let ballot_positions: Vec<BallotPosition> = relevant_decode_votes_with_write_ins
            .iter()
            .filter(|dvwi| !election_information.is_list(dvwi.second_position))
            .map(|dvwi| {
                BallotPosition::new_with(
                    election_information,
                    dvwi,
                    list_raw_data
                        .as_ref()
                        .map(|l| l.list_identification.as_str()),
                )
            })
            .collect::<Result<_, _>>()?;
        let is_unchanged_ballot = match list_raw_data.as_ref() {
            Some(l_id) => election_information
                .is_unchanged_list(
                    &l_id.list_identification,
                    ballot_positions
                        .iter()
                        .filter_map(|bp| {
                            if let CandidateOrIsEmpty::Candidate(CandidateEnum::Candidate {
                                candidate_identification,
                                candidate_reference_on_position: _,
                            }) = &bp.0
                            {
                                return Some(candidate_identification.as_str());
                            };
                            None
                        })
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
                .unwrap_or(false),
            None => ballot_positions
                .iter()
                .all(|bp| matches!(&bp.0, CandidateOrIsEmpty::IsEmpty(_))),
        };
        Ok(Self {
            election_identification: election_information
                .election
                .election_identification
                .clone(),
            list_raw_data,
            ballot_positions,
            is_unchanged_ballot: Some(is_unchanged_ballot),
        })
    }
}

impl ListRawData {
    pub(super) fn from_node(node: &Node) -> Self {
        Self {
            list_identification: node
                .first_element_child()
                .unwrap()
                .text()
                .unwrap()
                .to_string(),
        }
    }

    pub(super) fn new_with(list_identification: &str) -> Result<Self, ECH0222CalculatedErrorImpl> {
        Ok(Self {
            list_identification: list_identification.to_string(),
        })
    }
}

impl BallotPosition {
    pub(super) fn from_node(node: &Node) -> Self {
        Self(CandidateOrIsEmpty::from_node(
            &node.element_children().next().unwrap(),
        ))
    }

    pub(super) fn new_with(
        election_information: &ElectionInformation,
        relevant_decode_votes_with_write_ins: &DecodedVoteWithWriteIn,
        list_id: Option<&str>,
    ) -> Result<Self, ECH0222CalculatedErrorImpl> {
        Ok(Self(CandidateOrIsEmpty::new_wtih(
            election_information,
            relevant_decode_votes_with_write_ins,
            list_id,
        )?))
    }
}

impl CandidateOrIsEmpty {
    pub(super) fn from_node(node: &Node) -> Self {
        match node.has_tag_name("isEmpty") {
            true => Self::IsEmpty(true),
            false => Self::Candidate(CandidateEnum::from_node(node)),
        }
    }

    pub(super) fn new_wtih(
        election_information: &ElectionInformation,
        relevant_decode_votes_with_write_ins: &DecodedVoteWithWriteIn,
        list_id: Option<&str>,
    ) -> Result<Self, ECH0222CalculatedErrorImpl> {
        if let Some(write_in) = relevant_decode_votes_with_write_ins.write_in {
            return Ok(Self::Candidate(CandidateEnum::WriteIn(
                write_in.to_string(),
            )));
        }
        match election_information.type_of_id(
            relevant_decode_votes_with_write_ins.second_position,
            relevant_decode_votes_with_write_ins
                .third_position
                .map(|s| s.parse::<usize>().unwrap()),
        ) {
            Some(t) => match t {
                TypeOfIdInElection::List { id: _ } => {
                    Err(ECH0222CalculatedErrorImpl::UnexpectedList(
                        list_id.unwrap().to_string(),
                        "CandidateOrIsEmpty::new_wtih",
                    ))
                }
                TypeOfIdInElection::Candidate {
                    id,
                    candidate_reference_on_position,
                } => Ok(Self::Candidate(CandidateEnum::Candidate {
                    candidate_identification: id.to_string(),
                    candidate_reference_on_position: candidate_reference_on_position.to_string(),
                })),
                TypeOfIdInElection::EmptyPosition { id: _ } => Ok(Self::IsEmpty(true)),
                TypeOfIdInElection::WriteInPosition { id } => Err(
                    ECH0222CalculatedErrorImpl::WriteInOptionWithoutVote(id.to_string()),
                ),
            },
            None => Err(ECH0222CalculatedErrorImpl::TypeOfIdNone {
                id: relevant_decode_votes_with_write_ins
                    .second_position
                    .to_string(),
                list_id: list_id.map(|s| s.to_string()),
            }),
        }
    }
}

impl CandidateEnum {
    pub(super) fn from_node(node: &Node) -> Self {
        let first_element = node.first_element_child().unwrap();
        let first_element_text_str = first_element.text().unwrap();
        match first_element.has_tag_name("writeIn") {
            true => Self::WriteIn(first_element_text_str.to_string()),
            false => Self::Candidate {
                candidate_identification: first_element_text_str.to_string(),
                candidate_reference_on_position: first_element
                    .next_sibling_element()
                    .unwrap()
                    .text()
                    .unwrap()
                    .to_string(),
            },
        }
    }
}
