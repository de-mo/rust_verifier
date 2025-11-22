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

use rust_ev_verifier_lib::{
    ech_0222::{BallotCasted, BallotRawData, QuestionRawData, VoteRawData},
    election_event_configuration::{
        Answer, Ballot, StandardOrVariantBallot, StandardQuestion, Vote,
    },
};
use std::collections::HashMap;

use crate::results::ContestResultErrorImpl;

#[derive(Debug, Clone)]
pub struct VotationResult {
    pub vote_id: String,
    pub vote_position: usize,
    pub ballot_results: HashMap<String, BallotResult>,
}

#[derive(Debug, Clone)]
pub enum BallotResultType {
    Simple(QuestionResult),
    Variant(VariantBallotResult),
}

#[derive(Debug, Clone)]
pub struct BallotResult {
    ballot_id: String,
    ballot_position: usize,
    results: BallotResultType,
}

#[derive(Debug, Clone)]
pub struct VariantBallotResult {
    standard_quesitons: Vec<QuestionResult>,
    tie_break_questions: Vec<QuestionResult>,
}

#[derive(Debug, Clone)]
pub struct QuestionResult {
    question_id: String,
    answer_1: AnswerResult,
    answer_2: AnswerResult,
    empty: usize,
}

#[derive(Debug, Clone)]
pub struct AnswerResult {
    answer_id: String,
    answer_text: HashMap<String, String>,
    result: usize,
}

impl VotationResult {
    pub(super) fn try_from_vote(value: &Vote) -> Result<Self, ContestResultErrorImpl> {
        let ballot_results = value
            .ballots
            .iter()
            .map(|ballot| {
                let ballot_result = BallotResult::try_from_ballot(ballot)?;
                Ok((ballot_result.ballot_id.clone(), ballot_result))
            })
            .collect::<Result<HashMap<_, _>, ContestResultErrorImpl>>()?;
        Ok(Self {
            vote_id: value.vote_identification.clone(),
            vote_position: value.vote_position.clone(),
            ballot_results,
        })
    }

    pub(super) fn import_vote_raw_data(
        &mut self,
        vote_raw_data: &VoteRawData,
    ) -> Result<(), ContestResultErrorImpl> {
        for ballot in vote_raw_data.ballot_raw_data.iter() {
            self.ballot_results
                .get_mut(&ballot.electronic_ballot_identification)
                .ok_or(ContestResultErrorImpl::ObjectNotFound {
                    id: ballot.electronic_ballot_identification.clone(),
                    object: "Ballot",
                })?
                .results
                .import_question_raw_data(&ballot.ballot_casted.question_raw_data.as_slice())
                .map_err(|e| ContestResultErrorImpl::ImportError {
                    id: ballot.electronic_ballot_identification.clone(),
                    import_object: "Ballot Casted",
                    goal_object: "BallotResult",
                    source: Box::new(e),
                })?;
        }
        Ok(())
    }
}

impl BallotResult {
    pub(super) fn try_from_ballot(value: &Ballot) -> Result<Self, ContestResultErrorImpl> {
        Ok(Self {
            ballot_id: value.ballot_identification.clone(),
            ballot_position: value.ballot_position,
            results: BallotResultType::try_from_ballot(&value.standard_or_variant_ballot)?,
        })
    }
}

impl BallotResultType {
    pub(super) fn try_from_ballot(
        value: &StandardOrVariantBallot,
    ) -> Result<Self, ContestResultErrorImpl> {
        match value {
            StandardOrVariantBallot::StandardBallot(standard_ballot) => Ok(Self::Simple(
                QuestionResult::try_from_ballot(standard_ballot)?,
            )),
            StandardOrVariantBallot::VariantBallot(variant_ballot) => {
                Ok(Self::Variant(VariantBallotResult {
                    standard_quesitons: variant_ballot
                        .standard_questions
                        .iter()
                        .map(|q| QuestionResult::try_from_ballot(q))
                        .collect::<Result<_, _>>()?,
                    tie_break_questions: variant_ballot
                        .tie_break_questions
                        .iter()
                        .map(|q| QuestionResult::try_from_ballot(q))
                        .collect::<Result<_, _>>()?,
                }))
            }
        }
    }

    pub(super) fn import_question_raw_data(
        &mut self,
        question_raw_data: &[QuestionRawData],
    ) -> Result<(), ContestResultErrorImpl> {
        for question in question_raw_data.iter() {
            match self {
                BallotResultType::Simple(question_result) => {
                    if question.question_identification != question.question_identification {
                        return Err(ContestResultErrorImpl::MismatchedQuestionId {
                            expected_question_id: question_result.question_id.clone(),
                            found_question_id: question.question_identification.clone(),
                        });
                    }
                    question_result.import_question_raw_data(question)?
                }
                BallotResultType::Variant(variant_result) => {
                    let mut q = variant_result
                        .standard_quesitons
                        .iter_mut()
                        .find(|q| q.question_id == question.question_identification);
                    if q.is_none() {
                        q = variant_result
                            .tie_break_questions
                            .iter_mut()
                            .find(|q| q.question_id == question.question_identification);
                    }
                    if q.is_none() {
                        return Err(ContestResultErrorImpl::ObjectNotFound {
                            id: question.question_identification.clone(),
                            object: "Question",
                        });
                    }
                    q.unwrap().import_question_raw_data(question)?;
                }
            };
        }
        Ok(())
    }
}

impl QuestionResult {
    pub(super) fn try_from_ballot(
        value: &StandardQuestion,
    ) -> Result<Self, ContestResultErrorImpl> {
        let answer_1 = AnswerResult::try_from_ballot(
            value
                .answers
                .iter()
                .find(|ans| ans.answer_position == 1)
                .ok_or(ContestResultErrorImpl::MissingAnswer {
                    answer_position: 1,
                    question_id: value.question_identification.clone(),
                })?,
        )?;
        let answer_2 = AnswerResult::try_from_ballot(
            value
                .answers
                .iter()
                .find(|ans| ans.answer_position == 2)
                .ok_or(ContestResultErrorImpl::MissingAnswer {
                    answer_position: 2,
                    question_id: value.question_identification.clone(),
                })?,
        )?;
        Ok(Self {
            question_id: value.question_identification.clone(),
            answer_1,
            answer_2,
            empty: 0,
        })
    }

    pub(super) fn import_question_raw_data(
        &mut self,
        question_raw_data: &QuestionRawData,
    ) -> Result<(), ContestResultErrorImpl> {
        match question_raw_data.casted.as_ref() {
            Some(casted) => match casted.casted_vote {
                1 => {
                    self.answer_1.result += 1;
                }
                2 => {
                    self.answer_2.result += 1;
                }
                3 => {
                    self.empty += 1;
                }
                _ => (),
            },
            None => (),
        }
        Ok(())
    }
}

impl AnswerResult {
    pub(super) fn try_from_ballot(value: &Answer) -> Result<Self, ContestResultErrorImpl> {
        Ok(Self {
            answer_id: value.answer_identification.clone(),
            answer_text: value
                .answer_info
                .iter()
                .map(|info| (info.language.clone(), info.answer.clone()))
                .collect(),
            result: 0,
        })
    }
}
