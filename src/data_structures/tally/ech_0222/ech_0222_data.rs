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

use roxmltree::Node;

use super::{
    ECH0222CalculatedError, ECH0222CalculatedErrorImpl, ECH0222Difference, ECh0222differencesTrait,
};
pub use super::{election::*, votations::*};
use crate::{
    data_structures::{
        context::{
            election_event_configuration::{
                ElectionEventConfigurationData, ElectionGroupBallot, Vote,
            },
            election_event_context_payload::ElectionEventContext,
        },
        tally::tally_component_votes_payload::TallyComponentVotesPayload,
        xml::ElementChildren,
    },
    file_structure::tally_directory::BBDirectoryTrait,
};
use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hash, Hasher},
};

#[derive(Debug, Clone)]
pub struct ECH0222Data {
    pub raw_data: RawData,
}

#[derive(Debug, Clone)]
pub struct RawData {
    pub contest_identification: String,
    pub counting_circle_raw_data: HashMap<String, CountingCircleRawData>,
}

#[derive(Debug, Clone)]
pub struct CountingCircleRawData {
    pub counting_circle_id: String,
    pub voting_cards_information: VotingCardsInformation,
    pub vote_raw_data: HashMap<String, VoteRawData>,
    pub election_group_ballot_raw_data: Vec<ElectionGroupBallotRawData>,
}

#[derive(Debug, Clone, Default)]
pub struct VotingCardsInformation {
    pub count_of_received_valid_voting_cards_total: usize,
    pub count_of_received_invalid_voting_cards_total: usize,
}

impl ECH0222Data {
    pub(super) fn from_node(node: &Node) -> Self {
        let raw_data_delivery_elt = node
            .element_children()
            .find(|n| n.has_tag_name("rawDataDelivery"))
            .unwrap();
        Self {
            raw_data: RawData::from_node(
                &raw_data_delivery_elt
                    .element_children()
                    .find(|n| n.has_tag_name("rawData"))
                    .unwrap(),
            ),
        }
    }

    /// Create the [ECH0222Data] from the [ElectionEventContext], [ElectionEventConfigurationData] and the Ballot boxes as slice of [BBDirectoryTrait]
    pub fn create_ech0222_data<B: BBDirectoryTrait>(
        election_event_context: &ElectionEventContext,
        election_event_configuration: &ElectionEventConfigurationData,
        tally_directory: &[B],
    ) -> Result<Self, ECH0222CalculatedError> {
        let mut raw_data =
            RawData::new(&election_event_configuration.contest.contest_identification);
        for bb in tally_directory.iter() {
            let tally_votes = bb.tally_component_votes_payload().map_err(|e| {
                ECH0222CalculatedErrorImpl::TallyVoteMissing {
                    bb_id: bb.name().to_string(),
                    source: Box::new(e),
                }
            })?;
            raw_data.append_ballot_box(
                election_event_context,
                election_event_configuration,
                &tally_votes,
            )?;
        }
        Ok(Self { raw_data })
    }
}

impl ECh0222differencesTrait for ECH0222Data {
    fn calculate_differences(&self, expected: &Self) -> Vec<ECH0222Difference> {
        self.raw_data.calculate_differences(&expected.raw_data)
    }
}

impl RawData {
    pub(super) fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        let contest_identification = children.next().unwrap().text().unwrap().to_string();
        let counting_circle_raw_data = children
            .map(|n| CountingCircleRawData::from_node(&n))
            .collect::<HashMap<_, _>>();
        Self {
            contest_identification,
            counting_circle_raw_data,
        }
    }

    pub(super) fn new(contest_identification: &str) -> Self {
        Self {
            contest_identification: contest_identification.to_string(),
            counting_circle_raw_data: HashMap::default(),
        }
    }

    pub(super) fn append_ballot_box(
        &mut self,
        election_event_context: &ElectionEventContext,
        election_event_configuration: &ElectionEventConfigurationData,
        ballot_box_votes: &TallyComponentVotesPayload,
    ) -> Result<(), ECH0222CalculatedErrorImpl> {
        let vcs = election_event_context
            .find_verification_card_set_context_with_bb_id(&ballot_box_votes.ballot_box_id)
            .unwrap();
        let auth_id = vcs.verification_card_set_alias.replace("vcs_", "");
        let authorization = election_event_configuration
            .authorizations
            .iter()
            .find(|auth| auth.authorization_identification == auth_id)
            .unwrap();
        let cc_id = authorization.counting_circle_id();
        let dois = authorization.domain_of_influence_ids();
        let relevant_election_groups = election_event_configuration
            .contest
            .election_groups
            .iter()
            .filter(|eg| dois.contains(&eg.domain_of_influence.as_str()))
            .collect::<Vec<_>>();
        let relevant_votes = election_event_configuration
            .contest
            .votes
            .iter()
            .filter(|v| dois.contains(&v.vote.domain_of_influence.as_str()))
            .map(|v| &v.vote)
            .collect::<Vec<_>>();
        let cc_raw_data = self
            .counting_circle_raw_data
            .entry(cc_id.to_string())
            .or_insert(CountingCircleRawData::new(cc_id));
        cc_raw_data.append_ballot_box(
            &relevant_election_groups,
            &relevant_votes,
            ballot_box_votes,
        )?;
        Ok(())
    }
}

impl ECh0222differencesTrait for RawData {
    fn calculate_differences(&self, expected: &Self) -> Vec<ECH0222Difference> {
        let mut res = vec![];
        if self.contest_identification != expected.contest_identification {
            res.push(ECH0222Difference::new_with_messsage(
                "contest_identification not the same".to_string(),
            ))
        }
        if self.counting_circle_raw_data.len() != expected.counting_circle_raw_data.len() {
            res.push(ECH0222Difference::new_with_messsage(
                "Number of counting circles not the same".to_string(),
            ))
        }
        for (cc_id, self_cc) in self.counting_circle_raw_data.iter() {
            match expected.counting_circle_raw_data.get(cc_id) {
                Some(expected_cc) => res.append(&mut ECH0222Difference::new_vector_with_reason(
                    self_cc.calculate_differences(expected_cc),
                    format!("cc with id {}", cc_id),
                )),
                None => res.push(ECH0222Difference::new_with_messsage(format!(
                    "cc with id {} is missing in expected",
                    cc_id
                ))),
            }
        }
        for cc_id in expected.counting_circle_raw_data.keys() {
            if !self.counting_circle_raw_data.contains_key(cc_id) {
                res.push(ECH0222Difference::new_with_messsage(format!(
                    "cc with id {} is missing in loaded",
                    cc_id
                )))
            }
        }
        res
    }
}

impl CountingCircleRawData {
    pub(super) fn from_node(node: &Node) -> (String, Self) {
        let mut children = node.element_children();
        let counting_circle_id_str = children.next().unwrap().text().unwrap();
        let voting_cards_information = VotingCardsInformation::from_node(&children.next().unwrap());
        (
            counting_circle_id_str.to_string(),
            Self {
                counting_circle_id: counting_circle_id_str.to_string(),
                voting_cards_information,
                vote_raw_data: node
                    .element_children()
                    .filter(|n| n.has_tag_name("voteRawData"))
                    .map(|n| VoteRawData::from_node(&n))
                    .collect::<HashMap<_, _>>(),
                election_group_ballot_raw_data: node
                    .element_children()
                    .filter(|n| n.has_tag_name("electionGroupBallotRawData"))
                    .map(|n| ElectionGroupBallotRawData::from_node(&n))
                    .collect::<Vec<_>>(),
            },
        )
    }

    pub(super) fn new(counting_circle_id: &str) -> Self {
        Self {
            counting_circle_id: counting_circle_id.to_string(),
            voting_cards_information: VotingCardsInformation::new(),
            vote_raw_data: HashMap::default(),
            election_group_ballot_raw_data: vec![],
        }
    }

    pub(super) fn append_ballot_box(
        &mut self,
        relevant_election_groups: &[&ElectionGroupBallot],
        relevant_votations: &[&Vote],
        ballot_box_votes: &TallyComponentVotesPayload,
    ) -> Result<(), ECH0222CalculatedErrorImpl> {
        self.voting_cards_information
            .count_of_received_valid_voting_cards_total += ballot_box_votes.decoded_votes.len();
        for votation in relevant_votations.iter() {
            self.add_votation(votation, ballot_box_votes)?;
        }
        self.add_election_groups(relevant_election_groups, ballot_box_votes)?;
        Ok(())
    }

    fn add_votation(
        &mut self,
        votation: &Vote,
        ballot_box_votes: &TallyComponentVotesPayload,
    ) -> Result<(), ECH0222CalculatedErrorImpl> {
        let vote_raw_data = self
            .vote_raw_data
            .entry(votation.vote_identification.clone())
            .or_insert(VoteRawData::new(votation.vote_identification.as_str()));
        vote_raw_data.add_ballots(votation.ballots.as_slice(), &ballot_box_votes.decoded_votes)?;
        if vote_raw_data.is_empty() {
            self.vote_raw_data
                .remove_entry(&votation.vote_identification);
        }
        Ok(())
    }

    fn add_election_groups(
        &mut self,
        relevant_election_groups: &[&ElectionGroupBallot],
        ballot_box_votes: &TallyComponentVotesPayload,
    ) -> Result<(), ECH0222CalculatedErrorImpl> {
        self.election_group_ballot_raw_data =
            ElectionGroupBallotRawData::collect_election_group_ballot_raw_data(
                relevant_election_groups,
                &ballot_box_votes.decoded_votes,
                &ballot_box_votes.decoded_write_ins,
            )
            .map_err(|e| ECH0222CalculatedErrorImpl::ElectionCC {
                cc_id: self.counting_circle_id.clone(),
                source: Box::new(e),
            })?;
        Ok(())
    }
}

impl ECh0222differencesTrait for CountingCircleRawData {
    fn calculate_differences(&self, expected: &Self) -> Vec<ECH0222Difference> {
        let mut res = vec![];
        if self.counting_circle_id != expected.counting_circle_id {
            res.push(ECH0222Difference::new_with_messsage(
                "counting_circle_id not the same".to_string(),
            ))
        }
        res.append(&mut ECH0222Difference::new_vector_with_reason(
            self.voting_cards_information
                .calculate_differences(&expected.voting_cards_information),
            format!("voting_cards_information in cc {}", self.counting_circle_id),
        ));

        // Votes
        if self.vote_raw_data.len() != expected.vote_raw_data.len() {
            res.push(ECH0222Difference::new_with_messsage(
                "Number of vote_raw_data not the same".to_string(),
            ))
        }
        for (vote_id, self_voterd) in self.vote_raw_data.iter() {
            match expected.vote_raw_data.get(vote_id) {
                Some(expected_cc) => {
                    res.append(&mut self_voterd.calculate_differences(expected_cc))
                }
                None => res.push(ECH0222Difference::new_with_messsage(format!(
                    "vote_raw_data with id {} is missing in expected",
                    vote_id
                ))),
            }
        }
        for vote_id in expected.vote_raw_data.keys() {
            if !self.vote_raw_data.contains_key(vote_id) {
                res.push(ECH0222Difference::new_with_messsage(format!(
                    "vote_raw_data with id {} is missing in loaded",
                    vote_id
                )))
            }
        }

        // Elections
        let mut election_group_ballot_raw_data_hm: HashMap<u64, &ElectionGroupBallotRawData> =
            HashMap::new();
        let mut election_group_ballot_raw_data_histo_hm_self: HashMap<u64, usize> = HashMap::new();
        for raw in self.election_group_ballot_raw_data.iter() {
            let mut s = DefaultHasher::new();
            raw.hash(&mut s);
            let hash = s.finish();
            election_group_ballot_raw_data_hm.entry(hash).or_insert(raw);
            election_group_ballot_raw_data_histo_hm_self
                .entry(hash)
                .and_modify(|v| *v += 1)
                .or_insert(1);
        }
        let mut election_group_ballot_raw_data_histo_hm_expected: HashMap<u64, usize> =
            HashMap::new();
        for raw in expected.election_group_ballot_raw_data.iter() {
            let mut s = DefaultHasher::new();
            raw.hash(&mut s);
            let hash = s.finish();
            election_group_ballot_raw_data_hm.entry(hash).or_insert(raw);
            election_group_ballot_raw_data_histo_hm_expected
                .entry(hash)
                .and_modify(|v| *v += 1)
                .or_insert(1);
        }
        for (hash, self_nb) in election_group_ballot_raw_data_histo_hm_self.iter() {
            match election_group_ballot_raw_data_histo_hm_expected.get(hash) {
                Some(expected_nd) => {
                    if self_nb != expected_nd {
                        let eg_raw_data = election_group_ballot_raw_data_hm.get(hash).unwrap();
                        res.push(ECH0222Difference::new_with_messsage(format!(
                            "Found {} ballots and expeted {} for the election group raw data -> {}",
                            self_nb,
                            expected_nd,
                            eg_raw_data.difference_found_text()
                        )));
                    }
                }
                None => res.push(ECH0222Difference::new_with_messsage(format!(
                    "ballot is missing in expected election group raw data: {}",
                    election_group_ballot_raw_data_hm
                        .get(hash)
                        .unwrap()
                        .difference_found_text()
                ))),
            }
        }
        for (hash, _) in election_group_ballot_raw_data_histo_hm_expected.iter() {
            if !election_group_ballot_raw_data_histo_hm_self.contains_key(hash) {
                res.push(ECH0222Difference::new_with_messsage(format!(
                    "ballot is missing in loaded election group raw data: {}",
                    election_group_ballot_raw_data_hm
                        .get(hash)
                        .unwrap()
                        .difference_found_text()
                )))
            }
        }

        // Return results
        res
    }
}

impl VotingCardsInformation {
    pub(super) fn from_node(node: &Node) -> Self {
        Self {
            count_of_received_valid_voting_cards_total: node
                .element_children()
                .find(|n| n.has_tag_name("countOfReceivedValidVotingCardsTotal"))
                .unwrap()
                .text()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
            count_of_received_invalid_voting_cards_total: node
                .element_children()
                .find(|n| n.has_tag_name("countOfReceivedInvalidVotingCardsTotal"))
                .unwrap()
                .text()
                .unwrap()
                .parse::<usize>()
                .unwrap(),
        }
    }

    pub(super) fn new() -> Self {
        Self {
            count_of_received_valid_voting_cards_total: 0,
            count_of_received_invalid_voting_cards_total: 0,
        }
    }
}

impl ECh0222differencesTrait for VotingCardsInformation {
    fn calculate_differences(&self, expected: &Self) -> Vec<ECH0222Difference> {
        let mut res = vec![];
        if self.count_of_received_invalid_voting_cards_total
            != expected.count_of_received_invalid_voting_cards_total
        {
            res.push(ECH0222Difference::new_with_messsage(
                "count_of_received_invalid_voting_cards_total not the same".to_string(),
            ))
        }
        if self.count_of_received_valid_voting_cards_total
            != expected.count_of_received_valid_voting_cards_total
        {
            res.push(ECH0222Difference::new_with_messsage(
                "count_of_received_valid_voting_cards_total not the same".to_string(),
            ))
        }
        res
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        config::test::test_datasets_tally_path,
        data_structures::{VerifierDataDecode, tally::ech_0222::ECH0222},
    };
    use std::{fs, sync::Arc};

    fn get_data_and_copy() -> (ECH0222Data, ECH0222Data) {
        let elt = ECH0222::decode_xml(
            fs::read_to_string(
                test_datasets_tally_path().join("eCH-0222_v3-0_NE_20231124_TT05.xml"),
            )
            .unwrap(),
        )
        .unwrap()
        .get_data()
        .unwrap();
        let orig = Arc::into_inner(elt).unwrap();
        let copy = orig.clone();
        (orig, copy)
    }

    #[test]
    fn change_contest_id() {
        let (orig, mut modified_data) = get_data_and_copy();
        modified_data.raw_data.contest_identification = "modified".to_string();
        let differences = orig.calculate_differences(&modified_data);
        assert!(!differences.is_empty());
    }

    #[test]
    fn add_cc() {
        let (orig, mut modified_data) = get_data_and_copy();
        let mut cc = orig
            .raw_data
            .counting_circle_raw_data
            .values()
            .next()
            .unwrap()
            .clone();
        cc.counting_circle_id = "new_cc".to_string();
        modified_data
            .raw_data
            .counting_circle_raw_data
            .insert("new_cc".to_string(), cc);
        let differences = orig.calculate_differences(&modified_data);
        assert!(!differences.is_empty());
    }

    #[test]
    fn remove_cc() {
        let (orig, mut modified_data) = get_data_and_copy();
        modified_data.raw_data.counting_circle_raw_data.remove(
            &orig
                .raw_data
                .counting_circle_raw_data
                .keys()
                .next()
                .unwrap()
                .to_string(),
        );
        let differences = orig.calculate_differences(&modified_data);
        assert!(!differences.is_empty());
    }

    #[test]
    fn change_cc_id() {
        let (orig, mut modified_data) = get_data_and_copy();
        let cc_id = orig
            .raw_data
            .counting_circle_raw_data
            .keys()
            .next()
            .unwrap()
            .to_string();
        modified_data
            .raw_data
            .counting_circle_raw_data
            .get_mut(&cc_id)
            .unwrap()
            .counting_circle_id = "modified".to_string();
        let differences = orig.calculate_differences(&modified_data);
        assert!(!differences.is_empty());
    }

    #[test]
    fn add_vote() {
        let (orig, mut modified_data) = get_data_and_copy();
        let (cc_id, mut vote) = orig
            .raw_data
            .counting_circle_raw_data
            .iter()
            .find(|(_, cc)| !cc.vote_raw_data.is_empty())
            .map(|(cc_id, cc)| (cc_id, cc.vote_raw_data.values().next().unwrap().clone()))
            .unwrap();
        vote.vote_identification = "new_vote".to_string();
        modified_data
            .raw_data
            .counting_circle_raw_data
            .get_mut(cc_id)
            .unwrap()
            .vote_raw_data
            .insert("new_vote".to_string(), vote);
        let differences = orig.calculate_differences(&modified_data);
        assert!(!differences.is_empty());
    }

    #[test]
    fn add_election_groups() {
        let (orig, mut modified_data) = get_data_and_copy();
        let (cc_id, mut election_group) = orig
            .raw_data
            .counting_circle_raw_data
            .iter()
            .find(|(_, cc)| !cc.election_group_ballot_raw_data.is_empty())
            .map(|(cc_id, cc)| (cc_id, cc.election_group_ballot_raw_data[0].clone()))
            .unwrap();
        election_group.election_group_identification = "new_election_group".to_string();
        modified_data
            .raw_data
            .counting_circle_raw_data
            .get_mut(cc_id)
            .unwrap()
            .election_group_ballot_raw_data
            .push(election_group);
        let differences = orig.calculate_differences(&modified_data);
        assert!(!differences.is_empty());
    }
}
