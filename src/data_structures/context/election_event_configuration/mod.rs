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

mod election;
mod vote;

use super::super::{DataStructureError, VerifierDataDecode};
use crate::{
    data_structures::{
        DataStructureErrorImpl, VerifierDataToTypeTrait, VerifierDataType,
        xml::{ElementChildren, XMLData},
    },
    direct_trust::{CertificateAuthority, VerifiySignatureTrait, VerifiyXMLSignatureTrait},
};
use chrono::NaiveDate;
pub use election::{
    Candidate, Election, ElectionInformation, EmptyList, List, TypeOfIdInElection, WriteInPosition,
};
use roxmltree::{Document, Node};
use rust_ev_system_library::rust_ev_crypto_primitives::prelude::{EmptyContext, VerifyDomainTrait};
use std::sync::Arc;
pub use vote::*;

#[derive(Clone, Debug)]
pub struct ElectionEventConfigurationData {
    pub header: ConfigHeader,
    pub contest: Contest,
    pub authorizations: Vec<Authorization>,
    pub register: Vec<Voter>,
}

pub type ElectionEventConfiguration = XMLData<ElectionEventConfigurationData, DataStructureError>;

impl VerifierDataToTypeTrait for ElectionEventConfiguration {
    fn data_type() -> crate::data_structures::VerifierDataType {
        VerifierDataType::Context(super::VerifierContextDataType::ElectionEventConfiguration)
    }
}

#[derive(Debug, Clone)]
pub struct ConfigHeader {
    pub file_date: String,
    pub voter_total: usize,
}

#[derive(Clone, Debug)]
pub struct Contest {
    pub contest_identification: String,
    pub contest_date: NaiveDate,
    pub votes: Vec<VoteInformation>,
    pub election_groups: Vec<ElectionGroupBallot>,
}

#[derive(Debug, Clone)]
pub struct Voter {
    pub voter_identification: String,
    pub authorization: String,
}

#[derive(Debug, Clone)]
pub struct Authorization {
    pub authorization_identification: String,
    pub authorization_alias: String,
    pub authorization_test: bool,
    pub authorization_object: Vec<AuthorizationObject>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationObject {
    pub domain_of_influence: DomainOfInfluence,
    pub counting_circle: CountingCircle,
}

#[derive(Debug, Clone)]
pub struct DomainOfInfluence {
    pub domain_of_influence_identification: String,
}

#[derive(Debug, Clone)]
pub struct CountingCircle {
    pub counting_circle_identification: String,
    pub counting_circle_name: String,
}

#[derive(Debug, Clone)]
pub struct VoteInformation {
    pub vote: Vote,
}

#[derive(Debug, Clone)]
pub struct ElectionGroupBallot {
    pub election_group_identification: String,
    pub domain_of_influence: String,
    pub election_group_position: usize,
    pub election_informations: Vec<ElectionInformation>,
}

impl ElectionEventConfigurationData {
    fn list_of_test_ballot_boxes(&self) -> Result<Vec<&str>, DataStructureError> {
        Ok(self
            .authorizations
            .iter()
            .filter(|auth| auth.authorization_test)
            .map(|auth| auth.authorization_identification.as_str())
            .collect())
    }
}

fn decode_xml(s: &str) -> Result<ElectionEventConfigurationData, DataStructureError> {
    let doc = Document::parse(s).map_err(|e| DataStructureErrorImpl::ParseRoXML {
        msg: "Parsing the input string".to_string(),
        source: e,
    })?;
    let root = doc.root();
    let configuration = root.first_element_child().unwrap();
    let mut children = configuration.element_children();

    let header = ConfigHeader::from_node(&children.next().unwrap());

    let contest = Contest::from_node(&children.next().unwrap());

    let authorizations = children
        .next()
        .unwrap()
        .element_children()
        .map(|c| Authorization::from_node(&c))
        .collect::<Vec<_>>();

    let register = children
        .next()
        .unwrap()
        .element_children()
        .map(|c| Voter::from_node(&c))
        .collect::<Vec<_>>();

    Ok(ElectionEventConfigurationData {
        header,
        contest,
        authorizations,
        register,
    })
}

impl VerifyDomainTrait<EmptyContext, String> for ElectionEventConfiguration {}

impl VerifierDataDecode for ElectionEventConfiguration {
    fn decode_xml<'a>(s: String) -> Result<Self, DataStructureError> {
        Ok(XMLData::new(s.as_str(), decode_xml))
    }
}

impl ConfigHeader {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        let file_date = children.next().unwrap().text().unwrap().to_string();
        let voter_total = children
            .next()
            .unwrap()
            .text()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        Self {
            file_date,
            voter_total,
        }
    }
}

impl Contest {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        let contest_identification = children.next().unwrap().text().unwrap().to_string();
        children.next(); // contestDefaultLanguage
        let contest_date_str = children.next().unwrap().text().unwrap().to_string();
        let votes = node
            .element_children()
            .filter(|n| n.has_tag_name("voteInformation"))
            .map(|vi| VoteInformation::from_node(&vi))
            .collect::<Vec<_>>();
        let election_group_ballot = node
            .element_children()
            .filter(|n| n.has_tag_name("electionGroupBallot"))
            .map(|vi| ElectionGroupBallot::from_node(&vi))
            .collect::<Vec<_>>();
        Self {
            contest_identification,
            contest_date: NaiveDate::parse_from_str(&contest_date_str, "%Y-%m-%d").unwrap(),
            votes,
            election_groups: election_group_ballot,
        }
    }

    /// Calculate the number of election in the [Contest]
    pub fn number_of_elections(&self) -> Result<usize, DataStructureError> {
        Ok(self
            .election_groups
            .iter()
            .map(|el| el.number_of_elections())
            .sum())
    }

    /// Calculate the number of votations and ballots in the [Contest]
    ///
    /// Return a tuple with the number of votations and the number of ballots
    pub fn number_of_votations_and_ballots(&self) -> Result<(usize, usize), DataStructureError> {
        let mut number_of_votes = 0;
        let mut number_of_ballots = 0;
        self.votes.iter().for_each(|vote| {
            number_of_votes += 1;
            number_of_ballots += vote.vote.ballots.len();
        });
        Ok((number_of_votes, number_of_ballots))
    }
}

impl VoteInformation {
    fn from_node(node: &Node) -> Self {
        Self {
            vote: Vote::from_node(&node.first_element_child().unwrap()),
        }
    }

    /// Validate if the votation has the given [Authorization] based on the domain of influence
    pub fn has_authorization(&self, auth: &Authorization) -> bool {
        auth.authorization_object.iter().any(|a| {
            self.vote.domain_of_influence
                == a.domain_of_influence.domain_of_influence_identification
        })
    }
}

impl ElectionGroupBallot {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        let election_group_identification = children.next().unwrap().text().unwrap().to_string();
        let domain_of_influence = children.next().unwrap().text().unwrap().to_string();
        children.next(); // voteDescription
        let election_group_position = children
            .next()
            .unwrap()
            .text()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let election_informations = node
            .element_children()
            .filter(|n| n.has_tag_name("electionInformation"))
            .map(|vi| ElectionInformation::from_node(&vi))
            .collect::<Vec<_>>();
        Self {
            election_group_identification,
            domain_of_influence,
            election_group_position,
            election_informations,
        }
    }

    /// Validate if the election group has the given [Authorization] based on the domain of influence
    pub fn has_authorization(&self, auth: &Authorization) -> bool {
        auth.authorization_object.iter().any(|a| {
            self.domain_of_influence == a.domain_of_influence.domain_of_influence_identification
        })
    }

    /// Calculate the number of election in the election group
    pub fn number_of_elections(&self) -> usize {
        self.election_informations.len()
    }

    /// Collect of the ids of the write-in positions in the election group
    pub fn write_in_position_ids(&self) -> Vec<&str> {
        self.election_informations
            .iter()
            .flat_map(|el| el.write_in_position_ids())
            .collect()
    }
}

impl Authorization {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        Self {
            authorization_identification: children.next().unwrap().text().unwrap().to_string(),
            authorization_alias: children.next().unwrap().text().unwrap().to_string(),
            authorization_test: children.next().unwrap().text().unwrap() == "true",
            authorization_object: node
                .element_children()
                .filter(|n| n.has_tag_name("authorizationObject"))
                .map(|c| AuthorizationObject::from_node(&c))
                .collect::<Vec<_>>(),
        }
    }

    /// Get the counting circle id behind the authorization
    pub fn counting_circle_id(&self) -> &str {
        &self.authorization_object[0]
            .counting_circle
            .counting_circle_identification
    }

    /// Get the domain of influence ids behind the authorization
    pub fn domain_of_influence_ids(&self) -> Vec<&str> {
        self.authorization_object
            .iter()
            .map(|auth| {
                auth.domain_of_influence
                    .domain_of_influence_identification
                    .as_str()
            })
            .collect()
    }
}

impl AuthorizationObject {
    fn from_node(node: &Node) -> Self {
        let doi_node = node.first_element_child().unwrap();
        Self {
            domain_of_influence: DomainOfInfluence::from_node(&doi_node),
            counting_circle: CountingCircle::from_node(&doi_node.next_sibling_element().unwrap()),
        }
    }
}

impl DomainOfInfluence {
    fn from_node(node: &Node) -> Self {
        Self {
            domain_of_influence_identification: node
                .first_element_child()
                .unwrap()
                .text()
                .unwrap()
                .to_string(),
        }
    }
}

impl CountingCircle {
    fn from_node(node: &Node) -> Self {
        let first_child = node.first_element_child().unwrap();
        Self {
            counting_circle_identification: first_child.text().unwrap().to_string(),
            counting_circle_name: first_child
                .next_sibling_element()
                .unwrap()
                .text()
                .unwrap()
                .to_string(),
        }
    }
}

impl Voter {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        Self {
            voter_identification: children.next().unwrap().text().unwrap().to_string(),
            authorization: children.next().unwrap().text().unwrap().to_string(),
        }
    }

    /// Test if the voter is a test voter
    fn is_test_voter(&self, test_authorization_ids: &[&str]) -> Result<bool, DataStructureError> {
        Ok(test_authorization_ids.contains(&self.authorization.as_str()))
    }
}

impl VerifiyXMLSignatureTrait<'_> for ElectionEventConfiguration {
    fn get_certificate_authority(&self) -> Option<CertificateAuthority> {
        Some(CertificateAuthority::Canton)
    }

    fn get_data_str(&self) -> Option<Arc<String>> {
        self.get_raw()
    }
}

impl VerifiySignatureTrait<'_> for ElectionEventConfiguration {
    fn verifiy_signature(
        &'_ self,
        keystore: &crate::direct_trust::Keystore,
    ) -> Result<bool, crate::direct_trust::VerifySignatureError> {
        self.verifiy_xml_signature(keystore)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ManuelVerificationInputFromConfiguration {
    pub contest_identification: String,
    pub contest_date: NaiveDate,
    pub number_of_votes: usize,
    pub number_of_ballots: usize,
    pub number_of_elections: usize,
    pub number_of_productive_voters: usize,
    pub number_of_test_voters: usize,
    pub number_of_productive_ballot_boxes: usize,
    pub number_of_test_ballot_boxes: usize,
}

impl TryFrom<&ElectionEventConfigurationData> for ManuelVerificationInputFromConfiguration {
    type Error = DataStructureError;
    fn try_from(value: &ElectionEventConfigurationData) -> Result<Self, Self::Error> {
        let (number_of_votes, number_of_ballots) =
            value.contest.number_of_votations_and_ballots()?;
        let number_of_productive_ballot_boxes = value
            .authorizations
            .iter()
            .filter(|auth| !auth.authorization_test)
            .count();

        let mut number_of_productive_voters = 0;
        let mut number_of_test_voters = 0;
        let test_authorization_ids = value.list_of_test_ballot_boxes()?;
        value
            .register
            .iter()
            .map(|voter| match voter.is_test_voter(&test_authorization_ids) {
                Ok(b) => {
                    match b {
                        true => number_of_test_voters += 1,
                        false => number_of_productive_voters += 1,
                    };
                    Ok(())
                }
                Err(e) => Err(e),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            contest_identification: value.contest.contest_identification.clone(),
            contest_date: value.contest.contest_date,
            number_of_votes,
            number_of_ballots,
            number_of_elections: value.contest.number_of_elections()?,
            number_of_productive_voters,
            number_of_test_voters,
            number_of_productive_ballot_boxes,
            number_of_test_ballot_boxes: value.authorizations.len()
                - number_of_productive_ballot_boxes,
        })
    }
}

#[cfg(test)]
mod test {
    use std::fs;

    use super::*;
    use crate::config::test::{get_keystore, test_datasets_context_path};

    fn get_data_res() -> Result<ElectionEventConfiguration, DataStructureError> {
        ElectionEventConfiguration::decode_xml(
            fs::read_to_string(test_datasets_context_path().join("configuration-anonymized.xml"))
                .unwrap(),
        )
    }

    #[test]
    fn read_data_set() {
        let data_res = get_data_res();
        assert!(data_res.is_ok(), "{:?}", data_res.unwrap_err());
        let data = data_res.unwrap();
        assert_eq!(data.get_data().unwrap().as_ref().header.voter_total, 43);
    }

    #[test]
    fn verify_signature() {
        let data = get_data_res().unwrap();
        let ks = get_keystore();
        let sign_validate_res = data.verify_signatures(&ks);
        for r in sign_validate_res {
            assert!(
                r.is_ok(),
                "error validating signature: {:?}",
                r.as_ref().unwrap_err()
            );
            assert!(r.unwrap())
        }
    }

    #[test]
    fn test_voters() {
        let ec = get_data_res().unwrap();
        let data = ec.get_data().unwrap();
        let mut it = data.register.iter();
        assert_eq!(it.count(), 43);
        it = data.register.iter();
        assert_eq!(it.next().unwrap().voter_identification, "100001");
    }

    #[test]
    fn test_authorizations() {
        let ec = get_data_res().unwrap();
        let data = ec.get_data().unwrap();
        let mut it = data.authorizations.iter();
        assert_eq!(it.count(), 4);
        it = data.authorizations.iter();
        let auth = it.next().unwrap();
        assert_eq!(
            auth.authorization_identification,
            "516e2551-ee42-3401-9988-7dfebd0ac0c0"
        );
        assert_eq!(
            auth.authorization_object[0]
                .domain_of_influence
                .domain_of_influence_identification,
            "doid-ch1-mu"
        );
    }

    #[test]
    fn test_votes() {
        let ec = get_data_res().unwrap();
        let data = ec.get_data().unwrap();
        let mut it = data.contest.votes.iter();
        assert_eq!(it.count(), 1);
        it = data.contest.votes.iter();
        assert_eq!(it.next().unwrap().vote.vote_identification, "ch_test");
    }

    #[test]
    fn test_elections() {
        let ec = get_data_res().unwrap();
        let data = ec.get_data().unwrap();
        let mut it = data.contest.election_groups.iter();
        assert_eq!(it.count(), 2);
        it = data.contest.election_groups.iter();
        assert_eq!(
            it.next().unwrap().election_group_identification,
            "nrw_e66defd3-8542-4c5b-88bb-7e80cdbdb769"
        );
        assert_eq!(
            it.next().unwrap().election_group_identification,
            "majorz_e66defd3-8542-4c5b-88bb-7e80cdbdb769"
        );
    }

    #[test]
    fn test_manual_data() {
        let ec = get_data_res().unwrap();
        let data = ec.get_data().unwrap();
        let manual_data =
            ManuelVerificationInputFromConfiguration::try_from(data.as_ref()).unwrap();
        assert_eq!(
            manual_data,
            ManuelVerificationInputFromConfiguration {
                contest_identification: "Post_E2E_DEV".to_string(),
                contest_date: NaiveDate::from_ymd_opt(2027, 11, 25).unwrap(),
                number_of_votes: 1,
                number_of_ballots: 2,
                number_of_elections: 2,
                number_of_productive_voters: 0,
                number_of_test_voters: 43,
                number_of_productive_ballot_boxes: 0,
                number_of_test_ballot_boxes: 4
            }
        )
    }
}
