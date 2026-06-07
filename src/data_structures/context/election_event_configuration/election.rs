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

use crate::data_structures::xml::ElementChildren;

#[derive(Debug, Clone)]
pub struct ElectionInformation {
    pub election: Election,
    pub candidates: Vec<Candidate>,
    pub lists: Vec<List>,
    pub write_in_positions: Vec<WriteInPosition>,
    pub empty_list: EmptyList,
}

#[derive(Debug, Clone)]
pub struct Election {
    pub election_identification: String,
    pub type_of_election: usize,
    pub number_of_mandates: usize,
    pub write_ins_allowed: bool,
    pub candidate_accumulation: usize,
    pub minimal_candidate_selection_in_list: usize,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub candidate_identification: String,
    pub family_name: String,
    pub first_name: Option<String>,
    pub call_name: String,
    pub date_of_birth: String,
    pub reference_on_position: String,
}

#[derive(Debug, Clone)]
pub struct List {
    pub list_identification: String,
    pub list_indenture_number: String,
    pub list_description: ListDescription,
    pub candidate_positions: Vec<CandidatePosition>,
}

#[derive(Debug, Clone)]
pub struct ListDescription {
    pub list_description_info: Vec<ListDescriptionInfo>,
}

#[derive(Debug, Clone)]
pub struct ListDescriptionInfo {
    pub language: String,
    pub list_description: String,
}

#[derive(Debug, Clone)]
pub struct CandidatePosition {
    pub candidate_list_identification: String,
    pub position_on_list: usize,
    pub candidate_reference_on_position: String,
    pub candidate_identification: String,
}

#[derive(Debug, Clone)]
pub struct WriteInPosition {
    pub write_in_position_identification: String,
    pub position: usize,
}

#[derive(Debug, Clone)]
pub struct EmptyList {
    pub list_identification: String,
    pub list_description: ListDescription,
    pub empty_positions: Vec<EmptyPosition>,
}

#[derive(Debug, Clone)]
pub struct EmptyPosition {
    pub empty_position_identification: String,
    pub position_on_list: usize,
}

/// Enum defining the type of the id in an election
///
/// - [TypeOfIdInElection::List] : The id is a list
/// - [TypeOfIdInElection::Candidate] : The id is a candidate
/// - [TypeOfIdInElection::EmptyPosition] : The id is an empty position in the empty list
/// - [TypeOfIdInElection::WriteInPosition] : The id is a write-in position
pub enum TypeOfIdInElection<'a> {
    List {
        id: &'a str,
    },
    Candidate {
        id: &'a str,
        candidate_reference_on_position: &'a str,
    },
    EmptyPosition {
        id: &'a str,
    },
    WriteInPosition {
        id: &'a str,
    },
}

impl ElectionInformation {
    pub(super) fn from_node(node: &Node) -> Self {
        let mut lists = node
            .element_children()
            .filter(|n| n.has_tag_name("list"))
            .map(|n| List::from_node(&n))
            .collect::<Vec<_>>();
        if let Some(l) = node
            .element_children()
            .find(|n| n.has_tag_name("emptyList"))
            .map(|n| List::from_node(&n))
        {
            lists.push(l)
        };
        Self {
            election: node
                .first_element_child()
                .map(|n| Election::from_node(&n))
                .unwrap(),
            candidates: node
                .element_children()
                .filter(|n| n.has_tag_name("candidate"))
                .map(|n| Candidate::from_node(&n))
                .collect::<Vec<_>>(),
            lists: node
                .element_children()
                .filter(|n| n.has_tag_name("list"))
                .map(|n| List::from_node(&n))
                .collect::<Vec<_>>(),
            empty_list: node
                .element_children()
                .find(|n| n.has_tag_name("emptyList"))
                .map(|n| EmptyList::from_node(&n))
                .unwrap(),
            write_in_positions: node
                .element_children()
                .filter(|n| n.has_tag_name("writeInPosition"))
                .map(|n| WriteInPosition::from_node(&n))
                .collect::<Vec<_>>(),
        }
    }

    /// Collect of the ids of the write-in positions in the election group
    pub fn write_in_position_ids(&self) -> Vec<&str> {
        self.write_in_positions
            .iter()
            .map(|wp| wp.write_in_position_identification.as_str())
            .collect()
    }

    /// Test if the given id corresponds to a list, incl empty list
    pub fn is_list(&self, id: &str) -> bool {
        if self.empty_list.list_identification == id {
            return true;
        }
        self.lists.iter().any(|l| l.list_identification == id)
    }

    /// Calculate [TypeOfIdInElection] of the id
    ///
    /// `accumulation_pos` corresponds to the position of the candidate in a pre-accumulated list
    ///
    /// Return `None` if the id was not found in [ElectionInformation]
    pub fn type_of_id<'a>(
        &'a self,
        id: &str,
        accumulation_pos: Option<usize>,
    ) -> Option<TypeOfIdInElection<'a>> {
        if self.empty_list.list_identification == id {
            return Some(TypeOfIdInElection::List {
                id: self.empty_list.list_identification.as_str(),
            });
        }
        if self.is_list(id) {
            return Some(TypeOfIdInElection::List {
                id: self.election.election_identification.as_str(),
            });
        }
        if let Some(id) = self
            .empty_list
            .empty_positions
            .iter()
            .find(|ep| ep.empty_position_identification == id)
            .map(|ep| &ep.empty_position_identification)
        {
            return Some(TypeOfIdInElection::EmptyPosition { id });
        }
        if let Some(id) = self
            .write_in_positions
            .iter()
            .find(|ep| ep.write_in_position_identification == id)
            .map(|ep| &ep.write_in_position_identification)
        {
            return Some(TypeOfIdInElection::WriteInPosition { id });
        }
        let candidate_position = self.lists.iter().find_map(|l| {
            l.candidate_positions
                .iter()
                .filter(|cp| cp.candidate_identification == id)
                .nth(accumulation_pos.unwrap_or(0))
        });
        match candidate_position {
            Some(cp) => Some(TypeOfIdInElection::Candidate {
                id: cp.candidate_identification.as_str(),
                candidate_reference_on_position: cp.candidate_reference_on_position.as_str(),
            }),
            None => self
                .candidates
                .iter()
                .find(|c| c.candidate_identification == id)
                .map(|c| TypeOfIdInElection::Candidate {
                    id: &c.candidate_identification,
                    candidate_reference_on_position: &c.reference_on_position,
                }),
        }
    }

    /// Calculate if the given list of candidates correspond exactly to the candidates of the list
    pub fn is_unchanged_list(&self, list_id: &str, candidate_ids: &[&str]) -> Option<bool> {
        if list_id == self.empty_list.list_identification {
            return Some(candidate_ids.is_empty());
        }
        self.lists
            .iter()
            .find(|l| l.list_identification == list_id)
            .map(|l| {
                if candidate_ids.len() != l.candidate_positions.len() {
                    return false;
                }
                let candidates_id_sorted = {
                    let mut v = candidate_ids.to_vec();
                    v.sort();
                    v
                };
                let list_candidates_id_sorted = {
                    let mut v = l
                        .candidate_positions
                        .iter()
                        .map(|cp| cp.candidate_identification.as_str())
                        .collect::<Vec<_>>();
                    v.sort();
                    v
                };
                candidates_id_sorted == list_candidates_id_sorted
            })
    }
}

impl Election {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        let election_identification = children.next().unwrap().text().unwrap().to_string();
        let type_of_election = children
            .next()
            .unwrap()
            .text()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        if children
            .next()
            .unwrap()
            .has_tag_name("electionRulesExplanation")
        {
            children.next();
        }; // electionRulesExplanation or electionDescription
        children.next(); // electionPosition
        let number_of_mandates = children
            .next()
            .unwrap()
            .text()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let write_ins_allowed = children
            .next()
            .map(|n| n.text().unwrap() == "true")
            .unwrap();
        let candidate_accumulation = children
            .next()
            .unwrap()
            .text()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let minimal_candidate_selection_in_list = children
            .next()
            .unwrap()
            .text()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        Self {
            election_identification,
            type_of_election,
            number_of_mandates,
            write_ins_allowed,
            candidate_accumulation,
            minimal_candidate_selection_in_list,
        }
    }
}

impl Candidate {
    fn from_node(node: &Node) -> Self {
        Self {
            candidate_identification: node
                .element_children()
                .find(|n| n.has_tag_name("candidateIdentification"))
                .map(|n| n.text().unwrap().to_string())
                .unwrap(),
            family_name: node
                .element_children()
                .find(|n| n.has_tag_name("familyName"))
                .map(|n| n.text().unwrap().to_string())
                .unwrap(),
            first_name: node
                .element_children()
                .find(|n| n.has_tag_name("firstName"))
                .map(|n| n.text().unwrap().to_string()),
            call_name: node
                .element_children()
                .find(|n| n.has_tag_name("callName"))
                .map(|n| n.text().unwrap().to_string())
                .unwrap(),
            date_of_birth: node
                .element_children()
                .find(|n| n.has_tag_name("dateOfBirth"))
                .map(|n| n.text().unwrap().to_string())
                .unwrap(),
            reference_on_position: node
                .element_children()
                .find(|n| n.has_tag_name("referenceOnPosition"))
                .map(|n| n.text().unwrap().to_string())
                .unwrap(),
        }
    }
}

impl List {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        let list_identification = children.next().unwrap().text().unwrap().to_string();
        let list_indenture_number = children.next().unwrap().text().unwrap().to_string();
        let list_description = children
            .next()
            .map(|n| ListDescription::from_node(&n))
            .unwrap();
        Self {
            list_identification,
            list_description,
            list_indenture_number,
            candidate_positions: node
                .element_children()
                .filter(|n| n.has_tag_name("candidatePosition"))
                .map(|n| CandidatePosition::from_node(&n))
                .collect::<Vec<_>>(),
        }
    }
}

impl ListDescription {
    fn from_node(node: &Node) -> Self {
        Self {
            list_description_info: node
                .element_children()
                .map(|n| ListDescriptionInfo::from_node(&n))
                .collect::<Vec<_>>(),
        }
    }
}

impl ListDescriptionInfo {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        let language = children.next().unwrap().text().unwrap().to_string();
        children.next(); // listDescriptionShort
        let list_description = children.next().unwrap().text().unwrap().to_string();
        Self {
            language,
            list_description,
        }
    }
}
impl CandidatePosition {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        let candidate_list_identification = children.next().unwrap().text().unwrap().to_string();
        let position_on_list = children
            .next()
            .unwrap()
            .text()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let candidate_reference_on_position = children.next().unwrap().text().unwrap().to_string();
        let candidate_identification = children.next().unwrap().text().unwrap().to_string();
        Self {
            candidate_list_identification,
            position_on_list,
            candidate_reference_on_position,
            candidate_identification,
        }
    }
}

impl WriteInPosition {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        let write_in_position_identification = children.next().unwrap().text().unwrap().to_string();
        let position = children
            .next()
            .unwrap()
            .text()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        Self {
            write_in_position_identification,
            position,
        }
    }
}

impl EmptyList {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        let list_identification = children.next().unwrap().text().unwrap().to_string();
        children.next(); // listIndentureNumber
        let list_description = children
            .next()
            .map(|n| ListDescription::from_node(&n))
            .unwrap();
        Self {
            list_identification,
            list_description,
            empty_positions: node
                .element_children()
                .filter(|n| n.has_tag_name("emptyPosition"))
                .map(|n| EmptyPosition::from_node(&n))
                .collect::<Vec<_>>(),
        }
    }
}

impl EmptyPosition {
    fn from_node(node: &Node) -> Self {
        let mut children = node.element_children();
        let empty_position_identification = children.next().unwrap().text().unwrap().to_string();
        let position_on_list = children
            .next()
            .unwrap()
            .text()
            .unwrap()
            .parse::<usize>()
            .unwrap();
        Self {
            empty_position_identification,
            position_on_list,
        }
    }
}
