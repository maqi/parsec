// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::bool_set::BoolSet;
use super::meta_vote_counts::MetaVoteCounts;
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};

pub(crate) type MetaVotes<P> = BTreeMap<P, Vec<MetaVote>>;

// This holds the state of a (binary) meta vote about which we're trying to achieve consensus.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MetaVote {
    pub round: usize,
    pub step: Step,
    pub estimates: BoolSet,
    pub bin_values: BoolSet,
    pub aux_value: Option<bool>,
    pub decision: Option<bool>,
}

fn write_bool(f: &mut Formatter, a_bool: bool) -> fmt::Result {
    if a_bool {
        write!(f, "t")
    } else {
        write!(f, "f")
    }
}

fn write_multiple_bool_values(f: &mut Formatter, field: &str, input: &BoolSet) -> fmt::Result {
    write!(f, "{}:{{", field)?;
    match *input {
        BoolSet::Empty => (),
        BoolSet::Single(ref s) => {
            write_bool(f, *s)?;
        }
        BoolSet::Both => {
            write_bool(f, true)?;
            write!(f, ", ")?;
            write_bool(f, false)?;
        }
    }
    write!(f, "}} ")
}

fn write_optional_single_bool_value(
    f: &mut Formatter,
    field: &str,
    value: Option<bool>,
) -> fmt::Result {
    write!(f, "{}:{{", field)?;
    if let Some(vote) = value {
        write_bool(f, vote)?;
    }
    write!(f, "}} ")
}

impl Debug for MetaVote {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{{ {}/{:?}, ", self.round, self.step)?;

        write_multiple_bool_values(f, "est", &self.estimates)?;
        write_multiple_bool_values(f, "bin", &self.bin_values)?;
        write_optional_single_bool_value(f, "aux", self.aux_value)?;
        write_optional_single_bool_value(f, "dec", self.decision)?;

        write!(f, "}}")
    }
}

impl MetaVote {
    pub fn new(initial_estimate: bool, others: &[Vec<MetaVote>], total_peers: usize) -> Vec<Self> {
        let mut initial = Self::default();
        initial.estimates = BoolSet::from_bool(initial_estimate);
        Self::next(&[initial], others, &BTreeMap::new(), total_peers)
    }

    pub fn new_print(
        initial_estimate: bool,
        others: &[Vec<MetaVote>],
        total_peers: usize,
    ) -> Vec<Self> {
        let mut initial = Self::default();
        initial.estimates = BoolSet::from_bool(initial_estimate);
        Self::next_print(&[initial], others, &BTreeMap::new(), total_peers)
    }

    pub fn next_print(
        parent: &[MetaVote],
        others: &[Vec<MetaVote>],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
    ) -> Vec<Self> {
        let mut next = Vec::new();
        for vote in parent {
            let counts = MetaVoteCounts::new(vote, others, total_peers);
            let updated = Self::update_meta_vote(vote, counts, &coin_tosses);
            let decided = updated.decision.is_some();
            next.push(updated);
            if decided {
                break;
            }
        }
        println!("total_peers {:?} next {:?}", total_peers, next);

        while let Some(next_meta_vote) =
            Self::next_meta_vote_print(next.last(), others, &coin_tosses, total_peers)
        {
            let counts = MetaVoteCounts::new(&next_meta_vote, others, total_peers);
            let updated = Self::update_meta_vote(&next_meta_vote, counts.clone(), &coin_tosses);
            println!("counts {:?} updated: {:?}", counts, updated);
            next.push(updated);
        }

        // while let Some(next_meta_vote) =
        //     Self::next_meta_vote_print(next.last(), others, &coin_tosses, total_peers)
        // {
        //     next.push(next_meta_vote);
        // }
        next
    }

    fn next_meta_vote_print(
        parent: Option<&MetaVote>,
        others: &[Vec<MetaVote>],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
    ) -> Option<MetaVote> {
        parent.and_then(|parent| {
            if parent.decision.is_some() {
                return None;
            }
            let counts = MetaVoteCounts::new(parent, others, total_peers);
            // println!("counts {:?}", counts);
            if counts.is_supermajority(counts.aux_values_set()) {
                let coin_toss = coin_tosses.get(&parent.round);
                let mut next = parent.clone();
                Self::increase_step(&mut next, &counts, coin_toss.cloned());
                Some(next)
            } else {
                None
            }
        })
    }

    pub fn next(
        parent: &[MetaVote],
        others: &[Vec<MetaVote>],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
    ) -> Vec<Self> {
        let mut next = Vec::new();
        for vote in parent {
            let counts = MetaVoteCounts::new(vote, others, total_peers);
            let updated = Self::update_meta_vote(vote, counts, &coin_tosses);
            let decided = updated.decision.is_some();
            next.push(updated);
            if decided {
                break;
            }
        }

        while let Some(next_meta_vote) =
            Self::next_meta_vote(next.last(), others, &coin_tosses, total_peers)
        {
            next.push(next_meta_vote);
        }
        next
    }

    fn update_meta_vote(
        meta_vote: &MetaVote,
        mut counts: MetaVoteCounts,
        coin_tosses: &BTreeMap<usize, bool>,
    ) -> MetaVote {
        if meta_vote.decision.is_some() {
            return meta_vote.clone();
        }
        let coin_toss = coin_tosses.get(&meta_vote.round);
        let mut updated_meta_vote = meta_vote.clone();
        Self::calculate_new_estimates(&mut updated_meta_vote, &mut counts, coin_toss);
        let bin_values_was_empty = updated_meta_vote.bin_values.is_empty();
        Self::calculate_new_bin_values(&mut updated_meta_vote, &mut counts);
        Self::calculate_new_auxiliary_value(
            &mut updated_meta_vote,
            &mut counts,
            bin_values_was_empty,
        );
        Self::calculate_new_decision(&mut updated_meta_vote, &counts);
        updated_meta_vote
    }

    fn next_meta_vote(
        parent: Option<&MetaVote>,
        others: &[Vec<MetaVote>],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
    ) -> Option<MetaVote> {
        parent.and_then(|parent| {
            if parent.decision.is_some() {
                return None;
            }
            let counts = MetaVoteCounts::new(parent, others, total_peers);
            if counts.is_supermajority(counts.aux_values_set()) {
                let coin_toss = coin_tosses.get(&parent.round);
                let mut next = parent.clone();
                Self::increase_step(&mut next, &counts, coin_toss.cloned());
                Some(next)
            } else {
                None
            }
        })
    }

    fn calculate_new_estimates(
        meta_vote: &mut MetaVote,
        counts: &mut MetaVoteCounts,
        coin_toss: Option<&bool>,
    ) {
        if meta_vote.estimates.is_empty() {
            if let Some(toss) = coin_toss {
                if *toss {
                    counts.estimates_true += 1;
                } else {
                    counts.estimates_false += 1;
                }
                meta_vote.estimates = BoolSet::from_bool(*toss);
            }
        } else {
            if counts.at_least_one_third(counts.estimates_true) && meta_vote.estimates.insert(true)
            {
                counts.estimates_true += 1;
            }
            if counts.at_least_one_third(counts.estimates_false)
                && meta_vote.estimates.insert(false)
            {
                counts.estimates_false += 1;
            }
        }
    }

    fn calculate_new_bin_values(meta_vote: &mut MetaVote, counts: &mut MetaVoteCounts) {
        if counts.is_supermajority(counts.estimates_true) && meta_vote.bin_values.insert(true) {
            counts.bin_values_true += 1;
        }
        if counts.is_supermajority(counts.estimates_false) && meta_vote.bin_values.insert(false) {
            counts.bin_values_false += 1;
        }
    }

    fn calculate_new_auxiliary_value(
        meta_vote: &mut MetaVote,
        counts: &mut MetaVoteCounts,
        bin_values_was_empty: bool,
    ) {
        if meta_vote.aux_value.is_some() {
            return;
        }
        if bin_values_was_empty {
            if meta_vote.bin_values.len() == 1 {
                if meta_vote.bin_values.contains(true) {
                    meta_vote.aux_value = Some(true);
                    counts.aux_values_true += 1;
                } else {
                    meta_vote.aux_value = Some(false);
                    counts.aux_values_false += 1;
                }
            } else if meta_vote.bin_values.len() == 2 {
                meta_vote.aux_value = Some(true);
                counts.aux_values_true += 1;
            }
        }
    }

    fn calculate_new_decision(meta_vote: &mut MetaVote, counts: &MetaVoteCounts) {
        let opt_decision = match meta_vote.step {
            Step::ForcedTrue => if meta_vote.bin_values.contains(true)
                && counts.is_supermajority(counts.aux_values_true)
            {
                Some(true)
            } else {
                counts.decision
            },
            Step::ForcedFalse => if meta_vote.bin_values.contains(false)
                && counts.is_supermajority(counts.aux_values_false)
            {
                Some(false)
            } else {
                counts.decision
            },
            Step::GenuineFlip => counts.decision,
        };
        if let Some(decision) = opt_decision {
            meta_vote.estimates = BoolSet::from_bool(decision);
            meta_vote.bin_values = BoolSet::from_bool(decision);
            meta_vote.aux_value = Some(decision);
            meta_vote.decision = Some(decision);
        }
    }

    fn increase_step(
        new_meta_vote: &mut MetaVote,
        counts: &MetaVoteCounts,
        coin_toss: Option<bool>,
    ) {
        new_meta_vote.bin_values.clear();
        new_meta_vote.aux_value = None;

        // Set the estimates as per the concrete coin toss rules.
        match new_meta_vote.step {
            Step::ForcedTrue => {
                if counts.is_supermajority(counts.aux_values_false) {
                    new_meta_vote.estimates = BoolSet::from_bool(false);
                } else if !counts.is_supermajority(counts.aux_values_true) {
                    new_meta_vote.estimates = BoolSet::from_bool(true);
                }
                new_meta_vote.step = Step::ForcedFalse;
            }
            Step::ForcedFalse => {
                if counts.is_supermajority(counts.aux_values_true) {
                    new_meta_vote.estimates = BoolSet::from_bool(true);
                } else if !counts.is_supermajority(counts.aux_values_false) {
                    new_meta_vote.estimates = BoolSet::from_bool(false);
                }
                new_meta_vote.step = Step::GenuineFlip;
            }
            Step::GenuineFlip => {
                if counts.is_supermajority(counts.aux_values_true) {
                    new_meta_vote.estimates = BoolSet::from_bool(true);
                } else if counts.is_supermajority(counts.aux_values_false) {
                    new_meta_vote.estimates = BoolSet::from_bool(false);
                } else if let Some(coin_toss_result) = coin_toss {
                    new_meta_vote.estimates = BoolSet::from_bool(coin_toss_result);
                } else {
                    // Clear the estimates to indicate we're waiting for further events to be
                    // gossiped to try and get the coin toss result.
                    new_meta_vote.estimates.clear();
                }
                new_meta_vote.step = Step::ForcedTrue;
                new_meta_vote.round += 1;
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
pub(crate) enum Step {
    ForcedTrue,
    ForcedFalse,
    GenuineFlip,
}

impl Default for Step {
    fn default() -> Step {
        Step::ForcedTrue
    }
}

impl Debug for Step {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let step = match self {
            Step::ForcedTrue => 0,
            Step::ForcedFalse => 1,
            Step::GenuineFlip => 2,
        };
        write!(f, "{}", step)
    }
}
