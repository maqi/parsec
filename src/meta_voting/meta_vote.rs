// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{bool_set::BoolSet, meta_vote_counts::MetaVoteCounts};
use std::{
    collections::BTreeMap,
    fmt::{self, Debug, Formatter},
};

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Estimates(BoolSet);
impl Debug for Estimates {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write_multiple_bool_values(f, "est", self.0)
    }
}
impl Estimates {
    fn from_initial_value(value: bool) -> Self {
        Estimates(BoolSet::from_bool(value))
    }

    fn calculate(&mut self, counts: &mut MetaVoteCounts, coin_toss: Option<bool>, is_voter: bool) {
        if self.0.is_empty() {
            if let Some(toss) = coin_toss {
                if is_voter {
                    if toss {
                        counts.estimates_true += 1;
                    } else {
                        counts.estimates_false += 1;
                    }
                }
                self.0 = BoolSet::from_bool(toss);
            }
        } else {
            if counts.at_least_one_third(counts.estimates_true) && self.0.insert(true) && is_voter {
                counts.estimates_true += 1;
            }
            if counts.at_least_one_third(counts.estimates_false) && self.0.insert(false) && is_voter
            {
                counts.estimates_false += 1;
            }
        }
    }

    pub fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct BinValues(BoolSet);
impl Debug for BinValues {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write_multiple_bool_values(f, "bin", self.0)
    }
}

impl BinValues {
    fn calculate(&mut self, counts: &mut MetaVoteCounts, is_voter: bool) {
        if counts.is_supermajority(counts.estimates_true) && self.0.insert(true) && is_voter {
            counts.bin_values_true += 1;
        }
        if counts.is_supermajority(counts.estimates_false) && self.0.insert(false) && is_voter {
            counts.bin_values_false += 1;
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct AuxValue(Option<bool>);
impl Debug for AuxValue {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write_optional_single_bool_value(f, "aux", self.0)
    }
}

impl AuxValue {
    fn calculate(
        &mut self,
        counts: &mut MetaVoteCounts,
        bin_values_before_update: BinValues,
        bin_values_now: BinValues,
        is_voter: bool,
    ) {
        if self.0.is_some() {
            return;
        }
        let bin_values_was_empty = bin_values_before_update.0.is_empty();
        if bin_values_was_empty {
            if bin_values_now.0.len() == 1 {
                if bin_values_now.0.contains(true) {
                    self.0 = Some(true);
                    if is_voter {
                        counts.aux_values_true += 1;
                    }
                } else {
                    self.0 = Some(false);
                    if is_voter {
                        counts.aux_values_false += 1;
                    }
                }
            } else if bin_values_now.0.len() == 2 {
                self.0 = Some(true);
                if is_voter {
                    counts.aux_values_true += 1;
                }
            }
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndecidedMetaVoteValues {
    estimates: Estimates,
    bin_values: BinValues,
    aux_value: AuxValue,
}

impl Debug for UndecidedMetaVoteValues {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(
            f,
            "{:?}{:?}{:?}",
            self.estimates, self.bin_values, self.aux_value
        )
    }
}

impl UndecidedMetaVoteValues {
    fn from_decided_meta_vote(value: bool) -> Self {
        Self {
            estimates: Estimates(BoolSet::from_bool(value)),
            bin_values: BinValues(BoolSet::from_bool(value)),
            aux_value: AuxValue(Some(value)),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum MetaVoteValues {
    Decided(bool),
    Undecided(UndecidedMetaVoteValues),
}
impl Debug for MetaVoteValues {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            MetaVoteValues::Decided(value) => {
                write!(
                    f,
                    "{:?}",
                    UndecidedMetaVoteValues::from_decided_meta_vote(*value)
                )?;
                write_optional_single_bool_value(f, "dec", Some(*value))
            }
            MetaVoteValues::Undecided(values) => {
                write!(f, "{:?}", values)?;
                write_optional_single_bool_value(f, "dec", None)
            }
        }
    }
}

impl MetaVoteValues {
    fn from_initial_estimate(value: bool) -> Self {
        let mut values = UndecidedMetaVoteValues::default();
        values.estimates = Estimates::from_initial_value(value);
        MetaVoteValues::Undecided(values)
    }

    pub(crate) fn count(self) -> MetaVoteCounts {
        // Counts the contribution of these MetaVoteValues
        let mut counts = MetaVoteCounts::default();
        match self {
            MetaVoteValues::Decided(value) => {
                counts.decision = Some(value);
                if value {
                    counts.estimates_true = 1;
                    counts.bin_values_true = 1;
                    counts.aux_values_true = 1;
                } else {
                    counts.estimates_false = 1;
                    counts.bin_values_false = 1;
                    counts.aux_values_false = 1;
                }
            }
            MetaVoteValues::Undecided(values) => {
                if values.estimates.0.contains(true) {
                    counts.estimates_true = 1;
                }
                if values.estimates.0.contains(false) {
                    counts.estimates_false = 1;
                }
                if values.bin_values.0.contains(true) {
                    counts.bin_values_true = 1;
                }
                if values.bin_values.0.contains(false) {
                    counts.bin_values_false = 1;
                }
                match values.aux_value.0 {
                    Some(true) => counts.aux_values_true = 1,
                    Some(false) => counts.aux_values_false = 1,
                    None => (),
                }
            }
        }
        counts
    }

    fn calculate_new_estimates(
        &mut self,
        counts: &mut MetaVoteCounts,
        coin_toss: Option<bool>,
        is_voter: bool,
    ) {
        if let MetaVoteValues::Undecided(values) = self {
            values.estimates.calculate(counts, coin_toss, is_voter);
        }
    }

    fn calculate_new_bin_values(&mut self, counts: &mut MetaVoteCounts, is_voter: bool) {
        if let MetaVoteValues::Undecided(values) = self {
            values.bin_values.calculate(counts, is_voter);
        }
    }

    fn calculate_new_auxiliary_value(
        &mut self,
        counts: &mut MetaVoteCounts,
        bin_values_before_update: BinValues,
        is_voter: bool,
    ) {
        if let MetaVoteValues::Undecided(values) = self {
            let bin_values_now = values.bin_values;
            values
                .aux_value
                .calculate(counts, bin_values_before_update, bin_values_now, is_voter);
        }
    }
    fn calculate_new_decision(&mut self, counts: &MetaVoteCounts, step: Step) {
        if let MetaVoteValues::Undecided(values) = *self {
            let bin_values = values.bin_values;
            let decision = match step {
                Step::ForcedTrue => {
                    if bin_values.0.contains(true)
                        && counts.is_supermajority(counts.aux_values_true)
                    {
                        Some(true)
                    } else {
                        counts.decision
                    }
                }
                Step::ForcedFalse => {
                    if bin_values.0.contains(false)
                        && counts.is_supermajority(counts.aux_values_false)
                    {
                        Some(false)
                    } else {
                        counts.decision
                    }
                }
                Step::GenuineFlip => counts.decision,
            };
            if let Some(value) = decision {
                *self = MetaVoteValues::Decided(value);
            }
        }
    }

    fn increase_step(&mut self, counts: &MetaVoteCounts, coin_toss: Option<bool>, step: Step) {
        if let MetaVoteValues::Undecided(ref mut values) = *self {
            // Set the estimates as per the concrete coin toss rules.
            values.estimates.0 = match step {
                Step::ForcedTrue => {
                    if counts.is_supermajority(counts.aux_values_false) {
                        BoolSet::from_bool(false)
                    } else {
                        BoolSet::from_bool(true)
                    }
                }
                Step::ForcedFalse => {
                    if counts.is_supermajority(counts.aux_values_true) {
                        BoolSet::from_bool(true)
                    } else {
                        BoolSet::from_bool(false)
                    }
                }
                Step::GenuineFlip => {
                    if counts.is_supermajority(counts.aux_values_true) {
                        BoolSet::from_bool(true)
                    } else if counts.is_supermajority(counts.aux_values_false) {
                        BoolSet::from_bool(false)
                    } else if let Some(coin_toss) = coin_toss {
                        BoolSet::from_bool(coin_toss)
                    } else {
                        // Clear the estimates to indicate we're waiting for further events to be
                        // gossiped to try and get the coin toss result.
                        BoolSet::Empty
                    }
                }
            };
            values.bin_values.0 = BoolSet::Empty;
            values.aux_value.0 = None;
        }
    }

    fn update(
        &mut self,
        mut counts: MetaVoteCounts,
        coin_toss: Option<bool>,
        step: Step,
        is_voter: bool,
    ) {
        *self = match self {
            MetaVoteValues::Decided(_) => *self,
            MetaVoteValues::Undecided(ref values) => {
                let mut updated = *self;
                updated.calculate_new_estimates(&mut counts, coin_toss, is_voter);
                let bin_values_before_update = values.bin_values;
                updated.calculate_new_bin_values(&mut counts, is_voter);
                updated.calculate_new_auxiliary_value(
                    &mut counts,
                    bin_values_before_update,
                    is_voter,
                );
                counts.check_exceeding();
                updated.calculate_new_decision(&counts, step);
                updated
            }
        }
    }

    #[cfg(feature = "dump-graphs")]
    pub fn as_chars(self) -> (char, char, char, char) {
        let pretty_bool = |b: bool| {
            if b {
                't'
            } else {
                'f'
            }
        };
        let pretty_option_bool = |o: Option<bool>| match o {
            Some(b) => pretty_bool(b),
            None => '_',
        };
        let pretty_bool_set = |s: BoolSet| match s {
            BoolSet::Empty => '-',
            BoolSet::Single(b) => pretty_bool(b),
            BoolSet::Both => 'b',
        };

        match self {
            MetaVoteValues::Decided(value) => {
                let dec = pretty_bool(value);
                (dec, dec, dec, dec)
            }
            MetaVoteValues::Undecided(values) => {
                let est = pretty_bool_set(values.estimates.0);
                let bin = pretty_bool_set(values.bin_values.0);
                let aux = pretty_option_bool(values.aux_value.0);
                let dec = pretty_option_bool(None);
                (est, bin, aux, dec)
            }
        }
    }
}

impl Default for MetaVoteValues {
    fn default() -> Self {
        MetaVoteValues::Undecided(Default::default())
    }
}

// This holds the state of a (binary) meta vote about which we're trying to achieve consensus.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MetaVote {
    pub round: usize,
    pub step: Step,
    pub values: MetaVoteValues,
}

fn write_bool(f: &mut Formatter, a_bool: bool) -> fmt::Result {
    if a_bool {
        write!(f, "t")
    } else {
        write!(f, "f")
    }
}

fn write_multiple_bool_values(f: &mut Formatter, field: &str, input: BoolSet) -> fmt::Result {
    write!(f, "{}:{{", field)?;
    match input {
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
        write!(f, "{:?}", self.values)?;
        write!(f, "}}")
    }
}

impl MetaVote {
    #[cfg(any(test, feature = "testing"))]
    pub fn new(
        round: usize,
        step: Step,
        estimates: BoolSet,
        bin_values: BoolSet,
        aux_value: Option<bool>,
        decision: Option<bool>,
    ) -> Self {
        let values = match decision {
            Some(values) => MetaVoteValues::Decided(values),
            None => {
                let values = UndecidedMetaVoteValues {
                    estimates: Estimates(estimates),
                    bin_values: BinValues(bin_values),
                    aux_value: AuxValue(aux_value),
                };
                MetaVoteValues::Undecided(values)
            }
        };
        MetaVote {
            round,
            step,
            values,
        }
    }

    pub fn new_for_observer(
        initial_estimate: bool,
        others: &[&[MetaVote]],
        total_peers: usize,
        is_voter: bool,
    ) -> Vec<Self> {
        let initial = if is_voter {
            Self {
                values: MetaVoteValues::from_initial_estimate(initial_estimate),
                ..Default::default()
            }
        } else {
            Self::default()
        };
        Self::next_votes(&[initial], others, &BTreeMap::new(), total_peers, is_voter)
    }

    /// Create temporary next meta-votes. They must be finalized by calling `next_final` before
    /// passing them to `MetaEvent`.
    pub fn next_temp(
        parent: &[MetaVote],
        others: &[&[MetaVote]],
        total_peers: usize,
        is_voter: bool,
    ) -> Vec<Self> {
        Self::next_votes(parent, others, &BTreeMap::new(), total_peers, is_voter)
    }

    /// Finalize temporary meta-votes.
    pub fn next_final(
        temp: &[MetaVote],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
        is_voter: bool,
    ) -> Vec<Self> {
        Self::next_votes(temp, &[], coin_tosses, total_peers, is_voter)
    }

    pub fn contains_aux_value(&self) -> bool {
        match self.values {
            MetaVoteValues::Decided(_) => true,
            MetaVoteValues::Undecided(values) => values.aux_value.0.is_some(),
        }
    }

    pub fn decision(&self) -> Option<bool> {
        match self.values {
            MetaVoteValues::Decided(value) => Some(value),
            MetaVoteValues::Undecided(_) => None,
        }
    }

    pub fn has_empty_estimates(&self) -> bool {
        match self.values {
            MetaVoteValues::Decided(_) => false,
            MetaVoteValues::Undecided(values) => values.estimates.is_empty(),
        }
    }

    fn next_votes(
        prev: &[MetaVote],
        others: &[&[MetaVote]],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
        is_voter: bool,
    ) -> Vec<Self> {
        let mut next = Vec::new();
        for vote in prev {
            let counts = MetaVoteCounts::new(vote, others, total_peers, is_voter);
            let updated = vote.update(counts, &coin_tosses, is_voter);
            let decided = updated.is_decided();
            next.push(updated);
            if decided {
                break;
            }
        }

        while let Some(next_meta_vote) =
            Self::next_vote(next.last(), others, &coin_tosses, total_peers, is_voter)
        {
            next.push(next_meta_vote);
        }

        next
    }

    pub fn round_and_step(&self) -> (usize, Step) {
        (self.round, self.step)
    }

    fn is_decided(&self) -> bool {
        if let MetaVoteValues::Decided(_) = self.values {
            true
        } else {
            false
        }
    }

    fn update(
        &self,
        counts: MetaVoteCounts,
        coin_tosses: &BTreeMap<usize, bool>,
        is_voter: bool,
    ) -> MetaVote {
        let mut updated = *self;
        let coin_toss = coin_tosses.get(&self.round).cloned();
        updated
            .values
            .update(counts, coin_toss, self.step, is_voter);
        updated
    }

    fn next_vote(
        parent: Option<&Self>,
        others: &[&[MetaVote]],
        coin_tosses: &BTreeMap<usize, bool>,
        total_peers: usize,
        is_voter: bool,
    ) -> Option<MetaVote> {
        let parent = parent?;

        if parent.is_decided() {
            return None;
        }
        let counts = MetaVoteCounts::new(parent, others, total_peers, is_voter);
        if counts.is_supermajority(counts.aux_values_set()) {
            let coin_toss = coin_tosses.get(&parent.round);
            let next = parent.increase_step(&counts, coin_toss.cloned());
            let new_counts = MetaVoteCounts::new(&next, others, total_peers, is_voter);
            let updated = next.update(new_counts, &coin_tosses, is_voter);
            Some(updated)
        } else {
            None
        }
    }

    fn increase_step(&self, counts: &MetaVoteCounts, coin_toss: Option<bool>) -> Self {
        let mut next = *self;
        next.values.increase_step(counts, coin_toss, self.step);
        match next.step {
            Step::ForcedTrue => {
                next.step = Step::ForcedFalse;
            }
            Step::ForcedFalse => {
                next.step = Step::GenuineFlip;
            }
            Step::GenuineFlip => {
                next.step = Step::ForcedTrue;
                next.round += 1;
            }
        }
        next
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
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
