// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use hash::Hash;
use id::PublicId;
use parsec::is_more_than_two_thirds;
use round_hash::RoundHash;
use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::iter;

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

/// A simple enum to hold a set of bools.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum BoolSet {
    Empty,
    Single(bool),
    Both,
}

impl Default for BoolSet {
    fn default() -> BoolSet {
        BoolSet::Empty
    }
}

impl BoolSet {
    pub fn is_empty(&self) -> bool {
        *self == BoolSet::Empty
    }

    fn insert(&mut self, val: bool) -> bool {
        match self.clone() {
            BoolSet::Empty => *self = BoolSet::Single(val),
            BoolSet::Single(s) if s != val => *self = BoolSet::Both,
            _ => return false,
        }
        true
    }

    fn contains(&self, val: bool) -> bool {
        match *self {
            BoolSet::Empty => false,
            BoolSet::Single(ref s) => *s == val,
            BoolSet::Both => true,
        }
    }

    fn clear(&mut self) {
        *self = BoolSet::Empty
    }

    fn len(&self) -> usize {
        match *self {
            BoolSet::Empty => 0,
            BoolSet::Single(_) => 1,
            BoolSet::Both => 2,
        }
    }

    fn from_bool(val: bool) -> Self {
        BoolSet::Single(val)
    }
}

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

// This is used to collect the meta votes of other events relating to a single (binary) meta vote at
// a given round and step.
#[derive(Default)]
struct MetaVoteCounts {
    estimates_true: usize,
    estimates_false: usize,
    bin_values_true: usize,
    bin_values_false: usize,
    aux_values_true: usize,
    aux_values_false: usize,
    decision: Option<bool>,
    total_peers: usize,
}

impl MetaVoteCounts {
    // Construct a `MetaVoteCounts` by collecting details from all meta votes which are for the
    // given `parent`'s `round` and `step`.  These results will include info from our own `parent`
    // meta vote.
    fn new(parent: &MetaVote, others: &[Vec<MetaVote>], total_peers: usize) -> Self {
        let mut counts = MetaVoteCounts::default();
        counts.total_peers = total_peers;
        for vote in others
            .iter()
            .filter_map(|other| {
                other
                    .iter()
                    .filter(|vote| vote.round == parent.round && vote.step == parent.step)
                    .last()
            }).chain(iter::once(parent))
        {
            if vote.estimates.contains(true) {
                counts.estimates_true += 1;
            }
            if vote.estimates.contains(false) {
                counts.estimates_false += 1;
            }
            if vote.bin_values.contains(true) {
                counts.bin_values_true += 1;
            }
            if vote.bin_values.contains(false) {
                counts.bin_values_false += 1;
            }
            match vote.aux_value {
                Some(true) => counts.aux_values_true += 1,
                Some(false) => counts.aux_values_false += 1,
                None => (),
            }

            if counts.decision.is_none() {
                counts.decision = vote.decision;
            }
        }
        counts
    }

    fn aux_values_set(&self) -> usize {
        self.aux_values_true + self.aux_values_false
    }

    fn is_supermajority(&self, count: usize) -> bool {
        is_more_than_two_thirds(count, self.total_peers)
    }

    fn at_least_one_third(&self, count: usize) -> bool {
        3 * count >= self.total_peers
    }
}

pub(super) type MetaVotes<P> = BTreeMap<Hash, BTreeMap<P, Vec<MetaVote>>>;

struct MetaElection<P: PublicId> {
    // hash of the block that was last stable when this meta-election started
    block_hash: Hash,
    meta_votes: MetaVotes<P>,
    // The "round hash" for each set of meta votes.  They are held in sequence in the `Vec`, i.e.
    // the one for round `x` is held at index `x`.
    round_hashes: BTreeMap<P, Vec<RoundHash>>,
}

impl<P: PublicId> MetaElection<P> {
    fn new(block_hash: Hash) -> Self {
        MetaElection {
            block_hash,
            meta_votes: BTreeMap::new(),
            round_hashes: BTreeMap::new(),
        }
    }
}

pub(super) struct MetaElections<P: PublicId> {
    meta_elections: Vec<MetaElection<P>>,
}

impl<'a, P: 'a + PublicId> MetaElections<P> {
    pub(super) fn new() -> Self {
        MetaElections {
            meta_elections: iter::once(MetaElection::<P>::new(Hash::all_zero())).collect(),
        }
    }

    pub(super) fn meta_votes_from_current_election(
        &self,
        event_hash: &Hash,
    ) -> Option<&BTreeMap<P, Vec<MetaVote>>> {
        self.meta_elections
            .last()
            .and_then(|election| election.meta_votes.get(event_hash))
    }

    pub(super) fn round_hashes_from_current_election(
        &self,
        peer_id: &P,
    ) -> Option<&Vec<RoundHash>> {
        self.meta_elections
            .last()
            .and_then(|election| election.round_hashes.get(peer_id))
    }

    pub(super) fn consensus_history(&self) -> impl Iterator<Item = &Hash> {
        // The block_hash of the first round of election is all_zero, so need to be skipped.
        self.meta_elections
            .iter()
            .skip(1)
            .map(|election| &election.block_hash)
    }

    pub(super) fn new_election(&mut self, payload_hash: Hash) {
        self.meta_elections
            .push(MetaElection::<P>::new(payload_hash))
    }

    pub(super) fn insert_into_current_election(
        &mut self,
        event_hash: Hash,
        meta_votes: BTreeMap<P, Vec<MetaVote>>,
    ) {
        let election = self.current_election_mut();
        let _ = election.meta_votes.insert(event_hash, meta_votes);
    }

    pub(super) fn restart_last_election_round_hashes<I: Iterator<Item = &'a P>>(
        &mut self,
        peer_ids: I,
    ) {
        let election = self.current_election_mut();
        let latest_block_hash = election.block_hash;
        election.round_hashes = peer_ids
            .map(|peer_id| {
                let round_hash = RoundHash::new(peer_id, latest_block_hash);
                (peer_id.clone(), vec![round_hash])
            }).collect();
    }

    pub(super) fn update_current_election_round_hashes(&mut self, event_hash: &Hash) {
        let election = self.current_election_mut();
        if let Some(meta_votes) = election.meta_votes.get(event_hash) {
            for (peer_id, event_votes) in meta_votes.iter() {
                for meta_vote in event_votes {
                    if let Some(hashes) = election.round_hashes.get_mut(&peer_id) {
                        while hashes.len() < meta_vote.round + 1 {
                            let next_round_hash = hashes[hashes.len() - 1].increment_round();
                            hashes.push(next_round_hash);
                        }
                    }
                }
            }
        }
    }

    pub(super) fn initialise_round_hashes<I: Iterator<Item = &'a P>>(&mut self, peer_ids: I) {
        let election = self.current_election_mut();
        let initial_hash = Hash::from([].as_ref());
        for peer_id in peer_ids {
            let round_hash = RoundHash::new(peer_id, initial_hash);
            let _ = election
                .round_hashes
                .insert(peer_id.clone(), vec![round_hash]);
        }
    }

    pub(super) fn last_meta_votes(&self) -> &MetaVotes<P> {
        if let Some(election) = self.meta_elections.last() {
            &election.meta_votes
        } else {
            panic!("MetaElections is empty!")
        }
    }

    fn current_election_mut(&mut self) -> &mut MetaElection<P> {
        if let Some(election) = self.meta_elections.last_mut() {
            election
        } else {
            panic!("MetaElections is empty!")
        }
    }
}

#[cfg(test)]
impl<P: PublicId> MetaElections<P> {
    pub(super) fn new_from_parsed(votes: MetaVotes<P>) -> Self {
        let election = MetaElection {
            block_hash: Hash::all_zero(),
            meta_votes: votes,
            round_hashes: BTreeMap::new(),
        };
        MetaElections {
            meta_elections: iter::once(election).collect(),
        }
    }
}
