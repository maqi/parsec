// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::meta_vote::MetaVote;
use crate::observation::is_more_than_two_thirds;
use std::ops::AddAssign;

// This is used to collect the meta votes of other events relating to a single (binary) meta vote at
// a given round and step.
#[derive(Default, Debug)]
pub(crate) struct MetaVoteCounts {
    pub estimates_true: usize,
    pub estimates_false: usize,
    pub bin_values_true: usize,
    pub bin_values_false: usize,
    pub aux_values_true: usize,
    pub aux_values_false: usize,
    pub decision: Option<bool>,
    pub total_peers: usize,
}

impl AddAssign for MetaVoteCounts {
    fn add_assign(&mut self, other: MetaVoteCounts) {
        self.estimates_true += other.estimates_true;
        self.estimates_false += other.estimates_false;
        self.bin_values_true += other.bin_values_true;
        self.bin_values_false += other.bin_values_false;
        self.aux_values_true += other.aux_values_true;
        self.aux_values_false += other.aux_values_false;
        self.decision = self.decision.or(other.decision);
    }
}

impl MetaVoteCounts {
    // Construct a `MetaVoteCounts` by collecting details from all meta votes which are for the
    // given `parent`'s `round` and `step`.  These results will include info from our own `parent`
    // meta vote, if `is_voter` is true.
    pub fn new(
        parent: &MetaVote,
        others: &[&[MetaVote]],
        total_peers: usize,
        is_voter: bool,
    ) -> Self {
        let mut counts = MetaVoteCounts::default();
        counts.total_peers = total_peers;
        for vote in others
            .iter()
            .filter_map(|other| {
                other
                    .iter()
                    .filter(|vote| vote.round_and_step() == parent.round_and_step())
                    .last()
            })
            .chain(if is_voter { Some(parent) } else { None })
        {
            let contribution = vote.values.count();
            counts += contribution;
        }
        counts
    }

    pub fn aux_values_set(&self) -> usize {
        self.aux_values_true + self.aux_values_false
    }

    pub fn is_supermajority(&self, count: usize) -> bool {
        is_more_than_two_thirds(count, self.total_peers)
    }

    pub fn at_least_one_third(&self, count: usize) -> bool {
        3 * count >= self.total_peers
    }

    pub fn check_exceeding(&self) {
        let is_exceeding = self.estimates_true > self.total_peers
            || self.estimates_false > self.total_peers
            || self.bin_values_true > self.total_peers
            || self.bin_values_false > self.total_peers
            || self.aux_values_true > self.total_peers
            || self.aux_values_false > self.total_peers;

        if is_exceeding {
            log_or_panic!("Having count exceeding total peers {:?}", self);
        }
    }
}
