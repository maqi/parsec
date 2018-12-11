// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::meta_vote::MetaVote;
use observation::is_more_than_two_thirds;
use std::iter;

// This is used to collect the meta votes of other events relating to a single (binary) meta vote at
// a given round and step.
#[derive(Clone, Default, Debug)]
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

impl MetaVoteCounts {
    // Construct a `MetaVoteCounts` by collecting details from all meta votes which are for the
    // given `parent`'s `round` and `step`.  These results will include info from our own `parent`
    // meta vote.
    pub fn new(parent: &MetaVote, others: &[Vec<MetaVote>], total_peers: usize) -> Self {
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

    pub fn aux_values_set(&self) -> usize {
        self.aux_values_true + self.aux_values_false
    }

    pub fn is_supermajority(&self, count: usize) -> bool {
        is_more_than_two_thirds(count, self.total_peers)
    }

    pub fn at_least_one_third(&self, count: usize) -> bool {
        3 * count >= self.total_peers
    }
}
