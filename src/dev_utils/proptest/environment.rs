// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Bounded, BoundedBoxedStrategy};
use dev_utils::environment::{Environment, ObservationCount, PeerCount, RngChoice};
use dev_utils::network::Network;
use proptest_crate::prelude::RngCore;
use proptest_crate::strategy::{NewTree, Strategy, ValueTree};
use proptest_crate::test_runner::TestRunner;
use rand::{SeedableRng, XorShiftRng};

#[derive(Debug)]
pub struct EnvironmentStrategy {
    pub num_peers: BoundedBoxedStrategy<usize>,
    pub num_observations: BoundedBoxedStrategy<usize>,
}

impl Default for EnvironmentStrategy {
    fn default() -> Self {
        EnvironmentStrategy {
            num_peers: (4..=10).into(),
            num_observations: (1..10).into(),
        }
    }
}

pub struct EnvironmentValueTree {
    max_env: Environment,
    peers_trans: Box<ValueTree<Value = (usize, usize)>>,
    min_peers_trans: (usize, usize),
    seed: [u32; 4],
}

impl EnvironmentValueTree {
    fn filtered_environment(&self, n_peers: usize, n_trans: usize) -> Environment {
        let peer_ids = self
            .max_env
            .network
            .peers
            .iter()
            .take(n_peers)
            .map(|p| p.id.clone());
        let network = Network::with_peers(peer_ids);
        let observations = self
            .max_env
            .observations
            .iter()
            .take(n_trans)
            .cloned()
            .collect();
        Environment {
            network,
            observations,
            rng: Box::new(XorShiftRng::from_seed(self.seed)),
        }
    }
}

impl Bounded for EnvironmentValueTree {
    type Bound = Environment;

    fn min(&self) -> Environment {
        let (n_peers, n_trans) = self.min_peers_trans;
        self.filtered_environment(n_peers, n_trans)
    }

    fn max(&self) -> Environment {
        let (n_peers, n_trans) = (
            self.max_env.network.peers.len(),
            self.max_env.observations.len(),
        );
        self.filtered_environment(n_peers, n_trans)
    }
}

impl ValueTree for EnvironmentValueTree {
    type Value = Environment;

    fn current(&self) -> Environment {
        let (n_peers, n_trans) = self.peers_trans.current();
        self.filtered_environment(n_peers, n_trans)
    }

    fn simplify(&mut self) -> bool {
        self.peers_trans.simplify()
    }

    fn complicate(&mut self) -> bool {
        self.peers_trans.complicate()
    }
}

impl Strategy for EnvironmentStrategy {
    type Value = Environment;
    type Tree = EnvironmentValueTree;

    fn new_tree(&self, runner: &mut TestRunner) -> NewTree<Self> {
        let seed = {
            let rng = runner.rng();
            [
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
                rng.next_u32(),
            ]
        };
        let env = Environment::new(
            &PeerCount(self.num_peers.max()),
            &ObservationCount(self.num_observations.max()),
            RngChoice::SeededXor(seed),
        );
        (&self.num_peers, &self.num_observations)
            .new_tree(runner)
            .map(|t| EnvironmentValueTree {
                max_env: env,
                peers_trans: Box::new(t),
                min_peers_trans: (self.num_peers.min(), self.num_observations.min()),
                seed,
            })
    }
}
