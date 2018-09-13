// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Environment;
use super::Observation;
#[cfg(feature = "dump-graphs")]
use dump_graph::DIR;
use mock::PeerId;
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
#[cfg(feature = "dump-graphs")]
use std::fs::File;
#[cfg(feature = "dump-graphs")]
use std::io::Write;
use std::mem;

/// This struct holds the data necessary to make a simulated request when a node executes a local
/// step.
#[derive(Clone, Debug)]
pub struct Request {
    /// The recipient of the request - it will then respond back to the sender
    pub recipient: PeerId,
    /// The delay, in steps, between sending and reception of the request
    pub req_delay: usize,
    /// The delay, in steps, between sending and reception of the response
    pub resp_delay: usize,
}

/// Describes whether the node should make a request during its local step
#[derive(Clone, Debug)]
pub enum RequestTiming {
    /// Don't make a request
    Later,
    /// Make a request
    DuringThisStep(Request),
    /// Make a request if new data is available
    DuringThisStepIfNewData(Request),
}

/// Represents an event the network is supposed to simulate.
/// The simulation proceeds in steps. During every global step, every node has some probability
/// of being scheduled to perform a local step, consisting of receiving messages that reached it
/// by this time, generating appropriate responses and optionally sending a gossip request.
#[derive(Clone, Debug)]
pub enum ScheduleEvent {
    /// This event variant represents a node being scheduled to execute a local step. It contains a
    /// global step number, the ID of the node being scheduled, and optionally data of the request
    /// the node will send.
    LocalStep {
        global_step: usize,
        peer: PeerId,
        request_timing: RequestTiming,
    },
    /// This event causes the node with the given ID to stop responding. All further events
    /// concerning that node will be ignored.
    Fail(PeerId),
    /// This event makes a node vote on the given observation.
    VoteFor(PeerId, Observation),
}

// A function generating a Poisson-distributed random number.
fn poisson<R: Rng>(rng: &mut R, lambda: f64) -> usize {
    let mut result = 0;
    let mut p = 1.0;
    let l = (-lambda).exp();
    loop {
        p *= rng.gen::<f64>();
        if p <= l {
            break;
        }
        result += 1;
    }
    result
}

impl ScheduleEvent {
    fn gen_request<R: Rng>(
        rng: &mut R,
        peer: &PeerId,
        peers: &[PeerId],
        options: &ScheduleOptions,
    ) -> Request {
        let mut recipient = peer;
        while recipient == peer {
            recipient = unwrap!(rng.choose(peers));
        }
        let req_delay = options.gen_delay(rng);
        let resp_delay = options.gen_delay(rng);
        Request {
            recipient: recipient.clone(),
            req_delay,
            resp_delay,
        }
    }

    fn gen_local_step<R: Rng>(
        rng: &mut R,
        step: usize,
        peer: &PeerId,
        peers: &[PeerId],
        options: &ScheduleOptions,
    ) -> ScheduleEvent {
        let request_timing = match options.gossip_strategy {
            GossipStrategy::Probabilistic(prob) => if rng.gen::<f64>() < prob {
                RequestTiming::DuringThisStep(Self::gen_request(rng, peer, peers, options))
            } else {
                RequestTiming::Later
            },
            GossipStrategy::AfterReceive => {
                RequestTiming::DuringThisStepIfNewData(Self::gen_request(rng, peer, peers, options))
            }
        };
        ScheduleEvent::LocalStep {
            global_step: step,
            peer: peer.clone(),
            request_timing,
        }
    }

    fn gen_votes<R: Rng>(
        rng: &mut R,
        pending: &mut PendingObservations,
        options: &ScheduleOptions,
    ) -> Vec<ScheduleEvent> {
        let mut result = vec![];
        for peer in pending.nonempty_peers() {
            if rng.gen::<f64>() < options.prob_recv_trans {
                let observation = if rng.gen::<f64>() < options.prob_vote_duplication {
                    pending.peek_next_for_peer(&peer)
                } else {
                    pending.next_for_peer(&peer)
                };
                if let Some(observation) = observation {
                    result.push(ScheduleEvent::VoteFor(peer, observation));
                }
            }
        }
        result
    }

    /// Generates a random network event.
    pub fn gen_random<R: Rng>(
        rng: &mut R,
        step: usize,
        peers: &[PeerId],
        // note: first &mut required below to enable reborrowing
        pending: &mut Option<&mut PendingObservations>,
        options: &ScheduleOptions,
    ) -> Vec<ScheduleEvent> {
        let mut result = vec![];
        for peer in peers {
            if rng.gen::<f64>() < options.prob_local_step {
                result.push(Self::gen_local_step(rng, step, peer, peers, options));
            }
        }

        if let Some(pending) = pending {
            result.extend(Self::gen_votes(rng, pending, options));
        }

        if rng.gen::<f64>() < options.prob_failure {
            let peer = unwrap!(rng.choose(peers));
            result.push(ScheduleEvent::Fail(peer.clone()));
        }

        result
    }

    pub fn fail(&self) -> Option<&PeerId> {
        if let ScheduleEvent::Fail(ref peer) = self {
            Some(peer)
        } else {
            None
        }
    }

    pub fn get_peer(&self) -> &PeerId {
        match *self {
            ScheduleEvent::LocalStep { ref peer, .. } => peer,
            ScheduleEvent::Fail(ref peer) => peer,
            ScheduleEvent::VoteFor(ref peer, _) => peer,
        }
    }
}

/// Stores pending observations per node, so that nodes only vote for each observation once.
pub struct PendingObservations(BTreeMap<PeerId, Vec<Observation>>);

impl PendingObservations {
    pub fn new<R: Rng>(
        rng: &mut R,
        peers: &[PeerId],
        observations: &[Observation],
    ) -> PendingObservations {
        let mut inner = BTreeMap::new();
        for peer in peers {
            let mut trans = observations.to_vec();
            rng.shuffle(&mut trans);
            let _ = inner.insert(peer.clone(), trans);
        }
        PendingObservations(inner)
    }

    /// Gets the next observation for a given node, and removes it from the cache
    pub fn next_for_peer(&mut self, peer: &PeerId) -> Option<Observation> {
        self.0.get_mut(peer).and_then(|trans| trans.pop())
    }

    /// Gets the next observation for a given node without removing it
    pub fn peek_next_for_peer(&mut self, peer: &PeerId) -> Option<Observation> {
        self.0.get_mut(peer).and_then(|trans| trans.last().cloned())
    }

    /// Returns the list of names of peers that still have pending observations
    pub fn nonempty_peers(&self) -> Vec<PeerId> {
        self.0
            .iter()
            .filter(|&(_, v)| !v.is_empty())
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Returns true if no more peers have pending observations
    pub fn is_empty(&self) -> bool {
        self.0.values().all(|v| v.is_empty())
    }

    /// Removes peers that failed
    pub fn remove_peers<I: IntoIterator<Item = PeerId>>(&mut self, peers: I) {
        for peer in peers {
            let _ = self.0.remove(&peer);
        }
    }

    /// Returns an iterator of all (peer, observation) pairs, clearing the observation cache in the
    /// process.
    pub fn all_observations(&mut self) -> impl Iterator<Item = (PeerId, Observation)> {
        let data = mem::replace(&mut self.0, BTreeMap::new());
        data.into_iter()
            .flat_map(|(peer, x)| x.into_iter().map(move |trans| (peer.clone(), trans)))
    }
}

/// The condition on which a node gossips when it's scheduled
#[derive(Clone, Copy, Debug)]
pub enum GossipStrategy {
    /// Gossiping with a constant probability per local step
    Probabilistic(f64),
    /// Always gossip after receiving new data
    AfterReceive,
}

/// Available options for the distribution of message delays
#[derive(Clone, Copy, Debug)]
pub enum DelayDistribution {
    Poisson(f64),
    Constant(usize),
}

/// A struct aggregating the options controlling schedule generation
#[derive(Clone, Debug)]
pub struct ScheduleOptions {
    /// Probability per global step that a node will be scheduled to execute a local step
    pub prob_local_step: f64,
    /// Probability per global step that a node will make a vote
    pub prob_recv_trans: f64,
    /// Probabilitity per step that a random node will fail
    pub prob_failure: f64,
    /// Probability that a vote will get repeated
    pub prob_vote_duplication: f64,
    /// A map: step number → num of nodes to fail
    pub deterministic_failures: BTreeMap<usize, usize>,
    /// The distribution of message delays
    pub delay_distr: DelayDistribution,
    /// The strategy that defines when a node gossips
    pub gossip_strategy: GossipStrategy,
    /// When true, nodes will first insert all votes into the graph, then start gossiping
    pub votes_before_gossip: bool,
}

impl ScheduleOptions {
    /// Generates a delay according to the delay distribution
    pub fn gen_delay<R: Rng>(&self, rng: &mut R) -> usize {
        match self.delay_distr {
            DelayDistribution::Poisson(lambda) => poisson(rng, lambda),
            DelayDistribution::Constant(x) => x,
        }
    }
}

impl Default for ScheduleOptions {
    fn default() -> ScheduleOptions {
        ScheduleOptions {
            // local step on average every 6-7 steps - not too often
            prob_local_step: 0.15,
            // vote every 20 steps on average; so that there are local steps scheduled in between
            prob_recv_trans: 0.05,
            // no randomised failures
            prob_failure: 0.0,
            // no vote duplication
            prob_vote_duplication: 0.0,
            // no deterministic failures
            deterministic_failures: BTreeMap::new(),
            // randomised delays, 4 steps on average
            delay_distr: DelayDistribution::Poisson(4.0),
            // gossip when we receive new data
            gossip_strategy: GossipStrategy::AfterReceive,
            // vote while gossiping
            votes_before_gossip: false,
        }
    }
}

/// Stores the list of network events to be simulated.
#[derive(Clone)]
pub struct Schedule {
    pub num_observations: usize,
    pub events: Vec<ScheduleEvent>,
}

impl fmt::Debug for Schedule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "----------------------------")?;
        writeln!(f, " Schedule:")?;
        for event in &self.events {
            writeln!(f, "- {:?}", event)?;
        }
        writeln!(f, "----------------------------")
    }
}

impl Schedule {
    #[cfg(feature = "dump-graphs")]
    fn save(&self, options: &ScheduleOptions) {
        let path = DIR.with(|dir| dir.join("schedule.txt"));
        if let Ok(mut file) = File::create(&path) {
            unwrap!(writeln!(
                file,
                "Generating a schedule with options: {:?}",
                options
            ));
            unwrap!(write!(file, "{:?}", self));
        } else {
            println!("Failed to create {:?}", path);
        }
    }

    fn perform_step<R: Rng>(
        rng: &mut R,
        step: usize,
        peers: &mut Vec<PeerId>,
        // note: mut required below for reborrowing in ScheduleEvent::gen_random
        mut pending: Option<&mut PendingObservations>,
        schedule: &mut Vec<ScheduleEvent>,
        num_peers: usize,
        options: &ScheduleOptions,
    ) {
        // first, generate deterministic failures that are supposed to happen
        let num_deterministic_fails = options
            .deterministic_failures
            .get(&step)
            .cloned()
            .unwrap_or(0);
        // take random peers to fail
        let mut peers_to_fail = peers.clone();
        rng.shuffle(&mut peers_to_fail);
        let mut events: Vec<_> = peers_to_fail
            .into_iter()
            .take(num_deterministic_fails)
            .map(ScheduleEvent::Fail)
            .collect();
        // extend that with random events
        events.extend(ScheduleEvent::gen_random(
            rng,
            step,
            peers,
            &mut pending,
            options,
        ));
        // now, we can have more than max number of failures among events
        // we need to limit that
        // first, we will calculate the max number of failures we can add
        // note: num_peers is the original number of peers, and `peers` only contains
        // active peers, which means they may differ if some peers already failed
        let less_than_a_third_malicious_nodes = (num_peers - 1) / 3;
        let min_honest_nodes = num_peers - less_than_a_third_malicious_nodes;
        let max_number_of_failures = peers.len() - min_honest_nodes;
        // we take out all the failures
        let (fails, mut other): (Vec<_>, _) = events.into_iter().partition(|e| e.fail().is_some());
        // limit them to the max number
        let fails: Vec<_> = fails.into_iter().take(max_number_of_failures).collect();
        // since we have fails separated, take this opportunity to remove failed peers from
        // the peers vector
        let failed_peers: BTreeSet<_> = fails.iter().filter_map(|e| e.fail().cloned()).collect();
        // other events can still refer to failed peers, as they were drawn using the full peer
        // list
        other.retain(|ev| !failed_peers.contains(ev.get_peer()));
        peers.retain(|p| !failed_peers.contains(p));
        if let Some(pending) = pending {
            pending.remove_peers(failed_peers);
        }
        // finally, add all events to results
        schedule.extend(fails);
        schedule.extend(other);
    }

    /// Creates a new pseudo-random schedule based on the given options
    ///
    /// The `let_and_return` clippy lint is allowed since it is actually necessary to create the
    /// `result` variable so the result can be saved when the `dump-graphs` feature is used.
    #[cfg_attr(feature = "cargo-clippy", allow(let_and_return))]
    pub fn new(env: &mut Environment, options: &ScheduleOptions) -> Schedule {
        let mut peers: Vec<_> = env.network.peers.iter().map(|p| p.id.clone()).collect();
        let num_peers = env.network.peers.len();
        let mut pending = PendingObservations::new(&mut env.rng, &peers, &env.observations);
        let mut step = 0;

        // if votes before gossip enabled, insert all votes
        let mut schedule = if options.votes_before_gossip {
            pending
                .all_observations()
                .map(|(p, tx)| ScheduleEvent::VoteFor(p, tx))
                .collect()
        } else {
            vec![]
        };

        while !pending.is_empty() {
            Self::perform_step(
                &mut env.rng,
                step,
                &mut peers,
                Some(&mut pending),
                &mut schedule,
                num_peers,
                options,
            );
            step += 1;
        }
        let n = peers.len() as f64;
        // Gossip should theoretically complete in O(log N) steps
        // But the number of local steps taken by each node depends on the probability
        // of a local step - each node will take on avg [num steps]*[prob] local steps
        // Thus, we divide log N by the probability.
        // The constant (adjustment_coeff) is for making the number big enough.
        let adjustment_coeff = 200.0;
        let additional_steps = (adjustment_coeff * n.ln() / options.prob_local_step) as usize;
        for _ in 0..additional_steps {
            Self::perform_step(
                &mut env.rng,
                step,
                &mut peers,
                None,
                &mut schedule,
                num_peers,
                options,
            );
            step += 1;
        }
        let result = Schedule {
            num_observations: env.observations.len(),
            events: schedule,
        };
        #[cfg(feature = "dump-graphs")]
        result.save(options);
        result
    }
}
