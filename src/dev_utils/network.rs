// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(feature = "testing")]
use super::parse_test_dot_file;
use super::peer::{NetworkView, Peer, PeerStatus};
use super::schedule::{Schedule, ScheduleEvent, ScheduleOptions};
use super::Observation;
use crate::block::Block;
use crate::error::Error;
use crate::gossip::{Request, Response};
use crate::mock::{PeerId, Transaction};
use crate::observation::{
    is_more_than_two_thirds, ConsensusMode, Malice, Observation as ParsecObservation,
};
use rand::Rng;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

enum Message {
    Request(Request<Transaction, PeerId>, usize),
    Response(Response<Transaction, PeerId>),
}

struct QueueEntry {
    pub sender: PeerId,
    pub message: Message,
    pub deliver_after: usize,
}

pub struct Network {
    pub peers: BTreeMap<PeerId, Peer>,
    genesis: BTreeSet<PeerId>,
    msg_queue: BTreeMap<PeerId, Vec<QueueEntry>>,
    consensus_mode: ConsensusMode,
}

#[derive(Debug)]
pub struct BlocksOrder {
    peer: PeerId,
    order: Vec<Observation>,
}

#[derive(Debug)]
pub enum ConsensusError {
    DifferingBlocksOrder {
        order_1: BlocksOrder,
        order_2: BlocksOrder,
    },
    WrongBlocksNumber {
        expected_min: usize,
        expected_max: usize,
        got: usize,
    },
    WrongPeers {
        expected: BTreeMap<PeerId, PeerStatus>,
        got: BTreeMap<PeerId, PeerStatus>,
    },
    InvalidSignatory {
        observation: Observation,
        signatory: PeerId,
    },
    TooFewSignatures {
        observation: Observation,
        signatures: BTreeSet<PeerId>,
    },
    UnexpectedAccusation {
        accuser: PeerId,
        accused: PeerId,
        malice: Malice<Transaction, PeerId>,
    },
}

impl Network {
    /// Create an empty test network.
    pub fn new(consensus_mode: ConsensusMode) -> Self {
        Network {
            peers: BTreeMap::new(),
            genesis: BTreeSet::new(),
            msg_queue: BTreeMap::new(),
            consensus_mode,
        }
    }

    /// Create a test network with initial peers constructed from the given IDs.
    pub fn with_peers<I: IntoIterator<Item = PeerId>>(
        all_ids: I,
        consensus_mode: ConsensusMode,
    ) -> Self {
        let genesis_group = all_ids.into_iter().collect::<BTreeSet<_>>();
        let peers = genesis_group
            .iter()
            .map(|id| {
                (
                    id.clone(),
                    Peer::from_genesis(id.clone(), &genesis_group, consensus_mode),
                )
            })
            .collect();
        Network {
            genesis: genesis_group,
            peers,
            msg_queue: BTreeMap::new(),
            consensus_mode,
        }
    }

    #[cfg(feature = "testing")]
    pub fn from_graphs<I: IntoIterator<Item = &'static str>>(
        consensus_mode: ConsensusMode,
        genesis: BTreeSet<PeerId>,
        names: I,
    ) -> Self {
        let mut peers = BTreeMap::new();
        for name in names {
            let filename = format!("{}.dot", name.to_lowercase());
            let parsed_contents = parse_test_dot_file(&filename);
            let id = parsed_contents.our_id.clone();
            let _ = peers.insert(id, Peer::from_parsed_contents(parsed_contents));
        }
        Network {
            peers,
            genesis,
            msg_queue: BTreeMap::new(),
            consensus_mode,
        }
    }

    pub fn consensus_mode(&self) -> ConsensusMode {
        self.consensus_mode
    }

    fn active_peers(&self) -> impl Iterator<Item = &Peer> {
        self.peers
            .values()
            .filter(|peer| peer.status() == PeerStatus::Active)
    }

    /// Returns the IDs of peers which consider themselves to be still running correctly, i.e. those
    /// for which `is_running()` is true.
    fn running_peers_ids(&self) -> Vec<PeerId> {
        self.peers
            .values()
            .filter_map(|peer| {
                if peer.is_running() {
                    Some(peer.id().clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns the number of peers for which the network has the given view of their state.
    fn num_with_network_view(&self, network_view: NetworkView) -> usize {
        self.peers
            .values()
            .filter(|peer| peer.network_view() == network_view)
            .count()
    }

    /// Returns true if all peers hold the same sequence of stable blocks.
    fn check_blocks_all_in_sequence(&self) -> Result<(), ConsensusError> {
        let first_peer = unwrap!(self.active_peers().next());
        let payloads = first_peer.blocks_payloads();
        if let Some(peer) = self
            .active_peers()
            .find(|peer| peer.blocks_payloads() != payloads)
        {
            Err(ConsensusError::DifferingBlocksOrder {
                order_1: BlocksOrder {
                    peer: first_peer.id().clone(),
                    order: payloads.into_iter().cloned().collect(),
                },
                order_2: BlocksOrder {
                    peer: peer.id().clone(),
                    order: peer.blocks_payloads().into_iter().cloned().collect(),
                },
            })
        } else {
            Ok(())
        }
    }

    fn peer(&self, id: &PeerId) -> &Peer {
        unwrap!(self.peers.get(id))
    }

    fn peer_mut(&mut self, id: &PeerId) -> &mut Peer {
        unwrap!(self.peers.get_mut(id))
    }

    fn send_message(&mut self, src: PeerId, dst: &PeerId, message: Message, deliver_after: usize) {
        if !self.peer(dst).is_running() {
            return;
        }
        self.msg_queue
            .entry(dst.clone())
            .or_insert_with(Vec::new)
            .push(QueueEntry {
                sender: src,
                message,
                deliver_after,
            });
    }

    /// Handles incoming requests and responses.
    fn handle_messages(&mut self, peer: &PeerId, step: usize) {
        if let Some(msgs) = self.msg_queue.remove(peer) {
            let (to_handle, rest) = msgs
                .into_iter()
                .partition(|entry| entry.deliver_after <= step);
            let _ = self.msg_queue.insert(peer.clone(), rest);
            for entry in to_handle {
                match entry.message {
                    Message::Request(req, resp_delay) => match self
                        .peer_mut(peer)
                        .parsec
                        .handle_request(&entry.sender, req)
                    {
                        Ok(response) => {
                            self.send_message(
                                peer.clone(),
                                &entry.sender,
                                Message::Response(response),
                                step + resp_delay,
                            );
                        }
                        Err(Error::UnknownPeer) | Err(Error::InvalidPeerState { .. }) => (),
                        Err(e) => panic!("{:?}", e),
                    },
                    Message::Response(resp) => unwrap!(self
                        .peer_mut(peer)
                        .parsec
                        .handle_response(&entry.sender, resp)),
                }
            }
        }
    }

    fn send_gossip<R: Rng>(
        &mut self,
        rng: &mut R,
        options: &ScheduleOptions,
        sender: &PeerId,
        present_peers: &[PeerId],
        step: usize,
    ) {
        let recipient = loop {
            let recipient = unwrap!(rng.choose(present_peers));
            if recipient != sender {
                break recipient;
            }
        };
        let valid = self
            .peer(sender)
            .parsec
            .gossip_recipients()
            .any(|valid_recipient| valid_recipient == recipient);
        let result = self.peer(sender).parsec.create_gossip(Some(recipient));

        if valid {
            // Recipient is valid. `create_gossip` must have succeeded.
            let request = unwrap!(result);
            let req_delay = options.gen_delay(rng);
            let resp_delay = options.gen_delay(rng);
            self.send_message(
                sender.clone(),
                recipient,
                Message::Request(request, resp_delay),
                step + req_delay,
            );
        } else {
            // Recipient is not valid. `create_gossip` must have failed.
            match result {
                Err(Error::InvalidSelfState { .. })
                | Err(Error::InvalidPeerState { .. })
                | Err(Error::UnknownPeer) => (),
                x => panic!("Unexpected {:?}", x),
            }
        }
    }

    fn check_consensus_broken(&self) -> Result<(), ConsensusError> {
        let mut block_order = BTreeMap::new();
        for peer in self.active_peers() {
            for (index, block) in peer.blocks().iter().enumerate() {
                let key = self.block_key(block);

                if let Some((old_peer, old_index)) = block_order.insert(key, (peer, index)) {
                    if old_index != index {
                        // old index exists and isn't equal to the new one
                        return Err(ConsensusError::DifferingBlocksOrder {
                            order_1: BlocksOrder {
                                peer: peer.id().clone(),
                                order: peer.blocks_payloads().into_iter().cloned().collect(),
                            },
                            order_2: BlocksOrder {
                                peer: old_peer.id().clone(),
                                order: old_peer.blocks_payloads().into_iter().cloned().collect(),
                            },
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn block_key<'a>(
        &self,
        block: &'a Block<Transaction, PeerId>,
    ) -> (&'a Observation, Option<&'a PeerId>) {
        let peer_id = if block.payload().is_opaque() {
            if self.consensus_mode == ConsensusMode::Single {
                Some(&unwrap!(block.proofs().iter().next()).public_id)
            } else {
                None
            }
        } else {
            None
        };

        (block.payload(), peer_id)
    }

    fn consensus_complete(
        &self,
        expected_peers: &BTreeMap<PeerId, PeerStatus>,
        num_expected_observations: usize,
    ) -> bool {
        self.check_consensus(
            expected_peers,
            num_expected_observations,
            num_expected_observations,
        )
        .is_ok()
    }

    /// Checks whether there is a right number of blocks and the blocks are in an agreeing order.
    fn check_consensus(
        &self,
        expected_peers: &BTreeMap<PeerId, PeerStatus>,
        min_expected_observations: usize,
        max_expected_observations: usize,
    ) -> Result<(), ConsensusError> {
        // Check the number of consensused blocks.
        let got = unwrap!(self.active_peers().next()).blocks_payloads().len();
        if got < min_expected_observations || got > max_expected_observations {
            return Err(ConsensusError::WrongBlocksNumber {
                expected_min: min_expected_observations,
                expected_max: max_expected_observations,
                got,
            });
        }

        // Check peers.
        let got = self
            .peers
            .values()
            .map(|peer| (peer.id().clone(), peer.status()))
            .collect();
        if *expected_peers != got {
            return Err(ConsensusError::WrongPeers {
                expected: expected_peers.clone(),
                got,
            });
        }

        // Check everybody has the same blocks in the same order.
        self.check_blocks_all_in_sequence()
    }

    fn check_block_signatories(
        &self,
        block: &Block<Transaction, PeerId>,
        section: &BTreeSet<PeerId>,
    ) -> Result<(), ConsensusError> {
        let signatories: BTreeSet<_> = block
            .proofs()
            .iter()
            .map(|proof| proof.public_id().clone())
            .collect();
        if let Some(pub_id) = signatories.difference(section).next() {
            return Err(ConsensusError::InvalidSignatory {
                observation: block.payload().clone(),
                signatory: pub_id.clone(),
            });
        }

        let consensus_mode = if block.payload().is_opaque() {
            self.consensus_mode
        } else {
            ConsensusMode::Supermajority
        };
        let correct_signatories = match consensus_mode {
            ConsensusMode::Single => !signatories.is_empty(),
            ConsensusMode::Supermajority => {
                is_more_than_two_thirds(signatories.len(), section.len())
            }
        };
        if !correct_signatories {
            return Err(ConsensusError::TooFewSignatures {
                observation: block.payload().clone(),
                signatures: signatories,
            });
        }
        Ok(())
    }

    /// Checks if the blocks are only signed by valid voters.
    fn check_blocks_signatories(&self) -> Result<(), ConsensusError> {
        let blocks = unwrap!(self.active_peers().next()).blocks();
        let mut valid_voters = BTreeSet::new();
        for block in blocks {
            match *block.payload() {
                ParsecObservation::Genesis(ref g) => {
                    // Explicitly don't check signatories - the list of valid voters should be empty
                    // at this point.
                    valid_voters = g.clone();
                }
                ParsecObservation::Add { ref peer_id, .. } => {
                    self.check_block_signatories(block, &valid_voters)?;
                    let _ = valid_voters.insert(peer_id.clone());
                }
                ParsecObservation::Remove { ref peer_id, .. } => {
                    self.check_block_signatories(block, &valid_voters)?;
                    let _ = valid_voters.remove(peer_id);
                }
                _ => {
                    self.check_block_signatories(block, &valid_voters)?;
                }
            }
        }
        Ok(())
    }

    /// Check that no node has been accused of malice.
    fn check_unexpected_accusations(&self, peer_id: &PeerId) -> Result<(), ConsensusError> {
        let peer = self.peer(peer_id);
        let accusation = peer
            .unpolled_accusations()
            .find(|(_, malice)| malice.is_provable());
        if let Some((offender, malice)) = accusation {
            return Err(ConsensusError::UnexpectedAccusation {
                accuser: peer.id().clone(),
                accused: offender.clone(),
                malice: malice.clone(),
            });
        } else {
            Ok(())
        }
    }

    /// Simulates the network according to the given schedule.
    pub fn execute_schedule<R: Rng>(
        &mut self,
        rng: &mut R,
        schedule: Schedule,
    ) -> Result<(), ConsensusError> {
        let Schedule {
            peers,
            min_observations,
            max_observations,
            events,
            options,
        } = schedule;
        let mut queue: VecDeque<_> = events.into_iter().collect();
        let mut retry = Vec::new();

        while let Some(event) = queue.pop_front() {
            if self.execute_event(rng, &options, event.clone())? {
                for event in retry.drain(..).rev() {
                    queue.push_front(event)
                }

                self.check_consensus_broken()?;
                if self.consensus_complete(&peers, max_observations) {
                    break;
                }
            } else {
                retry.push(event);
            }
        }

        self.check_consensus(&peers, min_observations, max_observations)?;
        self.check_blocks_signatories()
    }

    // Returns 'Ok(true)' when event got executed, or 'Ok(false)' when the event needs to be delayed
    // due to the parsec membership status.
    fn execute_event<R: Rng>(
        &mut self,
        rng: &mut R,
        options: &ScheduleOptions,
        event: ScheduleEvent,
    ) -> Result<bool, ConsensusError> {
        match event {
            ScheduleEvent::Genesis(genesis_group) => {
                if !self.peers.is_empty() {
                    // If the peers are already initialised, we won't initialise them again.
                    return Ok(true);
                }
                let peers = genesis_group
                    .iter()
                    .map(|id| {
                        (
                            id.clone(),
                            Peer::from_genesis(id.clone(), &genesis_group, self.consensus_mode),
                        )
                    })
                    .collect();
                self.peers = peers;
                self.genesis = genesis_group;
                // Do a full reset while we're at it.
                self.msg_queue.clear();
            }
            ScheduleEvent::AddPeer(peer_id) => {
                let current_peers = self.active_peers().map(|peer| peer.id().clone()).collect();
                let _ = self.peers.insert(
                    peer_id.clone(),
                    Peer::from_existing(
                        peer_id.clone(),
                        &self.genesis,
                        &current_peers,
                        self.consensus_mode,
                    ),
                );
            }
            ScheduleEvent::RemovePeer(peer_id) => {
                if self.allow_removal_of_peer(&peer_id) {
                    (*self.peer_mut(&peer_id)).mark_as_removed();
                } else {
                    return Ok(false);
                }
            }
            ScheduleEvent::Fail(peer_id) => {
                if self.allow_removal_of_peer(&peer_id) {
                    (*self.peer_mut(&peer_id)).mark_as_failed();
                } else {
                    return Ok(false);
                }
            }
            ScheduleEvent::LocalStep(step) => {
                println!("processing step {:?} ", step);
                let stop = 47;
                if step > stop {
                    panic!("reached step {}", stop);
                }
                for peer_id in self.running_peers_ids() {
                    self.peer_mut(&peer_id).make_votes();
                    self.handle_messages(&peer_id, step);
                    self.peer_mut(&peer_id).poll_all();
                    if let Err(_err) = self.check_unexpected_accusations(&peer_id) {
                        // println!("Peer {:?} find unexpected_accusations {:?}", peer_id, err);
                    };
                }
                Peer::update_network_views(&mut self.peers);
                let running_peers_ids = self.running_peers_ids();
                for peer_id in &running_peers_ids {
                    if rng.gen::<f64>() < options.prob_gossip {
                        self.send_gossip(rng, options, peer_id, &running_peers_ids, step);
                    }
                }
            }
            ScheduleEvent::VoteFor(voting_peer_id, observation) => {
                // Skip voting by removed/failed peers.
                if !self.peer(&voting_peer_id).is_running() {
                    return Ok(true);
                }

                if let ParsecObservation::Remove { ref peer_id, .. } = observation {
                    if self.allow_removal_of_peer(&peer_id) {
                        (*self.peer_mut(&peer_id)).mark_network_view_as_leaving();
                    } else {
                        return Ok(false);
                    }
                }

                self.peer_mut(&voting_peer_id).vote_for(&observation);
            }
        }
        Ok(true)
    }

    fn allow_removal_of_peer(&self, peer_id: &PeerId) -> bool {
        match self.peer(peer_id).network_view() {
            NetworkView::Joining => false,
            NetworkView::Joined => {
                let joined_count = self.num_with_network_view(NetworkView::Joined);
                let leaving_count = self.num_with_network_view(NetworkView::Leaving);
                let current_count = joined_count + leaving_count;
                is_more_than_two_thirds(joined_count - 1, current_count)
            }
            NetworkView::Leaving | NetworkView::Left => true,
        }
    }
}
