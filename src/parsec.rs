// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
#[cfg(test)]
use dev_utils::ParsedContents;
use dump_graph;
use error::Error;
use gossip::{Event, PackedEvent, Request, Response};
use hash::Hash;
use id::SecretId;
use meta_vote::{MetaVote, MetaVotesMap, Step};
#[cfg(test)]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use observation::{Malice, Observation};
use peer_list::{PeerList, PeerState};
use serialise;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::iter;

pub type IsInterestingEventFn<P> = fn(voters: &BTreeSet<&P>, current_peers: &BTreeSet<&P>) -> bool;

/// Returns whether `small` is more than two thirds of `large`
pub fn is_more_than_two_thirds(small: usize, large: usize) -> bool {
    3 * small > 2 * large
}

/// Function which can be used as `is_interesting_event` in
/// [`Parsec::new()`](struct.Parsec.html#method.new) and which returns `true` if there are >2/3
/// `voters` which are members of `current_peers`.
pub fn is_supermajority<P: Ord>(voters: &BTreeSet<&P>, current_peers: &BTreeSet<&P>) -> bool {
    let valid_voter_count = current_peers.intersection(voters).count();
    is_more_than_two_thirds(valid_voter_count, current_peers.len())
}

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused `Block`s by applying the PARSEC algorithm.
///
/// Most public functions return an error if called after the owning node has been removed, i.e.
/// a block with payload `Observation::Remove(our_id)` has been made stable.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
    // The PeerInfo of other nodes.
    peer_list: PeerList<S>,
    // Gossip events created locally and received from other peers.
    events: BTreeMap<Hash, Event<T, S::PublicId>>,
    // The sequence in which all gossip events were added to this `Parsec`.
    events_order: Vec<Hash>,
    // The hashes of events for each peer that have a non-empty set of `interesting_content`
    interesting_events: BTreeMap<S::PublicId, VecDeque<Hash>>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: VecDeque<Block<T, S::PublicId>>,
    // The map of meta votes of the events on each consensus block.
    meta_votes_map: MetaVotesMap<S::PublicId>,
    is_interesting_event: IsInterestingEventFn<S::PublicId>,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs (ours included).
    /// Version to be used in production
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        is_interesting_event: IsInterestingEventFn<S::PublicId>,
    ) -> Self {
        if !genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group must contain us");
        }

        let mut parsec = Self::empty(our_id, is_interesting_event);

        for peer_id in genesis_group {
            parsec
                .peer_list
                .add_peer(peer_id.clone(), PeerState::active());
        }

        parsec
            .meta_votes_map
            .initialise_round_hashes(parsec.peer_list.all_ids());

        // Add initial event.
        let event = Event::new_initial(&parsec.peer_list);
        if let Err(error) = parsec.add_event(event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        // Add event carying genesis observation.
        let genesis_observation = Observation::Genesis(genesis_group.clone());
        let self_parent_hash = parsec.our_last_event_hash();
        let event = Event::new_from_observation(
            self_parent_hash,
            genesis_observation,
            &parsec.events,
            &parsec.peer_list,
        );

        if let Err(error) = parsec.add_event(event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding the genesis observation: {:?}",
                parsec.our_pub_id(),
                error,
            );
        }

        parsec
    }

    /// Creates a new `Parsec` for a peer that is joining an existing section.
    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
        is_interesting_event: IsInterestingEventFn<S::PublicId>,
    ) -> Self {
        if genesis_group.is_empty() {
            log_or_panic!("Genesis group can't be empty");
        }

        if genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group can't already contain us");
        }

        if section.is_empty() {
            log_or_panic!("Section can't be empty");
        }

        if section.contains(our_id.public_id()) {
            log_or_panic!("Section can't already contain us");
        }

        let our_public_id = our_id.public_id().clone();
        let mut parsec = Self::empty(our_id, is_interesting_event);

        parsec.peer_list.add_peer(our_public_id, PeerState::RECV);

        for peer_id in genesis_group {
            parsec
                .peer_list
                .add_peer(peer_id.clone(), PeerState::VOTE | PeerState::SEND)
        }

        for peer_id in section {
            parsec.peer_list.add_peer(peer_id.clone(), PeerState::SEND);
        }

        parsec
            .meta_votes_map
            .initialise_round_hashes(parsec.peer_list.all_ids());

        let initial_event = Event::new_initial(&parsec.peer_list);
        if let Err(error) = parsec.add_event(initial_event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        parsec
    }

    // Construct empty `Parsec` with no peers (except us) and no gossip events.
    fn empty(our_id: S, is_interesting_event: IsInterestingEventFn<S::PublicId>) -> Self {
        dump_graph::init();

        Self {
            peer_list: PeerList::new(our_id),
            events: BTreeMap::new(),
            events_order: vec![],
            interesting_events: BTreeMap::new(),
            consensused_blocks: VecDeque::new(),
            meta_votes_map: MetaVotesMap::new(),
            is_interesting_event,
        }
    }

    /// Adds a vote for `observation`.  Returns an error if we have already voted for this.
    pub fn vote_for(&mut self, observation: Observation<T, S::PublicId>) -> Result<(), Error> {
        debug!("{:?} voting for {:?}", self.our_pub_id(), observation);

        self.confirm_self_state(PeerState::VOTE)?;

        if self.have_voted_for(&observation) {
            return Err(Error::DuplicateVote);
        }

        let self_parent_hash = self.our_last_event_hash();
        let event = Event::new_from_observation(
            self_parent_hash,
            observation,
            &self.events,
            &self.peer_list,
        );
        self.add_event(event)
    }

    /// Creates a new message to be gossiped to a peer containing all gossip events this node thinks
    /// that peer needs.  If `peer_id` is `None`, a message containing all known gossip events is
    /// returned.  If `peer_id` is `Some` and the given peer is not an active node, an error is
    /// returned.
    pub fn create_gossip(
        &self,
        peer_id: Option<&S::PublicId>,
    ) -> Result<Request<T, S::PublicId>, Error> {
        self.confirm_self_state(PeerState::SEND)?;

        if let Some(recipient_id) = peer_id {
            // We require `PeerState::VOTE` in addition to `PeerState::RECV` here,
            // Because if the peer does not have `PeerState::VOTE`, it means we haven't
            // yet reached consensus on adding them to the section so we shouldn't contact
            // them yet.
            self.confirm_peer_state(recipient_id, PeerState::VOTE | PeerState::RECV)?;

            if self.peer_list.last_event_hash(recipient_id).is_some() {
                debug!(
                    "{:?} creating gossip request for {:?}",
                    self.our_pub_id(),
                    recipient_id
                );

                return self
                    .events_to_gossip_to_peer(recipient_id)
                    .map(Request::new);
            }
        }

        debug!(
            "{:?} creating gossip request for {:?}",
            self.our_pub_id(),
            peer_id
        );

        let mut events = vec![];
        for event_hash in &self.events_order {
            events.push(self.get_known_event(event_hash)?);
        }
        Ok(Request::new(events.into_iter()))
    }

    /// Handles a received `Request` from `src` peer.  Returns a `Response` to be sent back to `src`
    /// or `Err` if the request was not valid or if `src` has been removed already.
    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>, Error> {
        debug!(
            "{:?} received gossip request from {:?}",
            self.our_pub_id(),
            src
        );
        self.unpack_and_add_events(src, req.packed_events)?;
        self.create_sync_event(src, true)?;
        self.events_to_gossip_to_peer(src).map(Response::new)
    }

    /// Handles a received `Response` from `src` peer.  Returns `Err` if the response was not valid
    /// or if `src` has been removed already.
    pub fn handle_response(
        &mut self,
        src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<(), Error> {
        debug!(
            "{:?} received gossip response from {:?}",
            self.our_pub_id(),
            src
        );
        self.unpack_and_add_events(src, resp.packed_events)?;
        self.create_sync_event(src, false)
    }

    /// Steps the algorithm and returns the next stable block, if any.
    ///
    /// Once we have been removed (i.e. a block with payload `Observation::Remove(our_id)` has been
    /// made stable), then no further blocks will be enqueued.  So, once `poll()` returns such a
    /// block, it will continue to return `None` forever.
    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        self.consensused_blocks.pop_front()
    }

    /// Check if we can vote (that is, we have reached a consensus on us being
    /// full member of the section)
    pub fn can_vote(&self) -> bool {
        self.peer_list.peer_state(self.our_pub_id()).can_vote()
    }

    /// Checks if the given `observation` has already been voted for by us.
    pub fn have_voted_for(&self, observation: &Observation<T, S::PublicId>) -> bool {
        self.events.values().any(|event| {
            event.creator() == self.our_pub_id() && event
                .vote()
                .map_or(false, |voted| voted.payload() == observation)
        })
    }

    /// Must only be used for events which have already been added to our graph.
    fn get_known_event(&self, event_hash: &Hash) -> Result<&Event<T, S::PublicId>, Error> {
        self.events.get(event_hash).ok_or_else(|| {
            log_or_panic!(
                "{:?} doesn't have event {:?}",
                self.our_pub_id(),
                event_hash
            );
            Error::Logic
        })
    }

    /// Must only be used for events which have already been added to our graph.
    fn get_known_event_mut(
        &mut self,
        event_hash: &Hash,
    ) -> Result<&mut Event<T, S::PublicId>, Error> {
        let our_id = self.our_pub_id().clone();
        self.events.get_mut(event_hash).ok_or_else(|| {
            log_or_panic!("{:?} doesn't have event {:?}", our_id, event_hash);
            Error::Logic
        })
    }

    fn our_pub_id(&self) -> &S::PublicId {
        self.peer_list.our_id().public_id()
    }

    fn confirm_peer_state(&self, peer_id: &S::PublicId, required: PeerState) -> Result<(), Error> {
        let actual = self.peer_list.peer_state(peer_id);
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} detected invalid state of {:?} (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                peer_id,
                required,
                actual,
            );
            Err(Error::InvalidPeerState { required, actual })
        }
    }

    fn confirm_self_state(&self, required: PeerState) -> Result<(), Error> {
        let actual = self.peer_list.our_state();
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} has invalid state (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                required,
                actual,
            );
            Err(Error::InvalidSelfState { required, actual })
        }
    }

    fn our_last_event_hash(&self) -> Hash {
        if let Some(hash) = self.peer_list.last_event_hash(self.our_pub_id()) {
            *hash
        } else {
            log_or_panic!(
                "{:?} has no last event hash.\n{:?}\n",
                self.our_pub_id(),
                self.peer_list
            );
            Hash::from([].as_ref())
        }
    }

    fn self_parent<'a>(
        &'a self,
        event: &Event<T, S::PublicId>,
    ) -> Option<&'a Event<T, S::PublicId>> {
        event.self_parent().and_then(|hash| self.events.get(hash))
    }

    fn has_supermajority_observations(&self, event: &Event<T, S::PublicId>) -> bool {
        self.peer_list.is_super_majority(event.observations.len())
    }

    fn is_observer(&self, event: &Event<T, S::PublicId>) -> bool {
        // an event is an observer if it has a supermajority of observations and its self-parent
        // does not
        self.has_supermajority_observations(event) && self.self_parent(event).map_or_else(
            || {
                log_or_panic!("{:?} has observations, but no self-parent", event);
                true
            },
            |parent| !self.has_supermajority_observations(parent),
        )
    }

    fn unpack_and_add_events(
        &mut self,
        src: &S::PublicId,
        packed_events: Vec<PackedEvent<T, S::PublicId>>,
    ) -> Result<(), Error> {
        self.confirm_self_state(PeerState::RECV)?;
        self.confirm_peer_state(src, PeerState::SEND)?;

        // We have received at least one gossip from the sender, so they can now
        // receive gossips from us as well.
        self.peer_list.add_peer(src.clone(), PeerState::RECV);

        for packed_event in packed_events {
            if let Some(event) = Event::unpack(packed_event, &self.events, &self.peer_list)? {
                self.add_event(event)?;
            }
        }
        Ok(())
    }

    fn add_event(&mut self, event: Event<T, S::PublicId>) -> Result<(), Error> {
        self.peer_list.add_event(&event)?;
        let event_hash = *event.hash();
        let is_initial = event.is_initial();

        if !self.peer_list.our_state().contains(PeerState::VOTE)
            && event.creator() != self.our_pub_id()
        {
            // We're handling an event before we've been made active.  If it's not one of our own
            // events, it means we're in the process of handling our first incoming request.  Insert
            // it immediately before our initial event, so that when we calculate the list of events
            // to give in response to this request, we don't include the entire graph.
            let index = self
                .events_order
                .iter()
                .rev()
                .skip_while(|&hash| {
                    self.get_known_event(hash)
                        .map(|event| event.creator() == self.our_pub_id())
                        .unwrap_or(false)
                }).count();
            self.events_order.insert(index, event_hash);
        } else {
            self.events_order.push(event_hash);
        }

        let _ = self.events.insert(event_hash, event);

        if is_initial {
            return Ok(());
        }

        self.set_interesting_content(&event_hash)?;
        self.process_event(&event_hash)?;
        self.handle_malice(&event_hash)?;

        Ok(())
    }

    fn process_event(&mut self, event_hash: &Hash) -> Result<(), Error> {
        self.set_observations(event_hash)?;
        self.set_meta_votes(event_hash)?;
        self.meta_votes_map
            .update_last_election_round_hashes(event_hash);

        if let Some(block) = self.next_stable_block(event_hash) {
            dump_graph::to_file(
                self.our_pub_id(),
                &self.events,
                &self.meta_votes_map.last_meta_votes(),
                &self.peer_list,
            );
            self.clear_consensus_data();

            let payload_hash = block.create_payload_hash();
            info!(
                "{:?} got consensus on block {} with payload {:?} and payload hash {:?}",
                self.our_pub_id(),
                self.meta_votes_map.consensus_history().len(),
                block.payload(),
                payload_hash
            );
            self.meta_votes_map.push_last_block_hash(payload_hash);

            let observation = block.payload().clone();
            self.consensused_blocks.push_back(block);

            if !self.handle_consensus(observation) {
                return Ok(());
            }

            self.restart_consensus();
        }
        Ok(())
    }

    fn handle_consensus(&mut self, observation: Observation<T, S::PublicId>) -> bool {
        match observation {
            Observation::Genesis(_) => {
                // TODO: handle malice
            }
            Observation::Add(peer_id) => {
                // - If we are already full member of the section, we can start
                //   sending gossips to the new peer from this moment.
                // - If we are the new peer, we must wait for the other members
                //   to send gossips to us first.
                //
                // To distinguish between the two, we check whether everyone we
                // reached consensus on adding also reached consensus on adding us.
                let recv = self
                    .peer_list
                    .iter()
                    .filter(|&(id, peer)| {
                        // Peers that can vote, which means we have reached consensus
                        // on adding them.
                        peer.state.can_vote() &&
                        // Excluding the peer begin added.
                        *id != peer_id &&
                        // And excluding us.
                        *id != *self.our_pub_id()
                    }).all(|(_, peer)| {
                        // Peers that can receive, which implies they've already
                        // sent us at least one message which implies they've already
                        // reached consensus on adding us.
                        peer.state.can_recv()
                    });

                self.peer_list.add_peer(
                    peer_id,
                    if recv {
                        PeerState::VOTE | PeerState::SEND | PeerState::RECV
                    } else {
                        PeerState::VOTE | PeerState::SEND
                    },
                );
            }
            Observation::Remove(peer_id) => {
                self.peer_list.remove_peer(&peer_id);
                if peer_id == *self.our_pub_id() {
                    return false;
                }
            }
            Observation::Accusation { offender, malice } => {
                info!(
                    "{:?} removing {:?} due to consensus on accusation of malice {:?}",
                    self.our_pub_id(),
                    offender,
                    malice
                );
                self.peer_list.remove_peer(&offender);
            }
            Observation::OpaquePayload(_) => {}
        }

        true
    }

    fn set_interesting_content(&mut self, event_hash: &Hash) -> Result<(), Error> {
        let interesting_content = self.interesting_content(event_hash)?;
        if !interesting_content.is_empty() {
            let creator_id = self.get_known_event(event_hash)?.creator().clone();
            let _ = self
                .interesting_events
                .entry(creator_id)
                .and_modify(|hashes| {
                    hashes.push_back(*event_hash);
                }).or_insert_with(|| iter::once(*event_hash).collect());
        }
        self.get_known_event_mut(event_hash)
            .map(|ref mut event| event.interesting_content.extend(interesting_content))
    }

    // Any payloads which this event sees as "interesting".  If this returns a non-empty set, then
    // this event is classed as an interesting one.
    fn interesting_content(
        &self,
        event_hash: &Hash,
    ) -> Result<Vec<Observation<T, S::PublicId>>, Error> {
        let event = self.get_known_event(event_hash)?;
        let indexed_payloads_map: BTreeMap<_, _> = self
            .peer_list
            .iter()
            .flat_map(|(_peer_id, peer)| {
                peer.events.iter().filter_map(|(_index, hash)| {
                    self.events
                        .get(hash)
                        .and_then(|event| event.vote().map(|vote| vote.payload()))
                })
            }).filter(|&this_payload| !self.payload_is_already_carried(event, this_payload))
            .filter_map(|this_payload| {
                let voters_indices = self.ancestors_carrying_payload(event, this_payload);
                let all_peers = self.peer_list.voter_ids().collect();
                if (self.is_interesting_event)(
                    &voters_indices.keys().cloned().collect(),
                    &all_peers,
                ) {
                    Some((
                        this_payload.clone(),
                        voters_indices
                            .get(event.creator())
                            .cloned()
                            // sometimes the interesting event's creator won't have voted for the
                            // payload that became interesting - in such a case we would like it
                            // sorted at the end of the "queue"
                            .unwrap_or(::std::u64::MAX),
                    ))
                } else {
                    None
                }
            }).collect();
        let mut indexed_payloads: Vec<_> = indexed_payloads_map.into_iter().collect();
        indexed_payloads.sort_by_key(|&(_, index)| index);
        Ok(indexed_payloads
            .into_iter()
            .map(|(payload, _index)| payload)
            .collect())
    }

    fn payload_is_already_carried(
        &self,
        event: &Event<T, S::PublicId>,
        payload: &Observation<T, S::PublicId>,
    ) -> bool {
        let hashes = self.interesting_events.get(event.creator());
        hashes.map_or(false, |hashes| {
            hashes.iter().any(|hash| {
                if let Ok(event) = self.get_known_event(hash) {
                    event.interesting_content.contains(payload)
                } else {
                    false
                }
            })
        })
    }

    fn ancestors_carrying_payload(
        &self,
        event: &Event<T, S::PublicId>,
        payload: &Observation<T, S::PublicId>,
    ) -> BTreeMap<&S::PublicId, u64> {
        let payload_already_reached_consensus = self
            .meta_votes_map
            .consensus_history()
            .iter()
            .any(|payload_hash| *payload_hash == Hash::from(serialise(&payload).as_slice()));
        if payload_already_reached_consensus {
            return BTreeMap::new();
        }
        let sees_vote_for_same_payload = |pair: &(&u64, &Hash)| {
            let (_index, event_hash) = *pair;
            match self.get_known_event(event_hash) {
                Ok(that_event) => {
                    Some(payload) == that_event.vote().map(|vote| vote.payload())
                        && event.sees(that_event)
                }
                Err(_) => false,
            }
        };
        self.peer_list
            .iter()
            .filter_map(|(peer_id, peer)| {
                peer.events
                    .iter()
                    .find(sees_vote_for_same_payload)
                    .map(|(index, _hash)| (peer_id, *index))
            }).collect()
    }

    fn set_observations(&mut self, event_hash: &Hash) -> Result<(), Error> {
        let observations = {
            let event = self.get_known_event(event_hash)?;
            self.interesting_events
                .iter()
                .filter_map(|(peer, hashes)| {
                    let old_hash = hashes.front()?;
                    let old_event = self.get_known_event(old_hash).ok()?;
                    if self.strongly_sees(event, old_event) {
                        Some(peer)
                    } else {
                        None
                    }
                }).cloned()
                .collect()
        };
        self.get_known_event_mut(event_hash)
            .map(|ref mut event| event.observations = observations)
    }

    fn set_meta_votes(&mut self, event_hash: &Hash) -> Result<(), Error> {
        let total_peers = self.peer_list.voters().count();
        let mut meta_votes = BTreeMap::new();
        // If self-parent already has meta votes associated with it, derive this event's meta votes
        // from those ones.
        {
            let event = self.get_known_event(event_hash)?;
            if let Some(parent_votes) = self.self_parent(event).and_then(|parent| {
                self.meta_votes_map
                    .get_mvs_from_last_election(parent.hash())
                    .cloned()
            }) {
                for (peer_id, parent_event_votes) in parent_votes {
                    let new_meta_votes = {
                        let other_votes = self.collect_other_meta_votes(&peer_id, event);
                        let coin_tosses = self.toss_coins(&peer_id, &parent_event_votes, event)?;
                        MetaVote::next(&parent_event_votes, &other_votes, &coin_tosses, total_peers)
                    };
                    let _ = meta_votes.insert(peer_id, new_meta_votes);
                }
            } else if self.is_observer(event) {
                // Start meta votes for this event.
                for peer_id in self.peer_list.voter_ids() {
                    let other_votes = self.collect_other_meta_votes(peer_id, event);
                    let initial_estimate = event.observations.contains(peer_id);
                    let _ = meta_votes.insert(
                        peer_id.clone(),
                        MetaVote::new(initial_estimate, &other_votes, total_peers),
                    );
                }
            };
            trace!(
                "{:?} has set the meta votes for {:?}",
                self.our_pub_id(),
                event
            );
        }

        if !meta_votes.is_empty() {
            self.meta_votes_map
                .insert_into_last_election(*event_hash, meta_votes);
        }
        Ok(())
    }

    fn toss_coins(
        &self,
        peer_id: &S::PublicId,
        parent_votes: &[MetaVote],
        event: &Event<T, S::PublicId>,
    ) -> Result<BTreeMap<usize, bool>, Error> {
        let mut coin_tosses = BTreeMap::new();
        for parent_vote in parent_votes {
            let _ = self
                .toss_coin(peer_id, parent_vote, event)?
                .map(|coin| coin_tosses.insert(parent_vote.round, coin));
        }
        Ok(coin_tosses)
    }

    fn toss_coin(
        &self,
        peer_id: &S::PublicId,
        parent_vote: &MetaVote,
        event: &Event<T, S::PublicId>,
    ) -> Result<Option<bool>, Error> {
        // Get the round hash.
        let round = if parent_vote.estimates.is_empty() {
            // We're waiting for the coin toss result already.
            if parent_vote.round == 0 {
                // This should never happen as estimates get cleared only in increase step when the
                // step is Step::GenuineFlip and the round gets incremented
                log_or_panic!(
                    "{:?} missing parent vote estimates at round 0.",
                    self.our_pub_id()
                );
                return Err(Error::Logic);
            }
            parent_vote.round - 1
        } else if parent_vote.step == Step::GenuineFlip {
            parent_vote.round
        } else {
            return Ok(None);
        };
        let round_hash =
            if let Some(hashes) = self.meta_votes_map.get_rhs_from_last_election(peer_id) {
                hashes[round].value()
            } else {
                log_or_panic!("{:?} missing round hash.", self.our_pub_id());
                return Err(Error::Logic);
            };

        // Get the gradient of leadership.
        let mut peer_id_hashes = self.peer_list.peer_id_hashes().clone();
        peer_id_hashes.sort_by(|lhs, rhs| round_hash.xor_cmp(&lhs.0, &rhs.0));

        // Try to get the "most-leader"'s aux value.
        let creator = &peer_id_hashes[0].1;
        if let Some(creator_event_index) = event.last_ancestors().get(creator) {
            if let Some(aux_value) = self.aux_value(creator, *creator_event_index, peer_id, round) {
                return Ok(Some(aux_value));
            }
        }

        // If we've already waited long enough, get the aux value of the highest ranking leader.
        if self.stop_waiting(round, event) {
            for (_, creator) in &peer_id_hashes[1..] {
                if let Some(creator_event_index) = event.last_ancestors().get(creator) {
                    if let Some(aux_value) =
                        self.aux_value(creator, *creator_event_index, peer_id, round)
                    {
                        return Ok(Some(aux_value));
                    }
                }
            }
        }

        Ok(None)
    }

    // Returns the aux value for the given peer, created by `creator`, at the given round and at
    // the genuine flip step.
    fn aux_value(
        &self,
        creator: &S::PublicId,
        creator_event_index: u64,
        peer_id: &S::PublicId,
        round: usize,
    ) -> Option<bool> {
        self.meta_votes_since_round_and_step(
            creator,
            creator_event_index,
            peer_id,
            round,
            &Step::GenuineFlip,
        ).first()
        .and_then(|meta_vote| meta_vote.aux_value)
    }

    // Skips back through events created by the peer until passed `responsiveness_threshold`
    // response events and sees if the peer had its `aux_value` set at this round.  If so, returns
    // `true`.
    fn stop_waiting(&self, round: usize, event: &Event<T, S::PublicId>) -> bool {
        let mut event_hash = Some(event.hash());
        let mut response_count = 0;
        let responsiveness_threshold = self.responsiveness_threshold();

        loop {
            if let Some(event) = event_hash.and_then(|hash| self.get_known_event(hash).ok()) {
                if event.is_response() {
                    response_count += 1;
                    if response_count == responsiveness_threshold {
                        break;
                    }
                }
                event_hash = event.self_parent();
            } else {
                return false;
            }
        }
        let hash = match event_hash {
            Some(hash) => hash,
            None => {
                log_or_panic!("{:?} event_hash was None.", self.our_pub_id());
                return false;
            }
        };
        self.meta_votes_map
            .get_mvs_from_last_election(&hash)
            .and_then(|meta_votes| meta_votes.get(event.creator()))
            .map_or(false, |event_votes| {
                event_votes
                    .iter()
                    .any(|meta_vote| meta_vote.round == round && meta_vote.aux_value.is_some())
            })
    }

    // Returns the meta votes for the given peer, created by `creator`, since the given round and
    // step.
    // Starts iterating down the creator's events starting from `creator_event_index`.
    fn meta_votes_since_round_and_step(
        &self,
        creator: &S::PublicId,
        creator_event_index: u64,
        peer_id: &S::PublicId,
        round: usize,
        step: &Step,
    ) -> Vec<MetaVote> {
        if let Some(event_hash) = self.peer_list.event_by_index(creator, creator_event_index) {
            if let Some(latest_votes) = self
                .meta_votes_map
                .get_mvs_from_last_election(event_hash)
                .and_then(|meta_votes| meta_votes.get(peer_id))
                .map(|meta_votes| {
                    meta_votes
                        .iter()
                        .filter(|meta_vote| {
                            meta_vote.round > round
                                || meta_vote.round == round && meta_vote.step >= *step
                        }).cloned()
                        .collect()
                }) {
                latest_votes
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    }

    // Returns the set of meta votes held by all peers other than the creator of `event` which are
    // votes by `peer_id`.
    fn collect_other_meta_votes(
        &self,
        peer_id: &S::PublicId,
        event: &Event<T, S::PublicId>,
    ) -> Vec<Vec<MetaVote>> {
        let mut other_votes = vec![];
        for creator in self
            .peer_list
            .voter_ids()
            .filter(|id| *id != event.creator())
        {
            if let Some(meta_votes) =
                event
                    .last_ancestors()
                    .get(creator)
                    .map(|creator_event_index| {
                        self.meta_votes_since_round_and_step(
                            creator,
                            *creator_event_index,
                            &peer_id,
                            0,
                            &Step::ForcedTrue,
                        )
                    }) {
                other_votes.push(meta_votes)
            }
        }
        other_votes
    }

    fn next_stable_block(&mut self, event_hash: &Hash) -> Option<Block<T, S::PublicId>> {
        self.meta_votes_map
            .get_mvs_from_last_election(event_hash)
            .and_then(|last_meta_votes| {
                let decided_meta_votes = last_meta_votes.iter().filter_map(|(id, event_votes)| {
                    let vote = event_votes.last();
                    vote.and_then(|v| {
                        if v.decision.is_some() {
                            Some((id, v))
                        } else {
                            None
                        }
                    })
                });
                if decided_meta_votes.clone().count() < self.peer_list.voters().count() {
                    None
                } else {
                    let payloads = decided_meta_votes
                        .filter_map(|(id, vote)| {
                            if vote.decision == Some(true) {
                                self.interesting_events
                                    .get(&id)
                                    .and_then(|hashes| hashes.front())
                                    .and_then(|hash| self.get_known_event(&hash).ok())
                                    .and_then(|oldest_event| {
                                        oldest_event.interesting_content.first()
                                    }).cloned()
                            } else {
                                None
                            }
                        }).collect::<Vec<_>>();

                    let copied_payloads = payloads.clone();
                    copied_payloads
                        .iter()
                        .max_by(|lhs_payload, rhs_payload| {
                            let lhs_count = payloads
                                .iter()
                                .filter(|payload_carried| lhs_payload == payload_carried)
                                .count();
                            let rhs_count = payloads
                                .iter()
                                .filter(|payload_carried| rhs_payload == payload_carried)
                                .count();
                            lhs_count.cmp(&rhs_count)
                        }).cloned()
                        .and_then(|winning_payload| {
                            let votes = self
                                .events
                                .iter()
                                .filter_map(|(_hash, event)| {
                                    event.vote().and_then(|vote| {
                                        if *vote.payload() == winning_payload {
                                            Some((event.creator().clone(), vote.clone()))
                                        } else {
                                            None
                                        }
                                    })
                                }).collect();
                            Block::new(winning_payload.clone(), &votes).ok()
                        })
                }
            })
    }

    fn clear_consensus_data(&mut self) {
        // Clear all leftover data from previous consensus
        self.interesting_events = BTreeMap::new();

        for event in self.events.values_mut() {
            event.observations = BTreeSet::new();
            event.interesting_content = vec![];
        }
    }

    fn restart_consensus(&mut self) {
        self.meta_votes_map
            .restart_last_election_round_hashes(self.peer_list.all_ids());
        let events_hashes = self.events_order.to_vec();
        for event_hash in events_hashes {
            let _ = self.set_interesting_content(&event_hash);
            let _ = self.process_event(&event_hash);
        }
    }

    // Returns the number of peers through which there is a directed path in the gossip graph
    // from event X (descendant) to event Y (ancestor).
    fn n_peers_with_directed_paths(
        &self,
        x: &Event<T, S::PublicId>,
        y: &Event<T, S::PublicId>,
    ) -> usize {
        x.last_ancestors()
            .iter()
            .filter(|(peer_id, &event_index)| {
                self.peer_list
                    .event_by_index(peer_id, event_index)
                    .and_then(|event_hash| self.get_known_event(event_hash).ok())
                    .map_or(false, |last_ancestor_of_x| last_ancestor_of_x.sees(y))
            }).count()
    }

    // Returns whether event X can strongly see the event Y.
    fn strongly_sees(&self, x: &Event<T, S::PublicId>, y: &Event<T, S::PublicId>) -> bool {
        self.peer_list
            .is_super_majority(self.n_peers_with_directed_paths(x, y))
    }

    // Constructs a sync event to prove receipt of a `Request` or `Response` (depending on the value
    // of `is_request`) from `src`, then add it to our graph.
    fn create_sync_event(&mut self, src: &S::PublicId, is_request: bool) -> Result<(), Error> {
        let self_parent = *self
            .peer_list
            .last_event_hash(self.our_pub_id())
            .ok_or_else(|| {
                log_or_panic!("{:?} missing our own last event hash.", self.our_pub_id());
                Error::Logic
            })?;
        let other_parent = *self.peer_list.last_event_hash(src).ok_or_else(|| {
            log_or_panic!("{:?} missing {:?} last event hash.", self.our_pub_id(), src);
            Error::Logic
        })?;
        let sync_event = if is_request {
            Event::new_from_request(self_parent, other_parent, &self.events, &self.peer_list)
        } else {
            Event::new_from_response(self_parent, other_parent, &self.events, &self.peer_list)
        };
        self.add_event(sync_event)
    }

    // Returns an iterator over `self.events` which will yield all the events we think `peer_id`
    // doesn't yet know about.  We should already have checked that we know `peer_id` and that we
    // have recorded at least one event from this peer before calling this function.
    fn events_to_gossip_to_peer(
        &self,
        peer_id: &S::PublicId,
    ) -> Result<impl Iterator<Item = &Event<T, S::PublicId>>, Error> {
        let peer_last_event = if let Some(event_hash) = self.peer_list.last_event_hash(peer_id) {
            self.get_known_event(event_hash)?
        } else {
            log_or_panic!("{:?} doesn't have peer {:?}", self.our_pub_id(), peer_id);
            return Err(Error::Logic);
        };
        let mut last_ancestors_hashes = peer_last_event
            .last_ancestors()
            .iter()
            .filter_map(|(id, &index)| self.peer_list.event_by_index(id, index))
            .collect::<BTreeSet<_>>();
        // As `peer_id` isn't guaranteed to have `last_ancestor_hash` for all peers (which will
        // happen during the early stage when a node has not heard from all others), this may cause
        // the early events in `self.events_order` to be skipped mistakenly. To avoid this, if there
        // are any peers for which `peer_id` doesn't have a `last_ancestors` entry, add those peers'
        // oldest events we know about to the list of hashes.
        for (id, peer) in self.peer_list.iter() {
            if !peer_last_event.last_ancestors().contains_key(id) {
                if let Some(hash) = peer.events.get(&0) {
                    let _ = last_ancestors_hashes.insert(hash);
                }
            }
        }
        Ok(self
            .events_order
            .iter()
            .skip_while(move |hash| !last_ancestors_hashes.contains(hash))
            .filter_map(move |hash| self.get_known_event(hash).ok())
            .filter(move |event| {
                // We only need to include events newer than those indicated by
                // `peer_last_event.last_ancestors()`
                peer_last_event
                    .last_ancestors()
                    .get(event.creator())
                    .map(|&last_ancestor_index| event.index() > last_ancestor_index)
                    .unwrap_or(true)
            }))
    }

    // Get the responsiveness threshold based on the current number of peers.
    fn responsiveness_threshold(&self) -> usize {
        (self.peer_list.voters().count() as f64).log2().ceil() as usize
    }

    fn handle_malice(&mut self, event_hash: &Hash) -> Result<(), Error> {
        let accusations: Vec<_> = {
            let event = self.get_known_event(event_hash)?;
            self.detect_malice(event)
                .into_iter()
                .map(|malice| (event.creator().clone(), malice))
                .collect()
        };

        for (offender, malice) in accusations {
            trace!(
                "{:?} detected malice {:?} by {:?}",
                self.our_pub_id(),
                malice,
                offender
            );

            self.vote_for(Observation::Accusation { offender, malice })?;
        }

        Ok(())
    }

    fn detect_malice(&self, event: &Event<T, S::PublicId>) -> Vec<Malice> {
        let mut malices = Vec::new();

        if self.detect_unexpected_genesis(event) {
            malices.push(Malice::UnexpectedGenesis(*event.hash()));
        }

        // TODO: detect other forms of malice here

        malices
    }

    // Detect whether the event carries unexpected `Observation::Genesis`.
    fn detect_unexpected_genesis(&self, event: &Event<T, S::PublicId>) -> bool {
        let payload = if let Some(payload) = event.vote().map(|v| v.payload()) {
            payload
        } else {
            return false;
        };

        let genesis_group = if let Observation::Genesis(ref group) = *payload {
            group
        } else {
            return false;
        };

        // - the creator is not member of the genesis group, or
        // - the self-parent of the event is not initial event
        !genesis_group.contains(event.creator()) || self
            .self_parent(event)
            .map_or(true, |self_parent| !self_parent.is_initial())
    }
}

impl<T: NetworkEvent, S: SecretId> Drop for Parsec<T, S> {
    fn drop(&mut self) {
        if ::std::thread::panicking() {
            dump_graph::to_file(
                self.our_pub_id(),
                &self.events,
                &self.meta_votes_map.last_meta_votes(),
                &self.peer_list,
            );
        }
    }
}

#[cfg(test)]
impl Parsec<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(parsed_contents: ParsedContents) -> Self {
        let mut parsec = Parsec::empty(parsed_contents.our_id, is_supermajority);

        for hash in &parsed_contents.events_order.clone() {
            let event = unwrap!(parsed_contents.events.get(hash));
            if !event.interesting_content.is_empty() {
                let _ = parsec
                    .interesting_events
                    .entry(event.creator().clone())
                    .and_modify(|hashes| {
                        hashes.push_back(*event.hash());
                    }).or_insert_with(|| iter::once(*event.hash()).collect());
            }
        }

        parsec.events = parsed_contents.events;
        parsec.events_order = parsed_contents.events_order;
        parsec.meta_votes_map = MetaVotesMap::new_from_parsed(parsed_contents.meta_votes);
        parsec.peer_list = parsed_contents.peer_list;
        parsec
    }
}

#[cfg(test)]
mod functional_tests {
    use super::*;
    use dev_utils::parse_test_dot_file;
    use meta_vote::MetaVotes;
    use mock::{self, Transaction};
    use peer_list::PeerState;
    use std::collections::BTreeMap;

    #[derive(Debug, PartialEq, Eq)]
    pub struct Snapshot {
        peer_list: BTreeMap<PeerId, (PeerState, BTreeMap<u64, Hash>)>,
        events: BTreeSet<Hash>,
        events_order: Vec<Hash>,
        consensused_blocks: VecDeque<Block<Transaction, PeerId>>,
        meta_votes: MetaVotes<PeerId>,
    }

    impl Snapshot {
        fn new(parsec: &Parsec<Transaction, PeerId>) -> Self {
            let peer_list = parsec
                .peer_list
                .iter()
                .map(|(peer_id, peer)| (peer_id.clone(), (peer.state, peer.events.clone())))
                .collect();
            let events = parsec.events.keys().cloned().collect();

            Snapshot {
                peer_list,
                events,
                events_order: parsec.events_order.clone(),
                consensused_blocks: parsec.consensused_blocks.clone(),
                meta_votes: parsec.meta_votes_map.last_meta_votes().clone(),
            }
        }
    }

    macro_rules! assert_err {
        ($expected_error:pat, $result:expr) => {
            match $result {
                Err($expected_error) => (),
                unexpected => panic!(
                    "Expected {}, but got {:?}",
                    stringify!($expected_error),
                    unexpected
                ),
            }
        };
    }

    #[test]
    fn from_existing() {
        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let peers = peers.into_iter().collect();

        let parsec = Parsec::<Transaction, _>::from_existing(
            our_id.clone(),
            &peers,
            &peers,
            is_supermajority,
        );

        // Existing section + us
        assert_eq!(parsec.peer_list.all_ids().count(), peers.len() + 1);

        // Only the initial event should be in the gossip graph.
        assert_eq!(parsec.events.len(), 1);
        let event = unwrap!(parsec.events.values().next());
        assert_eq!(*event.creator(), our_id);
        assert!(event.is_initial());
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Genesis group can't be empty")]
    fn from_existing_requires_non_empty_genesis_group() {
        use mock;

        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let peers = peers.into_iter().collect();

        let _ = Parsec::<Transaction, _>::from_existing(
            our_id,
            &BTreeSet::new(),
            &peers,
            is_supermajority,
        );
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Genesis group can't already contain us")]
    fn from_existing_requires_that_genesis_group_does_not_contain_us() {
        use mock;

        let peers = mock::create_ids(10);
        let our_id = unwrap!(peers.first()).clone();
        let genesis_group = peers.iter().cloned().collect();
        let section = peers.into_iter().skip(1).collect();

        let _ = Parsec::<Transaction, _>::from_existing(
            our_id,
            &genesis_group,
            &section,
            is_supermajority,
        );
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Section can't be empty")]
    fn from_existing_requires_non_empty_section() {
        use mock;

        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let genesis_group = peers.into_iter().collect();

        let _ = Parsec::<Transaction, _>::from_existing(
            our_id,
            &genesis_group,
            &BTreeSet::new(),
            is_supermajority,
        );
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Section can't already contain us")]
    fn from_existing_requires_that_section_does_not_contain_us() {
        use mock;

        let peers = mock::create_ids(10);
        let our_id = unwrap!(peers.first()).clone();
        let genesis_group = peers.iter().skip(1).cloned().collect();
        let section = peers.into_iter().collect();

        let _ = Parsec::<Transaction, _>::from_existing(
            our_id,
            &genesis_group,
            &section,
            is_supermajority,
        );
    }

    #[test]
    fn from_genesis() {
        let peers = mock::create_ids(10);
        let our_id = unwrap!(peers.first()).clone();
        let peers = peers.into_iter().collect();

        let parsec =
            Parsec::<Transaction, _>::from_genesis(our_id.clone(), &peers, is_supermajority);
        // the peer_list should contain the entire genesis group
        assert_eq!(parsec.peer_list.all_ids().count(), peers.len());
        // initial event + genesis_observation
        assert_eq!(parsec.events.len(), 2);
        let initial_hash = parsec.events_order[0];
        let initial_event = unwrap!(parsec.events.get(&initial_hash));
        assert_eq!(*initial_event.creator(), our_id);
        assert!(initial_event.is_initial());
        let genesis_observation_hash = parsec.events_order[1];
        let genesis_observation = unwrap!(parsec.events.get(&genesis_observation_hash));
        assert_eq!(*genesis_observation.creator(), our_id);
        match &genesis_observation.vote() {
            Some(vote) => {
                assert_eq!(*vote.payload(), Observation::Genesis(peers));
            }
            None => panic!("Expected observation, but event carried no vote"),
        }
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Genesis group must contain us")]
    fn from_genesis_requires_the_genesis_group_contains_us() {
        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let peers = peers.into_iter().collect();

        let _ = Parsec::<Transaction, _>::from_genesis(our_id.clone(), &peers, is_supermajority);
    }

    #[test]
    fn from_parsed_contents() {
        let input_file = "0.dot";
        let parsed_contents = parse_test_dot_file(input_file);
        let parsed_contents_comparison = parse_test_dot_file(input_file);
        let parsec = Parsec::from_parsed_contents(parsed_contents);
        assert_eq!(parsed_contents_comparison.events, parsec.events);
        assert_eq!(parsed_contents_comparison.events_order, parsec.events_order);
        assert_eq!(
            &parsed_contents_comparison.meta_votes,
            parsec.meta_votes_map.last_meta_votes()
        );

        let parsed_contents_other = parse_test_dot_file("1.dot");
        assert_ne!(parsed_contents_other.events, parsec.events);
        assert_ne!(parsed_contents_other.events_order, parsec.events_order);
        assert_ne!(
            &parsed_contents_other.meta_votes,
            parsec.meta_votes_map.last_meta_votes()
        );
    }

    #[test]
    fn add_peer() {
        let mut parsed_contents = parse_test_dot_file("add_fred.dot");
        // Split out the events Eric would send to Alice.  These are the last seven events listed in
        // `parsed_contents.events_order`, i.e. B_14, C_14, D_14, D_15, B_15, C_15, E_14, and E_15.
        let mut final_events: Vec<_> = (0..8)
            .map(|_| unwrap!(parsed_contents.remove_latest_event()))
            .collect();
        final_events.reverse();

        let e_15 = unwrap!(final_events.pop());
        let e_14 = unwrap!(final_events.pop());

        // The final decision to add Fred is reached in C_15.
        let c_15 = unwrap!(final_events.pop());

        let mut alice = Parsec::from_parsed_contents(parsed_contents);
        let genesis_group = alice.peer_list.all_ids().into_iter().cloned().collect();
        let fred_id = PeerId::new("Fred");
        assert!(!alice.peer_list.all_ids().any(|peer_id| *peer_id == fred_id));

        let alice_snapshot = Snapshot::new(&alice);

        // Try calling `create_gossip()` for a peer which doesn't exist yet.
        assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&fred_id)));
        assert_eq!(alice_snapshot, Snapshot::new(&alice));

        // Keep a copy of a request which will be used later in the test.  This request will not
        // include enough events to allow a joining peer to see "Fred" as a valid member.
        let deficient_message = unwrap!(alice.create_gossip(None));

        // Add events now as though Alice had received the request from Eric.  This should result in
        // Alice adding Fred.
        for event in final_events {
            unwrap!(alice.add_event(event));
            assert!(!alice.peer_list.all_ids().any(|peer_id| *peer_id == fred_id));
        }

        // NOTE: currently the consensus is reached at c_15, but when we implement
        //       peer membership, it won't be reached until the "Eric" sync event.
        unwrap!(alice.add_event(c_15));
        unwrap!(alice.add_event(e_14));
        unwrap!(alice.add_event(e_15));
        unwrap!(alice.create_sync_event(&PeerId::new("Eric"), true));
        assert!(alice.peer_list.all_ids().any(|peer_id| *peer_id == fred_id));

        // Construct Fred's Parsec instance.
        let mut fred =
            Parsec::from_existing(fred_id, &genesis_group, &genesis_group, is_supermajority);
        let fred_snapshot = Snapshot::new(&fred);

        // Create a "naughty Carol" instance where the graph only shows four peers existing before
        // adding Fred.
        parsed_contents = parse_test_dot_file("naughty_carol.dot");
        let naughty_carol = Parsec::from_parsed_contents(parsed_contents);
        let alice_id = PeerId::new("Alice");
        let malicious_message = unwrap!(naughty_carol.create_gossip(None));
        // TODO - re-enable once `handle_request` is fixed to match the expected behaviour by
        //        MAID-3066/3067.
        if false {
            assert_err!(
                Error::InvalidInitialRequest,
                fred.handle_request(&alice_id, malicious_message)
            );
        }
        assert_eq!(fred_snapshot, Snapshot::new(&fred));

        // TODO - re-enable once `handle_request` is fixed to match the expected behaviour by
        //        MAID-3066/3067.
        if false {
            // Pass the deficient message gathered earlier which will not be sufficient to allow
            // Fred to see himself getting added to the section.
            assert_err!(
                Error::InvalidInitialRequest,
                fred.handle_request(&alice_id, deficient_message)
            );
        }
        // TODO - depending on the outcome of the discussion on how to handle such an invalid
        //        request, the following check may be invalid.  This would be the case if we decide
        //        to accept the events, expecting a good peer will soon augment our knowledge up to
        //        at least the point where we see ourself being added.
        assert_eq!(fred_snapshot, Snapshot::new(&fred));

        // Now pass a valid initial request from Alice to Fred.  The generated response should only
        // contain Fred's initial event, and the one recording receipt of Alice's request.
        let message = unwrap!(alice.create_gossip(None));
        let response = unwrap!(fred.handle_request(&alice_id, message));
        assert_eq!(response.packed_events.len(), 2);
    }

    #[test]
    fn remove_peer() {
        let mut parsed_contents = parse_test_dot_file("remove_eric.dot");
        // The final decision to remove Eric is reached in the last event of Alice.
        let a_last_hash = unwrap!(parsed_contents.events_order.pop());
        let a_last = unwrap!(parsed_contents.events.remove(&a_last_hash));

        let mut alice = Parsec::from_parsed_contents(parsed_contents);
        let eric_id = PeerId::new("Eric");

        assert!(alice.peer_list.all_ids().any(|peer_id| *peer_id == eric_id));
        assert_ne!(alice.peer_list.peer_state(&eric_id), PeerState::inactive());

        // Add event now which shall result in Alice removing Eric.
        unwrap!(alice.add_event(a_last));
        assert_eq!(alice.peer_list.peer_state(&eric_id), PeerState::inactive());

        // Try calling `create_gossip()` for Eric shall result in error.
        assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&eric_id)));

        // Construct Eric's parsec instance.
        let mut section: BTreeSet<_> = alice.peer_list.all_ids().cloned().collect();
        let _ = section.remove(&eric_id);
        let mut eric = Parsec::<Transaction, _>::from_existing(
            eric_id.clone(),
            &section,
            &section,
            is_supermajority,
        );

        // Peer state is (VOTE | SEND) when created from existing. Need to call
        // 'add_peer' to update the state to (VOTE | SEND | RECV).
        for peer_id in section {
            eric.peer_list.add_peer(peer_id, PeerState::RECV);
        }

        // Eric can no longer gossip to anyone.
        assert_err!(
            Error::InvalidSelfState { .. },
            eric.create_gossip(Some(&PeerId::new("Alice")))
        );
    }
}
