// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

mod peer;
mod peer_index;
mod peer_state;

pub use self::peer_state::PeerState;
#[cfg(all(test, feature = "mock"))]
pub(crate) use self::snapshot::PeerListSnapshot;
pub(crate) use self::{
    peer::Peer,
    peer_index::{PeerIndex, PeerIndexMap, PeerIndexSet},
};

#[cfg(all(test, feature = "mock"))]
use crate::gossip::Graph;
#[cfg(any(test, feature = "testing"))]
use crate::mock::PeerId;
use crate::{
    error::Error,
    gossip::{EventIndex, IndexedEventRef},
    id::SecretId,
};
use std::{
    collections::btree_map::{BTreeMap, Entry},
    fmt::{self, Debug, Formatter},
    iter,
};

pub(crate) struct PeerList<S: SecretId> {
    our_id: S,
    our_peer: Peer<S::PublicId>,
    peers: Vec<Peer<S::PublicId>>,
    indices: BTreeMap<S::PublicId, PeerIndex>,
}

impl<S: SecretId> PeerList<S> {
    pub fn new(our_id: S) -> Self {
        let our_peer = Peer::new(our_id.public_id().clone(), PeerState::inactive());

        PeerList {
            our_id,
            our_peer,
            peers: Vec::new(),
            indices: BTreeMap::new(),
        }
    }

    pub fn our_id(&self) -> &S {
        &self.our_id
    }

    pub fn our_pub_id(&self) -> &S::PublicId {
        &self.our_id.public_id()
    }

    pub fn get_index(&self, peer_id: &S::PublicId) -> Option<PeerIndex> {
        if peer_id == self.our_id.public_id() {
            Some(PeerIndex::OUR)
        } else {
            self.indices.get(peer_id).cloned()
        }
    }

    pub fn contains(&self, peer_id: &S::PublicId) -> bool {
        peer_id == self.our_id.public_id() || self.indices.contains_key(peer_id)
    }

    pub fn get(&self, index: PeerIndex) -> Option<&Peer<S::PublicId>> {
        if index == PeerIndex::OUR {
            Some(&self.our_peer)
        } else {
            self.peers.get(index.0 - 1)
        }
    }

    pub fn get_known(&self, index: PeerIndex) -> Result<&Peer<S::PublicId>, Error> {
        self.get(index).ok_or_else(|| {
            log_or_panic!(
                "{:?} does not have peer with index {:?}",
                self.our_id.public_id(),
                index
            );
            Error::UnknownPeer
        })
    }

    fn get_known_mut(&mut self, index: PeerIndex) -> Option<&mut Peer<S::PublicId>> {
        if index == PeerIndex::OUR {
            Some(&mut self.our_peer)
        } else if let Some(peer) = self.peers.get_mut(index.0 - 1) {
            Some(peer)
        } else {
            log_or_panic!(
                "{:?} does not have peer with index {:?}",
                self.our_id.public_id(),
                index
            );
            None
        }
    }

    /// Returns an iterator of peers.
    pub fn iter(&self) -> impl Iterator<Item = (PeerIndex, &Peer<S::PublicId>)> {
        iter::once((PeerIndex::OUR, &self.our_peer)).chain(
            self.peers
                .iter()
                .enumerate()
                .map(|(index, peer)| (PeerIndex(index + 1), peer)),
        )
    }

    /// Returns an iterator of peers that can vote.
    pub fn voters(&self) -> impl Iterator<Item = (PeerIndex, &Peer<S::PublicId>)> {
        self.iter().filter(|(_, peer)| peer.state().can_vote())
    }

    /// Returns an iterator of peers that we can send gossip to.
    pub fn gossip_recipients<'a>(
        &'a self,
    ) -> impl Iterator<Item = (PeerIndex, &Peer<S::PublicId>)> + 'a {
        let iter = if self.our_peer.state().can_send() {
            let iter = self
                .iter()
                .skip(1)
                .filter(|(_, peer)| peer.state().can_dkg() && peer.state().can_recv());
            Some(iter)
        } else {
            None
        };

        iter.into_iter().flat_map(|iter| iter)
    }

    /// Return public ids of all peers.
    #[cfg(all(test, any(feature = "testing", feature = "mock")))]
    pub fn all_ids(&self) -> impl Iterator<Item = (PeerIndex, &S::PublicId)> {
        self.iter().map(|(index, peer)| (index, peer.id()))
    }

    pub fn peer_state(&self, index: PeerIndex) -> PeerState {
        self.get(index)
            .map(Peer::state)
            .unwrap_or_else(PeerState::inactive)
    }

    pub fn our_state(&self) -> PeerState {
        self.our_peer.state()
    }

    /// Adds a peer in the given state into the map.
    pub fn add_peer(&mut self, peer_id: S::PublicId, state: PeerState) -> PeerIndex {
        if peer_id == *self.our_id.public_id() {
            log_or_panic!(
                "{:?} already has self in the peer list",
                self.our_id.public_id(),
            );

            return PeerIndex::OUR;
        }

        match self.indices.entry(peer_id) {
            Entry::Occupied(entry) => {
                log_or_panic!(
                    "{:?} already has {:?} in the peer list",
                    self.our_id.public_id(),
                    entry.key()
                );
                *entry.get()
            }
            Entry::Vacant(entry) => {
                let index = PeerIndex(self.peers.len() + 1);
                let peer = Peer::new(entry.key().clone(), state);

                self.peers.push(peer);
                let _ = entry.insert(index);

                index
            }
        }
    }

    /// Remove peer at `peer_index` after reaching consensus on the removal at the event
    /// at `deciding_event_index`.
    pub fn remove_peer(&mut self, peer_index: PeerIndex, deciding_event_index: EventIndex) {
        if let Some(peer) = self.get_known_mut(peer_index) {
            peer.set_removed(deciding_event_index)
        }
    }

    pub fn change_peer_state(&mut self, index: PeerIndex, state: PeerState) {
        if let Some(peer) = self.get_known_mut(index) {
            peer.change_state(state);
        }
    }

    /// Returns the index of the last event created by this peer. Returns `None` if cannot find.
    pub fn last_event(&self, peer_index: PeerIndex) -> Option<EventIndex> {
        self.get(peer_index)
            .and_then(|peer| peer.events().rev().next())
    }

    /// Returns the indices of the events at the given index-by-creator.
    pub fn events_by_index<'a>(
        &'a self,
        peer_index: PeerIndex,
        index_by_creator: usize,
    ) -> impl Iterator<Item = EventIndex> + 'a {
        self.get(peer_index)
            .into_iter()
            .flat_map(move |peer| peer.events_by_index(index_by_creator))
    }

    /// Record that the given peer gossiped to us the given event.
    pub fn record_gossiped_event_by(&mut self, index: PeerIndex, event_index: EventIndex) {
        if let Some(peer) = self.get_known_mut(index) {
            if peer
                .last_gossiped_event
                .map(|current| current < event_index)
                .unwrap_or(true)
            {
                peer.last_gossiped_event = Some(event_index)
            }
        }
    }

    #[cfg(feature = "malice-detection")]
    pub fn accomplice_event_checkpoint_by(&self, peer_index: PeerIndex) -> Option<EventIndex> {
        self.get(peer_index)
            .and_then(|peer| peer.accomplice_event_checkpoint)
    }

    #[cfg(feature = "malice-detection")]
    pub fn update_accomplice_event_checkpoint_by(
        &mut self,
        peer_index: PeerIndex,
        event_index: EventIndex,
    ) {
        if let Some(peer) = self.get_known_mut(peer_index) {
            if peer
                .accomplice_event_checkpoint
                .map(|current| current.topological_index() < event_index.topological_index())
                .unwrap_or(true)
            {
                peer.accomplice_event_checkpoint = Some(event_index)
            }
        }
    }

    /// Adds event created by the peer.
    pub fn add_event(&mut self, event: IndexedEventRef<S::PublicId>) {
        if let Some(peer) = self.get_known_mut(event.creator()) {
            peer.add_event(event.index_by_creator(), event.event_index())
        }
    }

    /// Removes last event from its creator.
    #[cfg(all(test, feature = "mock"))]
    pub fn remove_last_event(&mut self, creator: PeerIndex) -> Option<EventIndex> {
        if let Some(peer) = self.get_known_mut(creator) {
            peer.remove_last_event()
        } else {
            None
        }
    }

    /// Indices of events of the given creator, in insertion order.
    pub fn peer_events<'a>(
        &'a self,
        peer_index: PeerIndex,
    ) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.get(peer_index).into_iter().flat_map(Peer::events)
    }

    /// Indices of our events in insertion order.
    pub fn our_events<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.peer_events(PeerIndex::OUR)
    }
}

impl<S: SecretId> Debug for PeerList<S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(
            formatter,
            "PeerList{{ our_id: {:?}",
            self.our_id.public_id()
        )?;
        for peer in iter::once(&self.our_peer).chain(&self.peers) {
            writeln!(formatter, "    {:?},", peer)?;
        }
        write!(formatter, "}}")
    }
}

#[cfg(any(test, feature = "testing"))]
impl PeerList<PeerId> {
    // Creates a PeerList using the input parameters directly.
    pub(super) fn build_from_dot_input(
        our_id: PeerId,
        mut peer_data: BTreeMap<PeerId, PeerState>,
    ) -> Self {
        let our_state = unwrap!(peer_data.remove(&our_id));
        let our_peer = Peer::new(our_id.public_id().clone(), our_state);

        let mut peers = Vec::new();

        for (id, state) in peer_data {
            peers.push(Peer::new(id, state));
        }

        let indices: BTreeMap<_, _> = peers
            .iter()
            .enumerate()
            .map(|(index, peer)| (peer.id().clone(), PeerIndex(index + 1)))
            .collect();

        PeerList {
            our_id,
            our_peer,
            peers,
            indices,
        }
    }
}

/// Type of change to the peer list
#[derive(Clone, Copy)]
pub(crate) enum PeerListChange {
    Add(PeerIndex),
    Remove(PeerIndex),
}

#[cfg(test)]
pub(crate) mod snapshot {
    use super::*;
    use crate::{gossip::EventHash, id::PublicId};
    use std::collections::BTreeSet;

    #[derive(Eq, PartialEq, Debug)]
    pub(crate) struct PeerListSnapshot<P: PublicId>(
        BTreeMap<P, (PeerState, BTreeSet<(usize, EventHash)>)>,
    );

    #[cfg(feature = "mock")]
    impl<P: PublicId> PeerListSnapshot<P> {
        pub fn new<S: SecretId<PublicId = P>>(peer_list: &PeerList<S>, graph: &Graph<P>) -> Self {
            PeerListSnapshot(
                peer_list
                    .iter()
                    .map(|(_, peer)| {
                        let events = peer
                            .indexed_events()
                            .filter_map(|(index_by_creator, event_index)| {
                                graph
                                    .get(event_index)
                                    .map(|event| (index_by_creator, *event.hash()))
                            })
                            .collect();

                        (peer.id().clone(), (peer.state(), events))
                    })
                    .collect(),
            )
        }
    }
}
