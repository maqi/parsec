// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use error::Error;
use gossip::cause::Cause;
use gossip::content::Content;
use gossip::packed_event::PackedEvent;
use hash::Hash;
use id::{PublicId, SecretId};
#[cfg(test)]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use observation::Observation;
use peer_list::PeerList;
use serialise;
use std::cmp;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Formatter};
#[cfg(feature = "dump-graphs")]
use std::io::{self, Write};
use vote::Vote;

#[derive(PartialEq)]
pub(crate) struct Event<T: NetworkEvent, P: PublicId> {
    content: Content<T, P>,
    // Creator's signature of `content`.
    signature: P::Signature,
    hash: Hash,
    // Sequential index of this event: this event is the `index`-th one made by its creator.
    index: u64,
    // Index of each peer's latest event that is an ancestor of this event.
    last_ancestors: BTreeMap<P, u64>,
    // Payloads of all the votes deemed interesting by this event
    pub interesting_content: BTreeSet<Observation<T, P>>,
    // The set of peers for which this event can strongly-see an event by that peer which carries a
    // valid block.  If there are a supermajority of peers here, this event is an "observer".
    pub observations: BTreeSet<P>,
}

impl<T: NetworkEvent, P: PublicId> Event<T, P> {
    // Creates a new event as the result of receiving a gossip request message.
    pub fn new_from_request<S: SecretId<PublicId = P>>(
        self_parent: Hash,
        other_parent: Hash,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Self {
        Self::new(
            Cause::Request {
                self_parent,
                other_parent,
            },
            events,
            peer_list,
        )
    }

    // Creates a new event as the result of receiving a gossip response message.
    pub fn new_from_response<S: SecretId<PublicId = P>>(
        self_parent: Hash,
        other_parent: Hash,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Self {
        Self::new(
            Cause::Response {
                self_parent,
                other_parent,
            },
            events,
            peer_list,
        )
    }

    // Creates a new event as the result of observing a network event.
    pub fn new_from_observation<S: SecretId<PublicId = P>>(
        self_parent: Hash,
        observation: Observation<T, P>,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Self {
        let vote = Vote::new(peer_list.our_id(), observation);
        Self::new(Cause::Observation { self_parent, vote }, events, peer_list)
    }

    // Creates an initial event.  This is the first event by its creator in the graph.
    pub fn new_initial<S: SecretId<PublicId = P>>(peer_list: &PeerList<S>) -> Self {
        Self::new(Cause::Initial, &BTreeMap::new(), peer_list)
    }

    // Creates an event from a `PackedEvent`.
    //
    // Returns:
    //   * `Ok(None)` if the event already exists
    //   * `Err(Error::SignatureFailure)` if signature validation fails
    //   * `Err(Error::UnknownParent)` if the event indicates it should have an ancestor, but the
    //     ancestor isn't in `events`.
    pub(crate) fn unpack<S: SecretId<PublicId = P>>(
        packed_event: PackedEvent<T, P>,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Result<Option<Self>, Error> {
        let serialised_content = serialise(&packed_event.content);
        let hash = if packed_event
            .content
            .creator
            .verify_signature(&packed_event.signature, &serialised_content)
        {
            Hash::from(serialised_content.as_slice())
        } else {
            return Err(Error::SignatureFailure);
        };
        if events.contains_key(&hash) {
            return Ok(None);
        }

        let (index, last_ancestors) =
            Self::index_and_last_ancestors(&packed_event.content, events, peer_list)?;

        // `interesting_content` and `observations` still need to be set correctly by the caller.
        Ok(Some(Self {
            content: packed_event.content,
            signature: packed_event.signature,
            hash,
            index,
            last_ancestors,
            interesting_content: BTreeSet::default(),
            observations: BTreeSet::default(),
        }))
    }

    // Creates a `PackedEvent` from this `Event`.
    pub(super) fn pack(&self) -> PackedEvent<T, P> {
        PackedEvent {
            content: self.content.clone(),
            signature: self.signature.clone(),
        }
    }

    // Returns whether this event can see `other`, i.e. whether there's a directed path from `other`
    // to `self` in the graph.
    pub fn sees(&self, other: &Event<T, P>) -> bool {
        self.last_ancestors
            .get(other.creator())
            .map_or(false, |last_index| *last_index >= other.index())
    }

    /// Returns `Some(vote)` if the event is for a vote of network event, otherwise returns `None`.
    pub fn vote(&self) -> Option<&Vote<T, P>> {
        if let Cause::Observation { ref vote, .. } = self.content.cause {
            Some(vote)
        } else {
            None
        }
    }

    pub fn creator(&self) -> &P {
        &self.content.creator
    }

    pub fn self_parent(&self) -> Option<&Hash> {
        self.content.self_parent()
    }

    #[cfg(any(test, feature = "dump-graphs"))]
    pub fn other_parent(&self) -> Option<&Hash> {
        self.content.other_parent()
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn last_ancestors(&self) -> &BTreeMap<P, u64> {
        &self.last_ancestors
    }

    pub fn is_response(&self) -> bool {
        if let Cause::Response { .. } = self.content.cause {
            true
        } else {
            false
        }
    }

    pub fn is_initial(&self) -> bool {
        if let Cause::Initial = self.content.cause {
            true
        } else {
            false
        }
    }

    fn new<S: SecretId<PublicId = P>>(
        cause: Cause<T, P>,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Self {
        let content = Content {
            creator: peer_list.our_id().public_id().clone(),
            cause,
        };
        let serialised_content = serialise(&content);

        let (index, last_ancestors) = if let Ok((index, last_ancestors)) =
            Self::index_and_last_ancestors(&content, events, peer_list)
        {
            (index, last_ancestors)
        } else {
            log_or_panic!(
                "{:?} constructed an invalid event.",
                peer_list.our_id().public_id()
            );
            (0, BTreeMap::default())
        };

        // `interesting_content` and `observations` still need to be set correctly by the caller.
        Self {
            content,
            signature: peer_list.our_id().sign_detached(&serialised_content),
            hash: Hash::from(serialised_content.as_slice()),
            index,
            last_ancestors,
            interesting_content: BTreeSet::default(),
            observations: BTreeSet::default(),
        }
    }

    fn index_and_last_ancestors<S: SecretId<PublicId = P>>(
        content: &Content<T, P>,
        events: &BTreeMap<Hash, Event<T, P>>,
        peer_list: &PeerList<S>,
    ) -> Result<(u64, BTreeMap<P, u64>), Error> {
        let self_parent = if let Some(self_parent_hash) = content.self_parent() {
            if let Some(event) = events.get(&self_parent_hash) {
                event
            } else {
                debug!(
                    "{:?} missing self parent for {:?}",
                    peer_list.our_id().public_id(),
                    content
                );
                return Err(Error::UnknownParent);
            }
        } else {
            // This must be an initial event, i.e. having index 0
            let mut last_ancestors = BTreeMap::default();
            let _ = last_ancestors.insert(content.creator.clone(), 0);
            return Ok((0, last_ancestors));
        };

        let index = self_parent.index + 1;
        let mut last_ancestors = self_parent.last_ancestors().clone();

        if let Some(other_parent_hash) = content.other_parent() {
            if let Some(other_parent) = events.get(&other_parent_hash) {
                for (peer_id, _) in peer_list.iter() {
                    if let Some(other_index) = other_parent.last_ancestors().get(peer_id) {
                        let existing_index = last_ancestors
                            .entry(peer_id.clone())
                            .or_insert(*other_index);
                        *existing_index = cmp::max(*existing_index, *other_index);
                    }
                }
            } else {
                debug!(
                    "{:?} missing other parent for {:?}",
                    peer_list.our_id().public_id(),
                    content
                );
                return Err(Error::UnknownParent);
            }
        }
        let _ = last_ancestors.insert(content.creator.clone(), index);
        Ok((index, last_ancestors))
    }

    #[cfg(feature = "dump-graphs")]
    pub fn write_to_dot_format(&self, writer: &mut Write) -> io::Result<()> {
        writeln!(writer, "/// {{ {:?}", self.hash)?;
        writeln!(writer, "/// cause: {}", self.content.cause)?;
        writeln!(
            writer,
            "/// interesting_content: {:?}",
            self.interesting_content
        )?;
        writeln!(writer, "/// last_ancestors: {:?}", self.last_ancestors)?;
        writeln!(writer, "/// }}")
    }
}

impl<T: NetworkEvent, P: PublicId> Debug for Event<T, P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "Event{{ {:?}[{}] {:?}",
            self.content.creator, self.index, self.hash,
        )?;
        write!(
            formatter,
            ", {}",
            match &self.content.cause {
                Cause::Request { .. } => "Request".to_string(),
                Cause::Response { .. } => "Response".to_string(),
                Cause::Observation { vote, .. } => format!("Observation({:?})", vote.payload()),
                Cause::Initial => "Initial".to_string(),
            }
        )?;
        write!(
            formatter,
            ", self_parent: {:?}, other_parent: {:?}",
            self.content.self_parent(),
            self.content.other_parent()
        )?;
        write!(formatter, ", last_ancestors: {:?}", self.last_ancestors)?;
        write!(
            formatter,
            ", interesting_content: {:?}",
            self.interesting_content
        )?;
        write!(formatter, ", observations: {:?}", self.observations)?;
        write!(formatter, " }}")
    }
}

#[cfg(test)]
impl Event<Transaction, PeerId> {
    // Creates a new event using the input parameters directly
    pub(crate) fn new_from_dot_input(
        creator: &PeerId,
        cause: &str,
        self_parent: Option<Hash>,
        other_parent: Option<Hash>,
        index: u64,
        last_ancestors: BTreeMap<PeerId, u64>,
        interesting_content: BTreeSet<Observation<Transaction, PeerId>>,
    ) -> Self {
        let cause = match cause {
            "cause: Initial" => Cause::Initial,
            "cause: Request" => Cause::Request {
                self_parent: unwrap!(self_parent),
                other_parent: unwrap!(other_parent),
            },
            "cause: Response" => Cause::Response {
                self_parent: unwrap!(self_parent),
                other_parent: unwrap!(other_parent),
            },
            _ => {
                let payload =
                    Transaction::new(unwrap!(unwrap!(cause.split('(').nth(2)).split(')').next()));
                Cause::Observation {
                    self_parent: unwrap!(self_parent),
                    vote: Vote::new(creator, Observation::OpaquePayload(payload)),
                }
            }
        };
        let content = Content {
            creator: creator.clone(),
            cause,
        };
        let serialised_content = serialise(&content);

        Self {
            content,
            signature: creator.sign_detached(&serialised_content),
            hash: Hash::from(serialised_content.as_slice()),
            index,
            last_ancestors,
            interesting_content,
            observations: BTreeSet::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use gossip::cause::Cause;
    use gossip::Event;
    use hash::Hash;
    use id::SecretId;
    use mock::{PeerId, Transaction};
    use observation::Observation;
    use peer_list::PeerList;
    use std::collections::BTreeMap;

    struct PeerListAndEvent {
        peer_list: PeerList<PeerId>,
        event: Event<Transaction, PeerId>,
    }

    impl PeerListAndEvent {
        fn new(peer_list: PeerList<PeerId>) -> Self {
            Self {
                event: Event::<Transaction, PeerId>::new_initial(&peer_list),
                peer_list,
            }
        }
    }

    fn create_peer_list(id: &str) -> (PeerId, PeerList<PeerId>) {
        let peer_id = PeerId::new(id);
        let peer_list = PeerList::<PeerId>::new(peer_id.clone());
        (peer_id, peer_list)
    }

    fn create_event_with_single_peer(id: &str) -> PeerListAndEvent {
        let (_, peer_list) = create_peer_list(id);
        PeerListAndEvent::new(peer_list)
    }

    fn insert_into_gossip_graph(
        initial_event: Event<Transaction, PeerId>,
        events: &mut BTreeMap<Hash, Event<Transaction, PeerId>>,
    ) -> Hash {
        let initial_event_hash = *initial_event.hash();
        assert!(events.insert(initial_event_hash, initial_event).is_none());
        initial_event_hash
    }

    fn create_two_events(id0: &str, id1: &str) -> (PeerListAndEvent, PeerListAndEvent) {
        let (peer_id0, mut peer_id0_list) = create_peer_list(id0);
        let (peer_id1, mut peer_id1_list) = create_peer_list(id1);
        peer_id0_list.add_peer(peer_id1);
        peer_id1_list.add_peer(peer_id0);
        (
            PeerListAndEvent::new(peer_id0_list),
            PeerListAndEvent::new(peer_id1_list),
        )
    }

    fn create_gossip_graph_with_two_events(
        alice_initial: Event<Transaction, PeerId>,
        bob_initial: Event<Transaction, PeerId>,
    ) -> (Hash, Hash, BTreeMap<Hash, Event<Transaction, PeerId>>) {
        let mut events = BTreeMap::new();
        let alice_initial_hash = insert_into_gossip_graph(alice_initial, &mut events);
        let bob_initial_hash = insert_into_gossip_graph(bob_initial, &mut events);
        (alice_initial_hash, bob_initial_hash, events)
    }

    #[test]
    fn event_construction_initial() {
        let initial = create_event_with_single_peer("Alice").event;
        assert!(initial.is_initial());
        assert!(!initial.is_response());
        assert!(initial.self_parent().is_none());
        assert!(initial.other_parent().is_none());
        assert_eq!(initial.index, 0);
    }

    #[test]
    fn event_construction_from_observation() {
        let alice = create_event_with_single_peer("Alice");
        let mut events = BTreeMap::new();
        let initial_event_hash = insert_into_gossip_graph(alice.event, &mut events);

        // Our observation
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        let event_from_observation = Event::<Transaction, PeerId>::new_from_observation(
            initial_event_hash,
            net_event.clone(),
            &events,
            &alice.peer_list,
        );

        assert_eq!(
            event_from_observation.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        match &event_from_observation.content.cause {
            Cause::Observation { self_parent, vote } => {
                assert_eq!(self_parent, &initial_event_hash);
                assert_eq!(*vote.payload(), net_event);
            }
            _ => panic!(
                "Expected Observation, got {:?}",
                event_from_observation.content.cause
            ),
        }
        assert_eq!(event_from_observation.index, 1);
        assert!(!event_from_observation.is_initial());
        assert!(!event_from_observation.is_response());
        assert_eq!(
            event_from_observation.self_parent(),
            Some(&initial_event_hash)
        );
        assert!(event_from_observation.other_parent().is_none());
    }

    #[test]
    #[should_panic(expected = "Alice constructed an invalid event")]
    #[cfg(feature = "testing")]
    fn event_construction_from_observation_with_phony_hash() {
        let alice = create_event_with_single_peer("Alice");
        let hash = Hash::from(vec![42].as_slice());
        let events = BTreeMap::new();
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));
        let _ = Event::<Transaction, PeerId>::new_from_observation(
            hash,
            net_event.clone(),
            &events,
            &alice.peer_list,
        );
    }

    #[test]
    fn event_construction_from_request() {
        let (alice, bob) = create_two_events("Alice", "Bob");
        let (alice_initial_hash, bob_initial_hash, events) =
            create_gossip_graph_with_two_events(alice.event, bob.event);

        // Alice receives request from Bob
        let event_from_request = Event::<Transaction, PeerId>::new_from_request(
            alice_initial_hash,
            bob_initial_hash,
            &events,
            &alice.peer_list,
        );

        assert_eq!(
            event_from_request.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        assert_eq!(event_from_request.index, 1);
        assert!(!event_from_request.is_initial());
        assert!(!event_from_request.is_response());
        assert_eq!(event_from_request.self_parent(), Some(&alice_initial_hash));
        assert_eq!(event_from_request.other_parent(), Some(&bob_initial_hash));
    }

    #[test]
    #[should_panic(expected = "Alice constructed an invalid event")]
    #[cfg(feature = "testing")]
    fn event_construction_from_request_without_self_parent_event_in_graph() {
        let (alice, bob) = create_two_events("Alice", "Bob");
        let mut events = BTreeMap::new();
        let alice_initial_hash = *alice.event.hash();
        let bob_initial_hash = insert_into_gossip_graph(bob.event, &mut events);
        let _ = Event::<Transaction, PeerId>::new_from_request(
            alice_initial_hash,
            bob_initial_hash,
            &events,
            &alice.peer_list,
        );
    }

    #[test]
    #[should_panic(expected = "Alice constructed an invalid event")]
    #[cfg(feature = "testing")]
    fn event_construction_from_request_without_other_parent_event_in_graph() {
        let (alice, bob) = create_two_events("Alice", "Bob");
        let mut events = BTreeMap::new();
        let alice_initial_hash = insert_into_gossip_graph(alice.event, &mut events);
        let bob_initial_hash = *bob.event.hash();
        let _ = Event::<Transaction, PeerId>::new_from_request(
            alice_initial_hash,
            bob_initial_hash,
            &events,
            &alice.peer_list,
        );
    }

    #[test]
    fn event_construction_from_response() {
        let (alice, bob) = create_two_events("Alice", "Bob");
        let (alice_initial_hash, bob_initial_hash, events) =
            create_gossip_graph_with_two_events(alice.event, bob.event);

        let event_from_response = Event::<Transaction, PeerId>::new_from_response(
            alice_initial_hash,
            bob_initial_hash,
            &events,
            &alice.peer_list,
        );

        assert_eq!(
            event_from_response.content.creator,
            *alice.peer_list.our_id().public_id()
        );
        assert_eq!(event_from_response.index, 1);
        assert!(!event_from_response.is_initial());
        assert!(event_from_response.is_response());
        assert_eq!(event_from_response.self_parent(), Some(&alice_initial_hash));
        assert_eq!(event_from_response.other_parent(), Some(&bob_initial_hash));
    }

    #[test]
    fn event_construction_unpack() {
        let alice = create_event_with_single_peer("Alice");
        let mut events = BTreeMap::new();
        let initial_event_hash = insert_into_gossip_graph(alice.event, &mut events);

        // Our observation
        let net_event = Observation::OpaquePayload(Transaction::new("event_observed_by_alice"));

        let event_from_observation = Event::<Transaction, PeerId>::new_from_observation(
            initial_event_hash,
            net_event,
            &events,
            &alice.peer_list,
        );

        let packed_event = event_from_observation.pack();
        let unpacked_event = unwrap!(unwrap!(Event::<Transaction, PeerId>::unpack(
            packed_event.clone(),
            &events,
            &alice.peer_list
        )));

        assert_eq!(event_from_observation, unpacked_event);
        assert!(
            events
                .insert(*unpacked_event.hash(), unpacked_event)
                .is_none()
        );
        assert!(
            unwrap!(Event::<Transaction, PeerId>::unpack(
                packed_event,
                &events,
                &alice.peer_list
            )).is_none()
        );
    }
}
