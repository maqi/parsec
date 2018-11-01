// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::PackedEvent;
use hash::Hash;
use id::PublicId;
use network_event::NetworkEvent;
use serialise;
use std::collections::BTreeSet;

/// An enum of the various network events for which a peer can vote.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub enum Observation<T: NetworkEvent, P: PublicId> {
    /// Genesis group
    Genesis(BTreeSet<P>),
    /// Vote to add the indicated peer to the network.
    Add(P),
    /// Vote to remove the indicated peer from the network.
    Remove(P),
    /// Vote to accuse a peer of malicious behaviour.
    Accusation {
        /// Public id of the peer committing the malice.
        offender: P,
        /// Type of the malice committed.
        malice: Malice<T, P>,
    },
    /// Vote for an event which is opaque to Parsec.
    OpaquePayload(T),
}

impl<T: NetworkEvent, P: PublicId> Observation<T, P> {
    /// Compute hash of this `Observation`.
    pub fn create_hash(&self) -> Hash {
        Hash::from(serialise(self).as_slice())
    }
}

/// Type of malicious behaviour.
#[serde(bound = "")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub enum Malice<T: NetworkEvent, P: PublicId> {
    /// Event carries a vote for `Observation::Genesis`, but shouldn't.
    UnexpectedGenesis(Hash),
    /// Two or more votes with the same observation by the same creator.
    DuplicateVote(Hash, Hash),
    /// Event should be carrying a vote for `Observation::Genesis`, but doesn't
    MissingGenesis(Hash),
    /// Event carries a vote for `Observation::Genesis` which doesn't correspond to what we know.
    IncorrectGenesis(Hash),
    /// Event carries other_parent older than first ancestor of self_parent.
    StaleOtherParent(Hash),
    /// More than one events having this event as its self_parent.
    Fork(Hash),
    /// A node incorrectly accused other node of malice. Contains hash of the invalid Accusation
    /// event.
    InvalidAccusation(Hash),
    /// We receive a gossip containing an event whose creator should not be known to the sender.
    /// Contains hash of the sync event whose ancestor has the invalid creator.
    InvalidGossipCreator(Hash),
    /// The peer shall raise an accusation against another peer creating a malice.
    /// Contains hash of the sync event whose creator shall detect such malice however failed to
    /// raise an accusation.
    Accomplice(Hash),
    /// Event's creator is the same to its other_parent's creator. The accusation contains the
    /// original event so other peers can verify the accusation directly.
    OtherParentBySameCreator(Box<PackedEvent<T, P>>),
    // TODO: add other malice variants
}
