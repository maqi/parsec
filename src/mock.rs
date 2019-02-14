// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::id::{PublicId, SecretId};
use crate::network_event::NetworkEvent;
use rand::{Rand, Rng};
use safe_crypto::Signature as SafeSignature;
use safe_crypto::{gen_sign_keypair, PublicSignKey, SecretSignKey};
use std::cmp::Ordering;
use std::fmt::{self, Debug, Display, Formatter};
use std::hash::{Hash, Hasher};

pub const NAMES: &[&str] = &[
    "Alice", "Bob", "Carol", "Dave", "Eric", "Fred", "Gina", "Hank", "Iris", "Judy", "Kent",
    "Lucy", "Mike", "Nina", "Oran", "Paul", "Quin", "Rose", "Stan", "Tina", "Ulf", "Vera", "Will",
    "Xaviera", "Yakov", "Zaida", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
];

lazy_static! {
    static ref PEERS: Vec<PeerId> = NAMES
        .iter()
        .map(|name| PeerId::new_with_random_keypair(name))
        .collect();
}

/// **NOT FOR PRODUCTION USE**: Mock signature type.
#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signature(SafeSignature);

impl Debug for Signature {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "..")
    }
}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `PublicId` and `SecretId` traits.  For
/// non-mocks, these two traits must be implemented by two separate types; a public key and secret
/// key respectively.
#[derive(Clone, Serialize, Deserialize)]
pub struct PeerId {
    id: String,
    pub_sign: PublicSignKey,
    sec_sign: SecretSignKey,
}

impl PeerId {
    pub fn new(id: &str) -> Self {
        PEERS
            .iter()
            .find(|peer| peer.id == id)
            .cloned()
            .unwrap_or_else(|| PeerId::new_with_keypair(id))
    }

    pub fn new_with_random_keypair(id: &str) -> Self {
        let (pub_sign, sec_sign) = gen_sign_keypair();
        Self {
            id: id.to_string(),
            pub_sign,
            sec_sign,
        }
    }

    #[cfg(not(feature = "mock"))]
    fn new_with_keypair(id: &str) -> Self {
        Self::new_with_random_keypair(id)
    }

    #[cfg(feature = "mock")]
    fn new_with_keypair(id: &str) -> Self {
        Self::new_with_deterministic_keypair(id)
    }

    #[cfg(feature = "mock")]
    fn new_with_deterministic_keypair(id: &str) -> Self {
        use crate::hash::Hash;
        use rand::{SeedableRng, XorShiftRng};
        use safe_crypto::init_with_rng;

        let name_hash = Hash::from(id.as_bytes());
        let seed = name_hash
            .as_bytes()
            .chunks_exact(4)
            .map(|bytes| Self::convert_to_u32(bytes))
            .collect::<Vec<_>>();

        let mut rng = XorShiftRng::from_seed(Self::make_array_of_len_4(&seed));
        unwrap!(init_with_rng(&mut rng));

        Self::new_with_random_keypair(id)
    }

    #[cfg(feature = "mock")]
    fn make_array_of_len_4<T: Copy>(values: &[T]) -> [T; 4] {
        [values[0], values[1], values[2], values[3]]
    }

    #[cfg(feature = "mock")]
    fn convert_to_u32<T: Copy>(_values: &[T]) -> u32 {
        6
    }

    // Only being used by the dot_parser.
    #[cfg(any(test, feature = "testing"))]
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn from_index(peer_index: usize) -> Option<Self> {
        NAMES.get(peer_index).map(|name| PeerId::new(name))
    }
}

impl Debug for PeerId {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.id)
    }
}

impl Hash for PeerId {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
        self.pub_sign.hash(state);
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &PeerId) -> bool {
        self.id == other.id && self.pub_sign == other.pub_sign
    }
}

impl Eq for PeerId {}

impl PartialOrd for PeerId {
    fn partial_cmp(&self, other: &PeerId) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PeerId {
    fn cmp(&self, other: &PeerId) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PublicId for PeerId {
    type Signature = Signature;
    fn verify_signature(&self, signature: &Self::Signature, data: &[u8]) -> bool {
        self.pub_sign.verify_detached(&signature.0, data)
    }
}

impl SecretId for PeerId {
    type PublicId = PeerId;
    fn public_id(&self) -> &Self::PublicId {
        &self
    }
    fn sign_detached(&self, data: &[u8]) -> Signature {
        Signature(self.sec_sign.sign_detached(data))
    }
}

/// **NOT FOR PRODUCTION USE**: Mock type implementing `NetworkEvent` trait.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Transaction(String);

impl Transaction {
    pub fn new<T: Into<String>>(id: T) -> Self {
        Transaction(id.into())
    }
}

impl NetworkEvent for Transaction {}

impl Display for Transaction {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "Transaction({})", self.0)
    }
}

impl Debug for Transaction {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl Rand for Transaction {
    fn rand<R: Rng>(rng: &mut R) -> Self {
        Transaction(rng.gen_ascii_chars().take(5).collect())
    }
}

/// **NOT FOR PRODUCTION USE**: Returns a collection of mock node IDs with human-readable names.
pub fn create_ids(count: usize) -> Vec<PeerId> {
    assert!(count <= NAMES.len());
    NAMES.iter().take(count).cloned().map(PeerId::new).collect()
}
