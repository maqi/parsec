// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use hash::Hash;
use id::PublicId;
use network_event::NetworkEvent;
use std::fmt::{self, Display, Formatter};
use vote::Vote;

#[serde(bound = "")]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Cause<T: NetworkEvent, P: PublicId> {
    // Hashes are the latest `Event` of own and the peer which sent the request.
    Request {
        self_parent: Hash,
        other_parent: Hash,
    },
    // Hashes are the latest `Event` of own and the peer which sent the response.
    Response {
        self_parent: Hash,
        other_parent: Hash,
    },
    // Hash of our latest `Event`. Vote for a single network event of type `T`.
    Observation {
        self_parent: Hash,
        vote: Vote<T, P>,
    },
    // Initial empty `Event` of this peer.
    Initial,
}

impl<T: NetworkEvent, P: PublicId> Display for Cause<T, P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "{}",
            match &self {
                Cause::Request { .. } => "Request".to_string(),
                Cause::Response { .. } => "Response".to_string(),
                Cause::Observation { vote, .. } => format!("Observation({:?})", vote.payload()),
                Cause::Initial => "Initial".to_string(),
            }
        )
    }
}
