// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::cause::Cause;
use hash::Hash;
use id::PublicId;
use network_event::NetworkEvent;

#[serde(bound = "")]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Content<T: NetworkEvent, P: PublicId> {
    // ID of peer which created this `Event`.
    pub creator: P,
    // Whether it was created by receiving a gossip request, response or by being given a network
    // event to vote for.
    pub cause: Cause<T, P>,
}

impl<T: NetworkEvent, P: PublicId> Content<T, P> {
    // Hash of sender's latest event if the `cause` is a request or response; otherwise `None`.
    pub fn other_parent(&self) -> Option<&Hash> {
        match &self.cause {
            Cause::Request { other_parent, .. } | Cause::Response { other_parent, .. } => {
                Some(other_parent)
            }
            Cause::Observation { .. } | Cause::Initial => None,
        }
    }

    // Hash of our latest event if the `cause` is a request, response or observation; otherwise
    // `None`.
    pub fn self_parent(&self) -> Option<&Hash> {
        match &self.cause {
            Cause::Request { self_parent, .. }
            | Cause::Response { self_parent, .. }
            | Cause::Observation { self_parent, .. } => Some(self_parent),
            Cause::Initial => None,
        }
    }
}
