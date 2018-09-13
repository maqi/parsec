// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// This is used to read a dumped dot file and rebuild the event graph and associated info.
mod dot_parser;
mod environment;
mod network;
mod peer;
pub mod proptest;
mod schedule;

pub use self::dot_parser::{parse_dot_file, ParsedContents};
pub use self::environment::{Environment, ObservationCount, PeerCount, RngChoice};
pub use self::network::Network;
pub use self::peer::Peer;
pub use self::schedule::*;

type Observation = super::observation::Observation<super::mock::Transaction, super::mock::PeerId>;
