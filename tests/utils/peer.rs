// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use parsec::mock::{PeerId, Transaction};
use parsec::{Block, Parsec};
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};

pub struct Peer {
    pub id: PeerId,
    pub parsec: Parsec<Transaction, PeerId>,
    // The blocks returned by `parsec.poll()`, held in the order in which they were returned.
    pub blocks: Vec<Block<Transaction, PeerId>>,
}

impl Peer {
    pub fn new(id: PeerId, genesis_group: &BTreeSet<PeerId>) -> Self {
        Self {
            id: id.clone(),
            parsec: unwrap!(Parsec::new(id, genesis_group)),
            blocks: vec![],
        }
    }

    pub fn vote_for_first_not_already_voted_for(&mut self, transactions: &[Transaction]) {
        for transaction in transactions {
            if !self.parsec.have_voted_for(transaction) {
                unwrap!(self.parsec.vote_for(transaction.clone()));
                break;
            }
        }
    }

    pub fn poll(&mut self) {
        while let Some(block) = self.parsec.poll() {
            self.blocks.push(block)
        }
    }

    // Returns the payloads of `self.blocks` in the order in which they were returned by `poll()`.
    pub fn blocks_payloads(&self) -> Vec<&Transaction> {
        self.blocks.iter().map(Block::payload).collect()
    }
}

impl Debug for Peer {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "{:?}: Blocks: {:?}", self.id, self.blocks)
    }
}
