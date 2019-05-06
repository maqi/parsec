// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

/// A simple enum to hold a set of bools.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoolSet {
    Empty,
    Single(bool),
    Both,
}

impl Default for BoolSet {
    fn default() -> BoolSet {
        BoolSet::Empty
    }
}

impl BoolSet {
    pub fn is_empty(self) -> bool {
        self == BoolSet::Empty
    }

    pub fn insert(&mut self, val: bool) -> bool {
        match *self {
            BoolSet::Empty => *self = BoolSet::Single(val),
            BoolSet::Single(s) if s != val => *self = BoolSet::Both,
            _ => return false,
        }
        true
    }

    pub fn contains(self, val: bool) -> bool {
        match self {
            BoolSet::Empty => false,
            BoolSet::Single(ref s) => *s == val,
            BoolSet::Both => true,
        }
    }

    pub fn len(self) -> usize {
        match self {
            BoolSet::Empty => 0,
            BoolSet::Single(_) => 1,
            BoolSet::Both => 2,
        }
    }

    pub fn from_bool(val: bool) -> Self {
        BoolSet::Single(val)
    }
}
