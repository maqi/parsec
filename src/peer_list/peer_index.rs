// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use std::cmp;
use std::fmt::{self, Debug, Formatter};
use std::iter::FromIterator;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub(crate) struct PeerIndex(pub(super) usize);

impl PeerIndex {
    /// `PeerIndex` of ourselves.
    pub const OUR: Self = PeerIndex(0);

    #[cfg(any(test, feature = "testing"))]
    pub fn new_test_peer_index(index: usize) -> Self {
        PeerIndex(index)
    }
}

/// Map keyed by `PeerIndex`.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PeerIndexMap<T>(Vec<Option<T>>);

impl<T> PeerIndexMap<T> {
    pub fn new() -> Self {
        PeerIndexMap(Vec::new())
    }

    pub fn get(&self, key: PeerIndex) -> Option<&T> {
        self.0.get(key.0).and_then(|value| value.as_ref())
    }

    pub fn get_mut(&mut self, key: PeerIndex) -> Option<&mut T> {
        self.0.get_mut(key.0).and_then(|value| value.as_mut())
    }

    pub fn contains_key(&self, key: PeerIndex) -> bool {
        self.0
            .get(key.0)
            .map(|value| value.is_some())
            .unwrap_or(false)
    }

    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|value| value.is_none())
    }

    pub fn iter(&self) -> MapIter<T> {
        MapIter {
            map: self,
            current: 0,
        }
    }

    pub fn keys<'a>(&'a self) -> impl Iterator<Item = PeerIndex> + 'a {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, value)| value.is_some())
            .map(|(index, _)| PeerIndex(index))
    }

    pub fn insert(&mut self, key: PeerIndex, value: T) -> Option<T> {
        self.reserve(key.0 + 1);
        self.0[key.0].replace(value)
    }

    pub fn clear(&mut self) {
        self.0.clear()
    }

    pub fn entry(&mut self, key: PeerIndex) -> Entry<T> {
        if self.contains_key(key) {
            Entry::Occupied(OccupiedEntry { key, map: self })
        } else {
            Entry::Vacant(VacantEntry { key, map: self })
        }
    }

    fn reserve(&mut self, new_len: usize) {
        let add = new_len.saturating_sub(self.0.len());
        self.0.extend((0..add).map(|_| None))
    }
}

impl<T> Default for PeerIndexMap<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FromIterator<(PeerIndex, T)> for PeerIndexMap<T> {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (PeerIndex, T)>,
    {
        let iter = iter.into_iter();
        let (lower, _) = iter.size_hint();
        let mut map = PeerIndexMap(Vec::with_capacity(lower));

        for (index, value) in iter {
            let _ = map.insert(index, value);
        }

        map
    }
}

impl<T: Debug> Debug for PeerIndexMap<T> {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

#[derive(Copy, Clone)]
pub(crate) struct MapIter<'a, T> {
    map: &'a PeerIndexMap<T>,
    current: usize,
}

impl<'a, T> Iterator for MapIter<'a, T> {
    type Item = (PeerIndex, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let index = self.current;
            if index >= self.map.0.len() {
                return None;
            }

            self.current += 1;

            if let Some(value) = self.map.0[index].as_ref() {
                return Some((PeerIndex(index), value));
            }
        }
    }
}

impl<'a, T> IntoIterator for &'a PeerIndexMap<T> {
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = MapIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        MapIter {
            map: self,
            current: 0,
        }
    }
}

pub(crate) enum Entry<'a, T> {
    Occupied(OccupiedEntry<'a, T>),
    Vacant(VacantEntry<'a, T>),
}

impl<'a, T> Entry<'a, T> {
    pub fn or_insert(self, default: T) -> &'a mut T {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default),
        }
    }

    pub fn or_insert_with<F: FnOnce() -> T>(self, default: F) -> &'a mut T {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default()),
        }
    }
}

pub(crate) struct OccupiedEntry<'a, T> {
    key: PeerIndex,
    map: &'a mut PeerIndexMap<T>,
}

impl<'a, T> OccupiedEntry<'a, T> {
    pub fn into_mut(self) -> &'a mut T {
        self.map.0[self.key.0].as_mut().unwrap()
    }
}

pub(crate) struct VacantEntry<'a, T> {
    key: PeerIndex,
    map: &'a mut PeerIndexMap<T>,
}

impl<'a, T> VacantEntry<'a, T> {
    pub fn insert(self, value: T) -> &'a mut T {
        self.map.reserve(self.key.0 + 1);
        self.map.0[self.key.0].get_or_insert(value)
    }
}

/// Set of `PeerIndex`.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PeerIndexSet(Vec<bool>);

impl PeerIndexSet {
    pub fn new() -> Self {
        PeerIndexSet(Vec::new())
    }

    pub fn contains(&self, key: PeerIndex) -> bool {
        self.0.get(key.0).cloned().unwrap_or(false)
    }

    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|value| !*value)
    }

    pub fn len(&self) -> usize {
        self.0.iter().filter(|value| **value).count()
    }

    pub fn iter(&self) -> SetIter {
        SetIter {
            set: self,
            current: 0,
        }
    }

    pub fn insert(&mut self, value: PeerIndex) -> bool {
        let new_len = cmp::max(self.0.len(), value.0 + 1);
        self.0.resize(new_len, false);
        let prev = self.0[value.0];
        self.0[value.0] = true;
        !prev
    }

    pub fn remove(&mut self, value: PeerIndex) -> bool {
        if let Some(value) = self.0.get_mut(value.0) {
            let prev = *value;
            *value = false;
            prev
        } else {
            false
        }
    }

    pub fn clear(&mut self) {
        self.0.clear()
    }
}

impl Default for PeerIndexSet {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<PeerIndex> for PeerIndexSet {
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = PeerIndex>,
    {
        let mut set = PeerIndexSet(Vec::new());
        set.extend(iter);
        set
    }
}

impl Extend<PeerIndex> for PeerIndexSet {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = PeerIndex>,
    {
        let iter = iter.into_iter();
        let (lower, _) = iter.size_hint();
        self.0.reserve(lower);

        for value in iter {
            let _ = self.insert(value);
        }
    }
}

impl Debug for PeerIndexSet {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

#[derive(Copy, Clone)]
pub(crate) struct SetIter<'a> {
    set: &'a PeerIndexSet,
    current: usize,
}

impl<'a> Iterator for SetIter<'a> {
    type Item = PeerIndex;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let index = self.current;
            if index >= self.set.0.len() {
                return None;
            }

            self.current += 1;

            if self.set.0[index] {
                return Some(PeerIndex(index));
            }
        }
    }
}

impl<'a> IntoIterator for &'a PeerIndexSet {
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = SetIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        SetIter {
            set: self,
            current: 0,
        }
    }
}

#[derive(Clone)]
pub(crate) struct SetIntoIter {
    set: PeerIndexSet,
    current: usize,
}

impl Iterator for SetIntoIter {
    type Item = PeerIndex;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let index = self.current;
            if index >= self.set.0.len() {
                return None;
            }

            self.current += 1;

            if self.set.0[index] {
                return Some(PeerIndex(index));
            }
        }
    }
}

impl IntoIterator for PeerIndexSet {
    type Item = <Self::IntoIter as Iterator>::Item;
    type IntoIter = SetIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        SetIntoIter {
            set: self,
            current: 0,
        }
    }
}
