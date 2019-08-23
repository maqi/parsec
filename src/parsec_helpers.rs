// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{gossip::AbstractEventRef, observation::ObservationKey};
use itertools::Itertools;
use std::cmp::Ordering;
use std::usize;

/// Find interesting payloads for the builder_event.
/// For payload observed from builder_event, order them by creation index.
pub(crate) fn find_interesting_content_for_event<'a, E>(
    builder_event: E,
    unconsensused_events: impl Iterator<Item = E>,
    consistent_cmp: impl Fn(&ObservationKey, &ObservationKey) -> Ordering,
    is_descendant: impl Fn(E, E) -> bool,
    is_already_interesting_content: impl Fn(&ObservationKey) -> bool,
    is_interesting_payload: impl Fn(&ObservationKey) -> bool,
) -> Vec<ObservationKey>
where
    E: AbstractEventRef<'a>,
{
    let has_builder_creator = |event: E| event.creator() == builder_event.creator();

    let mut events_to_process = unconsensused_events
        .filter(|event| is_descendant(builder_event, *event))
        .filter_map(|event| {
            event
                .payload_key()
                .filter(|payload_key| !is_already_interesting_content(payload_key))
                .map(|payload_key| {
                    (
                        event,
                        (payload_key, if has_builder_creator(event) { 0 } else { 1 }),
                    )
                })
        })
        .collect_vec();

    // Transform to `Vec<(PayloadKey, Vec<Event>)>` so we can process identical payload once.
    // The First element of `Vec<Event>` will be the event that has builder creator.
    //
    // Order to group same payload together so group_by can group events with same payloads.
    // Each payload exists in Number of peers events with `ConsensusMode::Supermajority`.
    events_to_process.sort_by(|(_, l_key), (_, r_key)| l_key.cmp(&r_key));
    let payload_keys_with_events = events_to_process
        .into_iter()
        .group_by(|(_, (&payload_key, _))| payload_key)
        .into_iter()
        .map(|(payload_key, events)| {
            let events = events.map(|(event, _)| event);
            (payload_key, events.collect_vec())
        })
        .collect_vec();

    let mut interesting_payload_keys = payload_keys_with_events
        .iter()
        .filter_map(|(payload_key, events)| {
            // Event created by builder creator is first. Return this event if suitable.
            if is_interesting_payload(&payload_key) {
                events.iter().next().map(|event| (event, payload_key))
            } else {
                None
            }
        })
        .map(|(event, payload_key)| {
            (
                if has_builder_creator(*event) {
                    event.index_by_creator()
                } else {
                    usize::MAX
                },
                payload_key,
            )
        })
        .collect_vec();

    // Sort the payloads in the order the creator voted for them, followed by the ones
    // not voted for by the creator (if any).
    interesting_payload_keys.sort_by(|(l_index, l_key), (r_index, r_key)| {
        if l_index == r_index {
            consistent_cmp(l_key, r_key)
        } else {
            l_index.cmp(r_index)
        }
    });

    interesting_payload_keys
        .into_iter()
        .map(|(_, key)| key)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        hash::Hash,
        // mock::PeerId,
        observation::{ConsensusMode, ObservationHash},
        peer_list::PeerIndex,
    };

    lazy_static! {
        /// Hashes for opaque events to use in tests.
        static ref OPAQUE_HASHES: Vec<ObservationHash> =
            (0..9).map(observation_hash_from_u8).collect();

        /// Peer indexes to use in tests.
        static ref PEER_IDS: Vec<PeerIndex> =
            (0..9).map(PeerIndex::new_test_peer_index).collect();

        /// Mock ids for ordering in tests.
        static ref NAMES: Vec<u8> = vec![
            5, 9, 6, 1, 8, 2, 3, 7, 0, 4,
        ];
    }

    /// Stand in stub for Event: Implement AbstractEvent.
    #[derive(Debug, Clone)]
    struct TestEvent {
        peer_index: PeerIndex,
        creator_index: usize,
        payload_key: Option<ObservationKey>,
        has_ancestors: bool,
    }

    impl TestEvent {
        fn new(
            peer_index: PeerIndex,
            creator_index: usize,
            payload_hash: Option<ObservationHash>,
        ) -> Self {
            Self {
                peer_index,
                creator_index,
                payload_key: payload_hash.map(|hash| {
                    ObservationKey::new(hash, peer_index, ConsensusMode::Supermajority)
                }),
                has_ancestors: false,
            }
        }

        fn new_single(
            peer_index: PeerIndex,
            creator_index: usize,
            payload_hash: Option<ObservationHash>,
        ) -> Self {
            Self {
                peer_index,
                creator_index,
                payload_key: payload_hash
                    .map(|hash| ObservationKey::new(hash, peer_index, ConsensusMode::Single)),
                has_ancestors: false,
            }
        }

        fn with_ancestors(self) -> Self {
            Self {
                has_ancestors: true,
                ..self
            }
        }
    }

    impl<'a> AbstractEventRef<'a> for &'a TestEvent {
        fn payload_key(self) -> Option<&'a ObservationKey> {
            self.payload_key.as_ref()
        }

        fn creator(self) -> PeerIndex {
            self.peer_index
        }

        fn index_by_creator(self) -> usize {
            self.creator_index
        }
    }

    /// Observation key with readable assertion result and creation.
    #[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Debug)]
    pub(crate) enum AssertObservationKey {
        Single(u8, PeerIndex),
        Supermajority(u8),
    }

    impl AssertObservationKey {
        pub fn new_from_key(key: &ObservationKey, hashes: &[ObservationHash]) -> Self {
            match *key {
                ObservationKey::Single(ref hash, peer) => {
                    AssertObservationKey::Single(find_observation_hash_index(hash, hashes), peer)
                }
                ObservationKey::Supermajority(ref hash) => {
                    AssertObservationKey::Supermajority(find_observation_hash_index(hash, hashes))
                }
            }
        }
    }

    fn observation_hash_from_u8(value: u8) -> ObservationHash {
        ObservationHash(Hash::from(vec![value].as_slice()))
    }

    fn find_observation_hash_index(hash: &ObservationHash, hashes: &[ObservationHash]) -> u8 {
        unwrap!(hashes.iter().position(|obs_hash| obs_hash == hash)) as u8
    }

    /// Tests for find_interesting_content_for_event.
    mod find_interesting_content_for_event {
        use super::*;
        use AssertObservationKey::*;

        /// Data driven test configuration for test_find_interesting_content_for_event
        struct TestSimpleData {
            /// Events setup used for test
            events: Events,
            /// Return values for injected closures
            payload_properties: PayloadProperties,
            /// Expected returned payloads
            expected_payloads: Vec<AssertObservationKey>,
        }

        struct PayloadProperties {
            is_already_interesting_content: bool,
            is_interesting_payload: bool,
        }

        struct Events {
            builder_event: TestEvent,
            unconsensused_events: Vec<TestEvent>,
        }

        impl Events {
            fn with_builder_event_sees_other(self) -> Self {
                Self {
                    builder_event: self.builder_event.with_ancestors(),
                    ..self
                }
            }

            /// A simple setup for Events that can be used in multiple tests.
            fn new_basic_setup() -> Self {
                let opaque_1 = Some(OPAQUE_HASHES[1]);
                let opaque_2 = Some(OPAQUE_HASHES[2]);
                let last_event_peer = PEER_IDS[6];

                Self {
                    builder_event: TestEvent::new(last_event_peer, 100, None),
                    unconsensused_events: vec![
                        TestEvent::new(PEER_IDS[2], 2, opaque_1),
                        TestEvent::new(PEER_IDS[8], 11, opaque_1),
                        TestEvent::new(last_event_peer, 6, opaque_1),
                        TestEvent::new(last_event_peer, 10, opaque_2),
                    ],
                }
            }

            /// A simple setup for Events that can be used in multiple tests.
            fn new_basic_setup_single() -> Self {
                let opaque_1 = Some(OPAQUE_HASHES[1]);
                let opaque_2 = Some(OPAQUE_HASHES[2]);
                let last_event_peer = PEER_IDS[6];

                Self {
                    builder_event: TestEvent::new_single(last_event_peer, 100, None),
                    unconsensused_events: vec![
                        TestEvent::new_single(PEER_IDS[2], 2, opaque_1),
                        TestEvent::new_single(PEER_IDS[8], 11, opaque_1),
                        TestEvent::new_single(last_event_peer, 6, opaque_1),
                        TestEvent::new_single(last_event_peer, 10, opaque_2),
                    ],
                }
            }
        }

        /// Test function for find_interesting_content_for_event
        /// Call with different TestSimpleData for data driven tests
        /// (Follows AAA(Arrange/Act/Assert) test Pattern)
        fn test_find_interesting_content_for_event(data: TestSimpleData) {
            let TestSimpleData {
                events,
                payload_properties,
                expected_payloads,
            } = data;

            let payloads = find_interesting_content_for_event(
                &events.builder_event,
                events.unconsensused_events.iter(),
                |lhs_key, rhs_key| {
                    NAMES[unwrap!(lhs_key.peer_index()).value()]
                        .cmp(&NAMES[unwrap!(rhs_key.peer_index()).value()])
                },
                |event_x, _event_y| event_x.has_ancestors,
                |_payload_key| payload_properties.is_already_interesting_content,
                |_payload_key| payload_properties.is_interesting_payload,
            );

            assert_eq!(
                expected_payloads,
                payloads
                    .iter()
                    .map(|key| AssertObservationKey::new_from_key(key, &OPAQUE_HASHES))
                    .collect_vec()
            );
        }

        #[test]
        /// Basic happy path
        fn all_payloads_interesting() {
            test_find_interesting_content_for_event(TestSimpleData {
                events: Events::new_basic_setup().with_builder_event_sees_other(),
                payload_properties: PayloadProperties {
                    is_already_interesting_content: false,
                    is_interesting_payload: true,
                },
                expected_payloads: vec![Supermajority(1), Supermajority(2)],
            });
        }

        #[test]
        /// Basic happy path
        fn all_payloads_interesting_single() {
            test_find_interesting_content_for_event(TestSimpleData {
                events: Events::new_basic_setup_single().with_builder_event_sees_other(),
                payload_properties: PayloadProperties {
                    is_already_interesting_content: false,
                    is_interesting_payload: true,
                },
                expected_payloads: vec![
                    Single(1, PEER_IDS[6]),
                    Single(2, PEER_IDS[6]),
                    Single(1, PEER_IDS[2]),
                    Single(1, PEER_IDS[8]),
                ],
            });
        }

        #[test]
        /// Filter out already interesting payloads
        fn all_payloads_already_interesting() {
            test_find_interesting_content_for_event(TestSimpleData {
                events: Events::new_basic_setup().with_builder_event_sees_other(),
                payload_properties: PayloadProperties {
                    is_already_interesting_content: true,
                    is_interesting_payload: true,
                },
                expected_payloads: vec![],
            });
        }

        #[test]
        /// Basic case where we found no interesting payloads
        fn no_payloads_interesting() {
            test_find_interesting_content_for_event(TestSimpleData {
                events: Events::new_basic_setup().with_builder_event_sees_other(),
                payload_properties: PayloadProperties {
                    is_already_interesting_content: false,
                    is_interesting_payload: false,
                },
                expected_payloads: vec![],
            });
        }
    }
}
