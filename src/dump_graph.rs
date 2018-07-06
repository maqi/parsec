// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use gossip::Event;
use hash::Hash;
use id::PublicId;
use meta_vote::MetaVote;
use network_event::NetworkEvent;
use std::collections::BTreeMap;

/// Use this to initialise the folder into which the dot files will be dumped.  This allows the
/// folder's path to be displayed at the start of a run, rather than at the arbitrary point when
/// the first node's first stable block is about to be returned.  No-op for case where `dump-graphs`
/// feature not enabled.
pub(crate) fn init() {
    #[cfg(feature = "dump-graphs")]
    detail::init()
}

/// This function will dump the graphs from the specified peer in dot format to a random folder in
/// the system's temp dir.  The location of this folder will be printed to stdout.  The function
/// will never panic, and hence is suitable for use in creating these files after a thread has
/// already panicked, e.g. in the case of a test failure.  No-op for case where `dump-graphs`
/// feature not enabled.
pub(crate) fn to_file<T: NetworkEvent, P: PublicId>(
    _owner_id: &P,
    _gossip_graph: &BTreeMap<Hash, Event<T, P>>,
    _meta_votes: &BTreeMap<Hash, BTreeMap<P, Vec<MetaVote>>>,
) {
    #[cfg(feature = "dump-graphs")]
    detail::to_file(_owner_id, _gossip_graph, _meta_votes)
}

#[cfg(feature = "dump-graphs")]
mod detail {
    use gossip::Event;
    use hash::Hash;
    use id::PublicId;
    use meta_vote::MetaVote;
    use network_event::NetworkEvent;
    use rand::{self, Rng};
    use std::cell::RefCell;
    use std::cmp;
    use std::collections::BTreeMap;
    use std::env;
    use std::fmt::Debug;
    use std::fs::{self, File};
    use std::io::{self, Write};
    use std::path::PathBuf;
    use std::thread;

    lazy_static! {
        static ref ROOT_DIR: PathBuf = {
            env::temp_dir().join("parsec_graphs").join(
                rand::thread_rng()
                    .gen_ascii_chars()
                    .take(6)
                    .collect::<String>(),
            )
        };
    }

    thread_local!(static DIR: PathBuf = {
        let dir = match thread::current().name() {
            Some(thread_name) if thread_name != "main" => {
                ROOT_DIR.join(format!("test_{}", thread_name))
            }
            _ => ROOT_DIR.clone(),
        };
        if let Err(error) = fs::create_dir_all(&dir) {
            println!("Failed to create folder for dot files: {:?}", error);
        } else {
            println!("Writing dot files in {:?}", dir);
        }
        dir
    };);

    thread_local!(static DUMP_COUNTS: RefCell<BTreeMap<String, usize>> =
        RefCell::new(BTreeMap::new()));

    pub(crate) fn init() {
        DIR.with(|_| ());
    }

    pub(crate) fn to_file<T: NetworkEvent, P: PublicId>(
        owner_id: &P,
        gossip_graph: &BTreeMap<Hash, Event<T, P>>,
        meta_votes: &BTreeMap<Hash, BTreeMap<P, Vec<MetaVote>>>,
    ) {
        let id = format!("{:?}", owner_id);
        let call_count = DUMP_COUNTS.with(|counts| {
            let mut borrowed_counts = counts.borrow_mut();
            let count = borrowed_counts.entry(id.clone()).or_insert(0);
            *count += 1;
            *count
        });
        let file_path = DIR.with(|dir| dir.join(format!("{}-{:03}.dot", id, call_count)));
        if let Ok(mut file) = File::create(&file_path) {
            let initial_events: Vec<Hash> = gossip_graph
                .iter()
                .filter_map(|(hash, event)| {
                    if event.index.unwrap_or(0) == 0 {
                        Some(*hash)
                    } else {
                        None
                    }
                })
                .collect();
            if let Err(error) =
                write_gossip_graph_dot(&mut file, gossip_graph, meta_votes, &initial_events)
            {
                println!("Error writing to {:?}: {:?}", file_path, error);
            }
        } else {
            println!("Failed to create {:?}", file_path);
        }
    }

    fn first_char<D: Debug>(id: &D) -> Option<char> {
        format!("{:?}", id).chars().next()
    }

    fn write_self_parents<T: NetworkEvent, P: PublicId>(
        writer: &mut Write,
        node: &P,
        gossip_graph: &BTreeMap<Hash, Event<T, P>>,
        events: &[&Event<T, P>],
        positions: &BTreeMap<Hash, u64>,
    ) -> io::Result<()> {
        writeln!(writer, "    {:?} [style=invis]", node)?;
        for event in events {
            if let Some(self_parent) = event.self_parent() {
                let parent = if let Some(parent) = gossip_graph.get(self_parent) {
                    parent
                } else {
                    continue;
                };
                let event_pos = *positions.get(event.hash()).unwrap_or(&0);
                let self_parent_pos = *positions.get(parent.hash()).unwrap_or(&0);
                let minlen = if event_pos > self_parent_pos {
                    event_pos - self_parent_pos
                } else {
                    1
                };
                writeln!(
                    writer,
                    "    \"{:?}\" -> \"{:?}\" [minlen={}]",
                    self_parent,
                    event.hash(),
                    minlen
                )?
            } else {
                writeln!(
                    writer,
                    "    {:?} -> \"{:?}\" [style=invis]",
                    node,
                    event.hash()
                )?
            }
        }
        writeln!(writer)
    }

    fn write_subgraph<T: NetworkEvent, P: PublicId>(
        writer: &mut Write,
        node: &P,
        gossip_graph: &BTreeMap<Hash, Event<T, P>>,
        events: &[&Event<T, P>],
        positions: &BTreeMap<Hash, u64>,
    ) -> io::Result<()> {
        writeln!(writer, "    style=invis")?;
        writeln!(writer, "  subgraph cluster_{:?} {{", node)?;
        writeln!(writer, "    label={:?}", node)?;
        write_self_parents(writer, node, gossip_graph, events, positions)?;
        writeln!(writer)?;
        writeln!(writer, "  }}")
    }

    fn write_other_parents<T: NetworkEvent, P: PublicId>(
        w: &mut Write,
        events: &[&Event<T, P>],
    ) -> io::Result<()> {
        // Write the communications between events
        for event in events {
            if let Some(other_event) = event.other_parent() {
                writeln!(
                    w,
                    "  \"{:?}\" -> \"{:?}\" [constraint=false]",
                    other_event,
                    event.hash()
                )?;
            }
        }
        writeln!(w)
    }

    fn write_nodes<P: PublicId>(writer: &mut Write, nodes: &[P]) -> io::Result<()> {
        writeln!(writer, "  {{")?;
        writeln!(writer, "    rank=same")?;
        for node in nodes {
            writeln!(writer, "    {:?} [style=filled, color=white]", node)?;
        }
        writeln!(writer, "  }}")?;

        // Order the nodes alphabetically
        let mut peers: Vec<&P> = nodes.iter().collect();
        peers.sort_by(|lhs, rhs| first_char(lhs).cmp(&first_char(rhs)));

        write!(writer, "  ")?;
        let mut index = 0;
        for peer in &peers {
            write!(writer, "{:?}", peer)?;
            if index < peers.len() - 1 {
                write!(writer, " -> ")?;
                index += 1;
            }
        }
        writeln!(writer, " [style=invis]")
    }

    fn write_evaluates<T: NetworkEvent, P: PublicId>(
        writer: &mut Write,
        gossip_graph: &BTreeMap<Hash, Event<T, P>>,
        meta_votes: &BTreeMap<Hash, BTreeMap<P, Vec<MetaVote>>>,
        initial_events: &[Hash],
    ) -> io::Result<()> {
        for (event_hash, event) in gossip_graph.iter() {
            write!(writer, " \"{:?}\" [", event.hash())?;
            if meta_votes.contains_key(event_hash) {
                write!(writer, " shape=rectangle, ")?;
            }
            writeln!(
                writer,
                "fillcolor=white, label=\"{}_{}",
                first_char(event.creator()).unwrap_or('E'),
                event.index.unwrap_or(0)
            )?;

            if let Some(event_payload) = event.vote().map(|vote| vote.payload()) {
                writeln!(writer, "payload: {:?}", event_payload)?;
            }

            // Write the `valid_blocks_carried` if have
            if !event.valid_blocks_carried.is_empty() {
                write!(writer, "valid_blocks: {:?}", event.valid_blocks_carried)?;
            }

            // Write the `meta_votes` if have
            if let Some(event_meta_votes) = meta_votes.get(event_hash) {
                if event_meta_votes.len() >= initial_events.len() {
                    let mut peer_ids: Vec<&P> = event_meta_votes.keys().collect();
                    peer_ids.sort_by(|lhs, rhs| first_char(lhs).cmp(&first_char(rhs)));

                    for peer in &peer_ids {
                        if let Some(votes) = event_meta_votes.get(peer) {
                            if votes.is_empty() {
                                write!(writer, "\n{}: []", first_char(peer).unwrap_or('E'))?;
                            } else {
                                write!(writer, "\n{}: [ ", first_char(peer).unwrap_or('E'))?;
                                for i in 0..votes.len() {
                                    if i == votes.len() - 1 {
                                        write!(writer, "{:?}]", votes[i])?;
                                    } else {
                                        writeln!(writer, "{:?}", votes[i])?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            writeln!(writer, "\"]")?;
            // Add any styling
            if event.vote().is_some() {
                writeln!(
                    writer,
                    " \"{:?}\" [shape=rectangle, style=filled, fillcolor=cyan]",
                    event.hash()
                )?;
            }
        }

        writeln!(writer)
    }

    fn parent_pos(
        index: Option<u64>,
        parent_hash: Option<&Hash>,
        positions: &BTreeMap<Hash, u64>,
    ) -> Option<u64> {
        if let Some(parent_hash) = parent_hash {
            if let Some(parent_pos) = positions.get(parent_hash) {
                Some(*parent_pos)
            } else {
                None
            }
        } else {
            Some(index.unwrap_or(0))
        }
    }

    fn update_pos<T: NetworkEvent, P: PublicId>(
        positions: &mut BTreeMap<Hash, u64>,
        gossip_graph: &BTreeMap<Hash, Event<T, P>>,
    ) {
        while positions.len() < gossip_graph.len() {
            for (hash, event) in gossip_graph.iter() {
                if !positions.contains_key(hash) {
                    let self_parent_pos = if let Some(position) =
                        parent_pos(event.index, event.self_parent(), &positions)
                    {
                        position
                    } else {
                        continue;
                    };
                    let other_parent_pos = if let Some(position) =
                        parent_pos(event.index, event.other_parent(), &positions)
                    {
                        position
                    } else {
                        continue;
                    };
                    let _ =
                        positions.insert(*hash, cmp::max(self_parent_pos, other_parent_pos) + 1);
                    break;
                }
            }
        }
    }

    fn write_gossip_graph_dot<T: NetworkEvent, P: PublicId>(
        writer: &mut Write,
        gossip_graph: &BTreeMap<Hash, Event<T, P>>,
        meta_votes: &BTreeMap<Hash, BTreeMap<P, Vec<MetaVote>>>,
        initial_events: &[Hash],
    ) -> io::Result<()> {
        let mut nodes = Vec::new();
        for initial in initial_events {
            let initial_event = if let Some(initial_event) = gossip_graph.get(initial) {
                initial_event
            } else {
                continue;
            };
            nodes.push(initial_event.creator().clone());
        }

        let mut positions: BTreeMap<Hash, u64> = BTreeMap::new();
        update_pos(&mut positions, gossip_graph);

        writeln!(writer, "digraph GossipGraph {{")?;
        writeln!(writer, "  splines=false")?;
        writeln!(writer, "  rankdir=BT")?;

        for node in &nodes {
            let mut events: Vec<&Event<T, P>> = gossip_graph
                .values()
                .filter_map(|event| {
                    if event.creator() == node {
                        Some(event)
                    } else {
                        None
                    }
                })
                .collect();
            events.sort_by_key(|event| event.index.unwrap_or(0));
            write_subgraph(writer, node, gossip_graph, &events, &positions)?;
            write_other_parents(writer, &events)?;
        }

        write_evaluates(writer, gossip_graph, meta_votes, initial_events)?;

        write_nodes(writer, &nodes)?;
        writeln!(writer, "}}")
    }
}
