// MIT License
//
// Copyright (c) 2026 Sythos
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

//! `/links` network-topology reconstruction, matching Cicchetto's own
//! interpretation of the wire data — not a flat server list.
//!
//! Grappa's `links_bundle` event (`lib/grappa/session/links_accum.ex`,
//! `lib/grappa/session/wire.ex`) carries a flat array of `(server,
//! linked_to)` edges: `linked_to` is each server's *uplink* (parent), the
//! root self-links (`server == linked_to`, `hopcount == 0`). This is a
//! spanning tree by IRC protocol construction (no loops), and Cicchetto
//! renders it as one (`cicchetto/src/lib/linksLayout.ts`) rather than a
//! flat list — this module reconstructs the same tree (root selection,
//! orphan reparenting, cycle safety), so Cordiale interprets `/links` the
//! same way, even though it renders it as an indented list rather than
//! Cicchetto's radial SVG layout (a visual-only simplification, not a
//! data/structural one — see `docs/protocol-notes.md` §4ter).

use std::collections::HashMap;

use serde::Deserialize;

/// One `(server, linked_to)` edge as it arrives on the wire.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LinksEntry {
    pub server: String,
    #[serde(default)]
    pub linked_to: Option<String>,
    #[serde(default)]
    pub hopcount: Option<i64>,
    #[serde(default)]
    pub description: Option<String>,
}

/// One reconstructed tree node: `depth` is Cordiale's own reconstruction
/// (drives indentation), `hopcount` is the ircd-reported value verbatim —
/// the two are kept distinct, deliberately, exactly as Cicchetto does,
/// since they can differ on a masked/partial reply.
#[derive(Debug, Clone, PartialEq)]
pub struct LinksNode {
    pub server: String,
    pub description: Option<String>,
    pub hopcount: Option<i64>,
    pub depth: u32,
    pub parent: Option<String>,
    pub is_root: bool,
}

/// Reconstructs the spanning tree from a flat `/links` reply.
///
/// Root selection priority, matching `buildTree()`: a self-linked entry,
/// else the smallest `hopcount`, else the first entry. Every entry ends
/// up in the result — an uplink missing from the reply, or a cycle, gets
/// attached directly under the root rather than dropped, the same
/// guarantee `buildTree()` documents.
pub fn build_links_tree(entries: &[LinksEntry]) -> Vec<LinksNode> {
    if entries.is_empty() {
        return Vec::new();
    }

    let root_server = entries
        .iter()
        .find(|entry| entry.linked_to.as_deref() == Some(entry.server.as_str()))
        .map(|entry| entry.server.clone())
        .or_else(|| {
            entries
                .iter()
                .min_by_key(|entry| entry.hopcount.unwrap_or(i64::MAX))
                .map(|entry| entry.server.clone())
        })
        .unwrap_or_else(|| entries[0].server.clone());

    let by_server: HashMap<&str, &LinksEntry> = entries
        .iter()
        .map(|entry| (entry.server.as_str(), entry))
        .collect();

    let mut depth_of: HashMap<String, u32> = HashMap::new();
    let mut parent_of: HashMap<String, Option<String>> = HashMap::new();
    depth_of.insert(root_server.clone(), 0);
    parent_of.insert(root_server.clone(), None);

    // Iteratively attach whatever can be attached (parent already
    // resolved) until a pass makes no progress; anything still standing
    // at that point (a missing uplink, or an isolated cycle with no path
    // back to root) attaches directly under root instead of being
    // dropped.
    loop {
        let mut attached_any = false;
        for entry in entries {
            if depth_of.contains_key(&entry.server) {
                continue;
            }
            let usable_parent = entry
                .linked_to
                .as_ref()
                .filter(|parent| parent.as_str() != entry.server)
                .filter(|parent| by_server.contains_key(parent.as_str()));

            match usable_parent {
                Some(parent) => {
                    if let Some(&parent_depth) = depth_of.get(parent) {
                        depth_of.insert(entry.server.clone(), parent_depth + 1);
                        parent_of.insert(entry.server.clone(), Some(parent.clone()));
                        attached_any = true;
                    }
                }
                None => {
                    depth_of.insert(entry.server.clone(), 1);
                    parent_of.insert(entry.server.clone(), Some(root_server.clone()));
                    attached_any = true;
                }
            }
        }
        if !attached_any {
            break;
        }
    }

    // Isolated cycles disconnected from root never resolve through the
    // loop above (each member's parent is always "not yet resolved") —
    // sweep them onto root too, so nothing is ever silently missing.
    for entry in entries {
        depth_of.entry(entry.server.clone()).or_insert(1);
        parent_of
            .entry(entry.server.clone())
            .or_insert_with(|| Some(root_server.clone()));
    }

    entries
        .iter()
        .map(|entry| LinksNode {
            server: entry.server.clone(),
            description: entry.description.clone(),
            hopcount: entry.hopcount,
            depth: depth_of.get(&entry.server).copied().unwrap_or(1),
            parent: parent_of.get(&entry.server).cloned().flatten(),
            is_root: entry.server == root_server,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(server: &str, linked_to: Option<&str>, hopcount: i64) -> LinksEntry {
        LinksEntry {
            server: server.to_string(),
            linked_to: linked_to.map(str::to_string),
            hopcount: Some(hopcount),
            description: None,
        }
    }

    #[test]
    fn build_links_tree_is_empty_for_no_entries() {
        assert_eq!(build_links_tree(&[]), Vec::new());
    }

    #[test]
    fn build_links_tree_finds_the_self_linked_root() {
        let entries = vec![
            entry("hub", Some("hub"), 0),
            entry("leaf-a", Some("hub"), 1),
            entry("leaf-b", Some("hub"), 1),
        ];
        let tree = build_links_tree(&entries);

        let root = tree.iter().find(|node| node.server == "hub").unwrap();
        assert!(root.is_root);
        assert_eq!(root.depth, 0);
        assert_eq!(root.parent, None);

        let leaf_a = tree.iter().find(|node| node.server == "leaf-a").unwrap();
        assert_eq!(leaf_a.depth, 1);
        assert_eq!(leaf_a.parent, Some("hub".to_string()));
    }

    #[test]
    fn build_links_tree_reconstructs_multiple_levels() {
        let entries = vec![
            entry("hub", Some("hub"), 0),
            entry("mid", Some("hub"), 1),
            entry("leaf", Some("mid"), 2),
        ];
        let tree = build_links_tree(&entries);

        let leaf = tree.iter().find(|node| node.server == "leaf").unwrap();
        assert_eq!(leaf.depth, 2);
        assert_eq!(leaf.parent, Some("mid".to_string()));
        // hopcount is preserved verbatim, distinct from reconstructed depth.
        assert_eq!(leaf.hopcount, Some(2));
    }

    #[test]
    fn build_links_tree_falls_back_to_smallest_hopcount_without_a_self_link() {
        let entries = vec![entry("a", Some("b"), 2), entry("b", Some("a"), 0)];
        let tree = build_links_tree(&entries);

        let root = tree.iter().find(|node| node.is_root).unwrap();
        assert_eq!(root.server, "b");
    }

    #[test]
    fn build_links_tree_reparents_a_missing_uplink_to_root() {
        let entries = vec![
            entry("hub", Some("hub"), 0),
            entry("orphan", Some("nowhere"), 3),
        ];
        let tree = build_links_tree(&entries);

        let orphan = tree.iter().find(|node| node.server == "orphan").unwrap();
        assert_eq!(orphan.depth, 1);
        assert_eq!(orphan.parent, Some("hub".to_string()));
    }

    #[test]
    fn build_links_tree_never_drops_a_node_in_an_isolated_cycle() {
        let entries = vec![
            entry("hub", Some("hub"), 0),
            entry("a", Some("b"), 5),
            entry("b", Some("a"), 5),
        ];
        let tree = build_links_tree(&entries);

        assert_eq!(tree.len(), 3);
        assert!(tree.iter().all(|node| node.depth < u32::MAX));
    }

    #[test]
    fn build_links_tree_handles_a_chain_of_orphans_progressively() {
        // "grand" and "child" are both disconnected from the resolvable
        // root at the point they're first considered; "child" only
        // resolves once "grand" itself resolves (onto root).
        let entries = vec![
            entry("hub", Some("hub"), 0),
            entry("child", Some("grand"), 2),
            entry("grand", Some("missing"), 1),
        ];
        let tree = build_links_tree(&entries);

        let grand = tree.iter().find(|node| node.server == "grand").unwrap();
        assert_eq!(grand.depth, 1);
        assert_eq!(grand.parent, Some("hub".to_string()));

        let child = tree.iter().find(|node| node.server == "child").unwrap();
        assert_eq!(child.depth, 2);
        assert_eq!(child.parent, Some("grand".to_string()));
    }
}
