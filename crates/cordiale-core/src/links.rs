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
//! flat list — `build_links_tree` reconstructs the same tree (root
//! selection, orphan reparenting, cycle safety), and `radial_layout`
//! positions it the same way Cicchetto does: depth drives the ring
//! radius, each node's angle is the mean of its children's angular
//! span (equal slices at the leaves), not a force-directed simulation —
//! see `docs/protocol-notes.md` §4ter.

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

/// One positioned node in a radial layout, coordinates relative to the
/// diagram's own center (0.0, 0.0) — the caller offsets to a canvas
/// origin.
#[derive(Debug, Clone, PartialEq)]
pub struct LinksGraphNode {
    pub server: String,
    pub x: f64,
    pub y: f64,
    pub depth: u32,
}

/// One edge (parent -> child) as a pair of already-positioned endpoints.
#[derive(Debug, Clone, PartialEq)]
pub struct LinksGraphEdge {
    pub from: (f64, f64),
    pub to: (f64, f64),
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RadialLayout {
    pub nodes: Vec<LinksGraphNode>,
    pub edges: Vec<LinksGraphEdge>,
}

/// Positions a reconstructed tree radially: depth sets the ring radius
/// (`depth * ring_gap`), each node's angle is the midpoint of the
/// angular span its subtree was allotted — a leaf gets an equal slice of
/// its parent's span, an internal node's span is divided among its
/// children proportional to their own leaf-descendant count. Same
/// approach as Cicchetto's `assignAngles()`/`radialLayout()`
/// (`cicchetto/src/lib/linksLayout.ts`), not a force-directed layout.
pub fn radial_layout(tree: &[LinksNode], ring_gap: f64) -> RadialLayout {
    let Some(root) = tree.iter().find(|node| node.is_root) else {
        return RadialLayout::default();
    };

    let mut children: HashMap<Option<String>, Vec<&LinksNode>> = HashMap::new();
    for node in tree {
        children.entry(node.parent.clone()).or_default().push(node);
    }
    for kids in children.values_mut() {
        kids.sort_by(|a, b| a.server.cmp(&b.server));
    }

    fn leaf_count(server: &str, children: &HashMap<Option<String>, Vec<&LinksNode>>) -> u32 {
        match children.get(&Some(server.to_string())) {
            Some(kids) if !kids.is_empty() => kids
                .iter()
                .map(|kid| leaf_count(&kid.server, children))
                .sum(),
            _ => 1,
        }
    }

    fn assign_angles(
        server: &str,
        start: f64,
        end: f64,
        children: &HashMap<Option<String>, Vec<&LinksNode>>,
        angle_of: &mut HashMap<String, f64>,
    ) {
        angle_of.insert(server.to_string(), (start + end) / 2.0);
        let Some(kids) = children.get(&Some(server.to_string())) else {
            return;
        };
        let total: u32 = kids.iter().map(|kid| leaf_count(&kid.server, children)).sum();
        let span = end - start;
        let mut cursor = start;
        for kid in kids {
            let weight = leaf_count(&kid.server, children) as f64 / total.max(1) as f64;
            let kid_end = cursor + span * weight;
            assign_angles(&kid.server, cursor, kid_end, children, angle_of);
            cursor = kid_end;
        }
    }

    let mut angle_of: HashMap<String, f64> = HashMap::new();
    assign_angles(
        &root.server,
        0.0,
        std::f64::consts::TAU,
        &children,
        &mut angle_of,
    );

    let mut positions: HashMap<&str, (f64, f64)> = HashMap::new();
    let mut nodes = Vec::with_capacity(tree.len());
    for node in tree {
        let angle = angle_of.get(&node.server).copied().unwrap_or(0.0);
        let radius = f64::from(node.depth) * ring_gap;
        let x = radius * angle.cos();
        let y = radius * angle.sin();
        positions.insert(node.server.as_str(), (x, y));
        nodes.push(LinksGraphNode {
            server: node.server.clone(),
            x,
            y,
            depth: node.depth,
        });
    }

    let mut edges = Vec::new();
    for node in tree {
        let Some(parent) = &node.parent else { continue };
        if let (Some(&from), Some(&to)) = (
            positions.get(parent.as_str()),
            positions.get(node.server.as_str()),
        ) {
            edges.push(LinksGraphEdge { from, to });
        }
    }

    RadialLayout { nodes, edges }
}

/// Renders a `RadialLayout`'s edges as a single SVG `Path` `commands`
/// string (`"M x,y L x,y M x,y L x,y ..."`, one disconnected segment per
/// edge), with `(center_x, center_y)` added to every coordinate so the
/// diagram is centered on a canvas of that size rather than at (0, 0).
pub fn links_graph_edges_svg_path(
    edges: &[LinksGraphEdge],
    center_x: f64,
    center_y: f64,
) -> String {
    edges
        .iter()
        .map(|edge| {
            format!(
                "M {} {} L {} {}",
                edge.from.0 + center_x,
                edge.from.1 + center_y,
                edge.to.0 + center_x,
                edge.to.1 + center_y
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
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

    #[test]
    fn radial_layout_is_empty_without_a_root() {
        assert_eq!(radial_layout(&[], 72.0), RadialLayout::default());
    }

    #[test]
    fn radial_layout_places_the_root_at_the_center() {
        let entries = vec![entry("hub", Some("hub"), 0)];
        let tree = build_links_tree(&entries);
        let layout = radial_layout(&tree, 72.0);

        assert_eq!(layout.nodes.len(), 1);
        assert_eq!((layout.nodes[0].x, layout.nodes[0].y), (0.0, 0.0));
    }

    #[test]
    fn radial_layout_places_children_at_the_ring_radius() {
        let entries = vec![
            entry("hub", Some("hub"), 0),
            entry("leaf-a", Some("hub"), 1),
            entry("leaf-b", Some("hub"), 1),
        ];
        let tree = build_links_tree(&entries);
        let layout = radial_layout(&tree, 72.0);

        let leaf_a = layout
            .nodes
            .iter()
            .find(|node| node.server == "leaf-a")
            .unwrap();
        let radius = (leaf_a.x.powi(2) + leaf_a.y.powi(2)).sqrt();
        assert!((radius - 72.0).abs() < 1e-9);
    }

    #[test]
    fn radial_layout_gives_two_leaves_distinct_angles() {
        let entries = vec![
            entry("hub", Some("hub"), 0),
            entry("leaf-a", Some("hub"), 1),
            entry("leaf-b", Some("hub"), 1),
        ];
        let tree = build_links_tree(&entries);
        let layout = radial_layout(&tree, 72.0);

        let leaf_a = &layout.nodes.iter().find(|n| n.server == "leaf-a").unwrap();
        let leaf_b = &layout.nodes.iter().find(|n| n.server == "leaf-b").unwrap();
        assert!((leaf_a.x - leaf_b.x).abs() > 1e-6 || (leaf_a.y - leaf_b.y).abs() > 1e-6);
    }

    #[test]
    fn radial_layout_produces_one_edge_per_non_root_node() {
        let entries = vec![
            entry("hub", Some("hub"), 0),
            entry("mid", Some("hub"), 1),
            entry("leaf", Some("mid"), 2),
        ];
        let tree = build_links_tree(&entries);
        let layout = radial_layout(&tree, 72.0);

        assert_eq!(layout.edges.len(), 2);
    }

    #[test]
    fn links_graph_edges_svg_path_offsets_by_the_given_center() {
        let edges = vec![LinksGraphEdge {
            from: (0.0, 0.0),
            to: (10.0, 20.0),
        }];
        assert_eq!(
            links_graph_edges_svg_path(&edges, 100.0, 100.0),
            "M 100 100 L 110 120"
        );
    }

    #[test]
    fn links_graph_edges_svg_path_is_empty_for_no_edges() {
        assert_eq!(links_graph_edges_svg_path(&[], 100.0, 100.0), "");
    }
}
