//! Topic trie with interned node ids, subscriptions and retained messages.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use urmqtt_mqtt::QoS;

use crate::{Msg, SessionId};

pub type NodeId = u32;
const ROOT: NodeId = 0;

#[derive(Default)]
struct Node {
    children: BTreeMap<Box<str>, NodeId>,
    subs: Vec<(SessionId, QoS)>,
    retained: Option<(Msg, QoS)>,
}

pub struct Topics {
    nodes: Vec<Node>,
    retained: usize,
}

impl Default for Topics {
    fn default() -> Self {
        Self::new()
    }
}

impl Topics {
    pub fn new() -> Self {
        Self {
            nodes: alloc::vec![Node::default()],
            retained: 0,
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn retained_count(&self) -> usize {
        self.retained
    }

    fn child(&self, n: NodeId, level: &str) -> Option<NodeId> {
        self.nodes.get(n as usize)?.children.get(level).copied()
    }

    /// Node for `path` (topic or filter), created if missing.
    pub fn intern(&mut self, path: &str) -> NodeId {
        let mut n = ROOT;
        for level in path.split('/') {
            n = match self.child(n, level) {
                Some(c) => c,
                None => {
                    let id = self.nodes.len() as NodeId;
                    self.nodes.push(Node::default());
                    if let Some(parent) = self.nodes.get_mut(n as usize) {
                        parent.children.insert(level.into(), id);
                    }
                    id
                }
            };
        }
        n
    }

    pub fn subscribe(&mut self, node: NodeId, s: SessionId, qos: QoS) {
        if let Some(n) = self.nodes.get_mut(node as usize) {
            match n.subs.iter_mut().find(|(id, _)| *id == s) {
                Some(e) => e.1 = qos,
                None => n.subs.push((s, qos)),
            }
        }
    }

    pub fn unsubscribe(&mut self, node: NodeId, s: SessionId) {
        if let Some(n) = self.nodes.get_mut(node as usize) {
            n.subs.retain(|(id, _)| *id != s);
        }
    }

    /// Subscribers matching `topic`, with the highest QoS per session.
    pub fn subscribers(&self, topic: &str, out: &mut Vec<(SessionId, QoS)>) {
        out.clear();
        let levels: Vec<&str> = topic.split('/').collect();
        let dollar = topic.starts_with('$');
        self.collect(ROOT, &levels, 0, dollar, out);
        // One delivery per session at the maximum granted QoS (§3.3.5 permits).
        out.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        out.dedup_by_key(|e| e.0);
    }

    fn add_subs(&self, n: NodeId, out: &mut Vec<(SessionId, QoS)>) {
        if let Some(node) = self.nodes.get(n as usize) {
            out.extend_from_slice(&node.subs);
        }
    }

    fn collect(
        &self,
        n: NodeId,
        levels: &[&str],
        i: usize,
        dollar: bool,
        out: &mut Vec<(SessionId, QoS)>,
    ) {
        let wild_ok = !(dollar && i == 0);
        if wild_ok && let Some(h) = self.child(n, "#") {
            self.add_subs(h, out);
        }
        let Some(level) = levels.get(i) else {
            self.add_subs(n, out);
            return;
        };
        if let Some(c) = self.child(n, level) {
            self.collect(c, levels, i + 1, dollar, out);
        }
        if wild_ok && let Some(p) = self.child(n, "+") {
            self.collect(p, levels, i + 1, dollar, out);
        }
    }

    /// Stores (or with an empty payload clears) the retained message.
    pub fn set_retained(&mut self, topic: &str, msg: Msg, qos: QoS) {
        let n = self.intern(topic);
        if let Some(node) = self.nodes.get_mut(n as usize) {
            let had = node.retained.is_some();
            if msg.payload.is_empty() {
                node.retained = None;
            } else {
                node.retained = Some((msg, qos));
            }
            match (had, node.retained.is_some()) {
                (false, true) => self.retained += 1,
                (true, false) => self.retained -= 1,
                _ => {}
            }
        }
    }

    /// Retained messages whose topic matches `filter`.
    pub fn retained_matching(&self, filter: &str, out: &mut Vec<(Msg, QoS)>) {
        let levels: Vec<&str> = filter.split('/').collect();
        self.walk_retained(ROOT, &levels, 0, out);
    }

    fn all_below(
        &self,
        n: NodeId,
        include_self: bool,
        root_level: bool,
        out: &mut Vec<(Msg, QoS)>,
    ) {
        let Some(node) = self.nodes.get(n as usize) else {
            return;
        };
        if include_self && let Some(r) = &node.retained {
            out.push(r.clone());
        }
        for (name, &c) in &node.children {
            if root_level && name.starts_with('$') {
                continue;
            }
            self.all_below(c, true, false, out);
        }
    }

    fn walk_retained(&self, n: NodeId, levels: &[&str], i: usize, out: &mut Vec<(Msg, QoS)>) {
        let Some(node) = self.nodes.get(n as usize) else {
            return;
        };
        match levels.get(i) {
            None => {
                if let Some(r) = &node.retained {
                    out.push(r.clone());
                }
            }
            Some(&"#") => self.all_below(n, i > 0, i == 0, out),
            Some(&"+") => {
                for (name, &c) in &node.children {
                    if i == 0 && name.starts_with('$') {
                        continue;
                    }
                    self.walk_retained(c, levels, i + 1, out);
                }
            }
            Some(level) => {
                if let Some(c) = self.child(n, level) {
                    self.walk_retained(c, levels, i + 1, out);
                }
            }
        }
    }
}
