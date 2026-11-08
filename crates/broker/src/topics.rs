//! Topic trie with interned node ids, subscriptions and retained messages.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use urmqtt_mqtt::QoS;

use crate::{Msg, SessionId};

pub type NodeId = u32;

/// The options of one subscription: the MQTT 5.0 Subscription Options byte
/// (§3.8.3.1: maximum QoS in bits 0-1, No Local bit 2, Retain As Published
/// bit 3, Retain Handling bits 4-5). A 3.1.1 subscription is its QoS alone
/// (ADR-273 rule 12), so the trie keeps one byte per subscriber, as it kept
/// the QoS before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubOpts(pub u8);

impl SubOpts {
    /// QoS only, every flag off (what a 3.1.1 subscription means).
    pub const fn qos(q: QoS) -> Self {
        Self(q as u8)
    }

    /// From a stored or received byte; reserved bits and an impossible QoS
    /// or Retain Handling fall back to the QoS bits alone (the store is not
    /// trusted).
    pub fn from_byte(b: u8) -> Self {
        match urmqtt_mqtt::v5::SubscriptionOptions::from_byte(b) {
            Ok(o) => Self(o.to_byte()),
            Err(_) => Self::qos(QoS::from_bits(b & 3).unwrap_or(QoS::AtMostOnce)),
        }
    }

    /// The maximum QoS of deliveries.
    pub fn max_qos(self) -> QoS {
        QoS::from_bits(self.0 & 3).unwrap_or(QoS::AtMostOnce)
    }

    pub const fn no_local(self) -> bool {
        self.0 & 0x04 != 0
    }

    pub const fn retain_as_published(self) -> bool {
        self.0 & 0x08 != 0
    }

    /// 0: retained messages on every subscribe, 1: only for a new
    /// subscription, 2: never.
    pub const fn retain_handling(self) -> u8 {
        (self.0 >> 4) & 3
    }

    /// The same options with another maximum QoS.
    pub const fn with_qos(self, q: QoS) -> Self {
        Self((self.0 & !3) | q as u8)
    }

    /// Two matching subscriptions of one session, delivered once (§3.3.4
    /// lets the server send one copy): the higher QoS, No Local only if
    /// both have it, Retain As Published if either has it.
    pub fn merge(self, o: Self) -> Self {
        let qos = self.max_qos().max(o.max_qos());
        let no_local = self.0 & o.0 & 0x04;
        let rap = (self.0 | o.0) & 0x08;
        Self((self.0 & 0x30) | no_local | rap | qos as u8)
    }
}
const ROOT: NodeId = 0;

#[derive(Default)]
struct Node {
    children: BTreeMap<Box<str>, NodeId>,
    subs: Vec<(SessionId, SubOpts)>,
    retained: Option<(Msg, QoS)>,
    /// Who retained it, on the shard that accepted it (H3: per-device
    /// limit); `None` for replicas and restored messages.
    owner: Option<Box<str>>,
    /// The full filter, once the node is used as a subscription filter:
    /// sessions keep only the node id (PROMPT §7.3).
    path: Option<Box<str>>,
}

impl Node {
    fn unused(&self) -> bool {
        self.children.is_empty() && self.subs.is_empty() && self.retained.is_none()
    }
}

/// Bytes a retained message is charged against `limits.max_retained_bytes`:
/// topic and payload plus a fixed amount for the node and the message.
pub const RETAINED_OVERHEAD: usize = 128;

pub fn retained_cost(topic: &str, payload_len: usize) -> usize {
    topic.len() + payload_len + RETAINED_OVERHEAD
}

pub struct Topics {
    nodes: Vec<Node>,
    /// Ids of removed nodes, reused before the arena grows (H3: nodes of
    /// cleared retained messages and dropped filters do not accumulate).
    free: Vec<NodeId>,
    retained: usize,
    retained_bytes: usize,
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
            free: Vec::new(),
            retained: 0,
            retained_bytes: 0,
        }
    }

    /// Live nodes (the arena minus reusable slots).
    pub fn node_count(&self) -> usize {
        self.nodes.len() - self.free.len()
    }

    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
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
                    let id = match self.free.pop() {
                        Some(id) => id,
                        None => {
                            self.nodes.push(Node::default());
                            (self.nodes.len() - 1) as NodeId
                        }
                    };
                    if let Some(parent) = self.nodes.get_mut(n as usize) {
                        parent.children.insert(level.into(), id);
                    }
                    id
                }
            };
        }
        n
    }

    /// Node for the subscription filter `filter`, which it remembers.
    pub fn intern_filter(&mut self, filter: &str) -> NodeId {
        let n = self.intern(filter);
        if let Some(node) = self.nodes.get_mut(n as usize)
            && node.path.is_none()
        {
            node.path = Some(filter.into());
        }
        n
    }

    /// The filter interned as `n` by [`Topics::intern_filter`].
    pub fn path(&self, n: NodeId) -> Option<&str> {
        self.nodes.get(n as usize)?.path.as_deref()
    }

    pub fn subscribe(&mut self, node: NodeId, s: SessionId, opts: SubOpts) {
        if let Some(n) = self.nodes.get_mut(node as usize) {
            match n.subs.iter_mut().find(|(id, _)| *id == s) {
                Some(e) => e.1 = opts,
                None => n.subs.push((s, opts)),
            }
        }
    }

    pub fn unsubscribe(&mut self, node: NodeId, s: SessionId) {
        let Some(n) = self.nodes.get_mut(node as usize) else {
            return;
        };
        n.subs.retain(|(id, _)| *id != s);
        // The last subscriber gone: the filter's nodes go too, unless
        // something else still lives there (H3).
        if n.subs.is_empty()
            && let Some(path) = n.path.clone()
        {
            self.prune(&path);
        }
    }

    /// The node for `path`, if it exists (never creates one).
    fn find(&self, path: &str) -> Option<NodeId> {
        let mut n = ROOT;
        for level in path.split('/') {
            n = self.child(n, level)?;
        }
        Some(n)
    }

    /// Removes the unused nodes along `path`, deepest first.
    fn prune(&mut self, path: &str) {
        let mut chain: Vec<(NodeId, &str)> = Vec::new();
        let mut n = ROOT;
        for level in path.split('/') {
            let Some(c) = self.child(n, level) else {
                return;
            };
            chain.push((n, level));
            n = c;
        }
        let mut child = n;
        while let Some((parent, level)) = chain.pop() {
            if !self.nodes.get(child as usize).is_some_and(Node::unused) {
                return;
            }
            if let Some(p) = self.nodes.get_mut(parent as usize) {
                p.children.remove(level);
            }
            if let Some(slot) = self.nodes.get_mut(child as usize) {
                *slot = Node::default();
            }
            self.free.push(child);
            child = parent;
        }
    }

    /// Subscribers matching `topic`, one entry per session with the options
    /// of its matching subscriptions merged ([`SubOpts::merge`]).
    pub fn subscribers(&self, topic: &str, out: &mut Vec<(SessionId, SubOpts)>) {
        out.clear();
        let levels: Vec<&str> = topic.split('/').collect();
        let dollar = topic.starts_with('$');
        self.collect(ROOT, &levels, 0, dollar, out);
        // One delivery per session at the maximum granted QoS (§3.3.5 permits).
        dedup_sessions(out);
    }

    fn add_subs(&self, n: NodeId, out: &mut Vec<(SessionId, SubOpts)>) {
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
        out: &mut Vec<(SessionId, SubOpts)>,
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

    /// The retained message at `topic`: its cost and owner.
    pub fn retained_at(&self, topic: &str) -> Option<(usize, Option<&str>)> {
        let node = self.nodes.get(self.find(topic)? as usize)?;
        let (m, _) = node.retained.as_ref()?;
        Some((
            retained_cost(&m.topic, m.payload.len()),
            node.owner.as_deref(),
        ))
    }

    /// The retained message at `topic`.
    pub fn retained_msg(&self, topic: &str) -> Option<&Msg> {
        let node = self.nodes.get(self.find(topic)? as usize)?;
        node.retained.as_ref().map(|(m, _)| m)
    }

    /// Whether the retained message at `topic` is `msg` itself.
    pub fn retained_is(&self, topic: &str, msg: &Msg) -> bool {
        self.find(topic)
            .and_then(|n| self.nodes.get(n as usize))
            .and_then(|n| n.retained.as_ref())
            .is_some_and(|(m, _)| alloc::sync::Arc::ptr_eq(m, msg))
    }

    /// Stores (or with an empty payload clears) the retained message;
    /// returns the previous one's owner (`Some(None)`: there was one, of no
    /// tracked owner). Clearing a topic that holds nothing creates nothing.
    pub fn set_retained(
        &mut self,
        topic: &str,
        msg: Msg,
        qos: QoS,
        owner: Option<&str>,
    ) -> Option<Option<Box<str>>> {
        if msg.payload.is_empty() {
            return self.clear_retained(topic);
        }
        let cost = retained_cost(topic, msg.payload.len());
        let n = self.intern(topic);
        let node = self.nodes.get_mut(n as usize)?;
        let old = node.retained.take().map(|(m, _)| {
            self.retained_bytes -= retained_cost(&m.topic, m.payload.len());
            node.owner.take()
        });
        if old.is_none() {
            self.retained += 1;
        }
        node.retained = Some((msg, qos));
        node.owner = owner.map(Box::from);
        self.retained_bytes += cost;
        old
    }

    /// Clears the retained message at `topic` and prunes the nodes it
    /// leaves unused; returns its owner as [`Topics::set_retained`] does.
    pub fn clear_retained(&mut self, topic: &str) -> Option<Option<Box<str>>> {
        let n = self.find(topic)?;
        let node = self.nodes.get_mut(n as usize)?;
        let (m, _) = node.retained.take()?;
        let owner = node.owner.take();
        self.retained -= 1;
        self.retained_bytes -= retained_cost(&m.topic, m.payload.len());
        self.prune(topic);
        Some(owner)
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

/// Sorts `out` by session and merges the entries of one session into one
/// (the highest QoS first, then [`SubOpts::merge`]).
pub fn dedup_sessions(out: &mut Vec<(SessionId, SubOpts)>) {
    out.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(b.1.max_qos().cmp(&a.1.max_qos())));
    out.dedup_by(|later, kept| {
        if later.0 == kept.0 {
            kept.1 = kept.1.merge(later.1);
            true
        } else {
            false
        }
    });
}

/// Topic name `topic` matches filter `filter` (`+`, `#`). `None` is the
/// empty remainder below a scope (`a/b` against relative filters under
/// `a/b/`), which only `#` matches (§4.7.1.2). The `$` rule does not apply:
/// relative topics never start at the first level.
pub fn filter_matches(filter: &str, topic: Option<&str>) -> bool {
    let Some(topic) = topic else {
        return filter == "#";
    };
    let mut f = filter.split('/');
    let mut t = topic.split('/');
    loop {
        match (f.next(), t.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}
