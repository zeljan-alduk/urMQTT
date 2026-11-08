//! Shared subscriptions (MQTT 5.0 §4.8.2; ADR-273 rule 16, ADR-275).
//!
//! `$share/{group}/{filter}`: every message that matches the filter goes to
//! one member of the group. A group is named by (role class, group, filter)
//! and lives on one shard, its **owner**: `first + fnv1a(class, group,
//! filter) % count`. Every message is already offered to every shard
//! (ADR-032), so the owner sees each one exactly once and picks one member,
//! round robin over the members that are online. Members live on their home
//! shards: the owner hands a delivery to the member's shard
//! ([`SharedMsg::Deliver`], the message's `Arc`, no copy), which delivers it
//! like any other with the QoS and options of the member's subscription.
//!
//! The member's shard tells the owner when a member joins (SUBSCRIBE: the
//! SUBACK waits for the owner's answer, [`SharedMsg::Joined`], so a refused
//! join is reported and a message routed after the SUBACK finds the member),
//! leaves (UNSUBSCRIBE, session end), comes online or goes offline. A
//! delivery that finds its member gone is sent back
//! ([`SharedMsg::Bounce`]): the owner forgets the member and, for QoS 1 and 2,
//! picks another one. QoS 1 messages a clean session got and did not
//! acknowledge before it ended go back to the owner too
//! ([`SharedMsg::Redispatch`]), as §4.8.2 asks; QoS 2 ones never do
//! [MQTT-4.8.2-5].
//!
//! A shard holds the groups it owns ([`Owner`]) and, apart, the shared
//! subscriptions of its own sessions (one 8-byte `Sub` each, its path
//! interned in `Broker::share_paths`).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use urmqtt_mqtt::QoS;
use urmqtt_mqtt::v5::ReasonCode;

use crate::topics::{SubOpts, Topics};
use crate::{Broker, ConnId, Msg, NodeId, PersistOp, Role, SessionId, Sub};

/// The prefix of a shared subscription's filter.
pub const SHARE_PREFIX: &str = "$share/";

/// Times one message may be handed on from a member that was gone before
/// it is dropped (counted): bounds the work a churning group costs.
pub const MAX_TRIES: u8 = 4;

/// How long a SUBACK waits for the owners' answers before the joins still
/// open are reported as failed (0x80). The mesh does not lose messages, so
/// this is a bound, not a path that is taken.
pub const SUBACK_WAIT_MS: u64 = 2_000;

/// `$share/{group}/{filter}` split into group and filter; `None` for any
/// other filter, or a malformed share (an empty group or filter, a group
/// with a wildcard: the 5.0 codec refuses those, a 3.1.1 SUBSCRIBE does not).
pub fn parse(filter: &str) -> Option<(&str, &str)> {
    let rest = filter.strip_prefix(SHARE_PREFIX)?;
    let (g, f) = rest.split_once('/')?;
    (!g.is_empty() && !f.is_empty() && !g.contains(['+', '#'])).then_some((g, f))
}

/// The role class a group belongs to: a device can never join a service's
/// group, nor a plaintext client a device's (ADR-273 rule 16).
pub fn class(role: Role) -> u8 {
    match role {
        Role::Device => 0,
        Role::Service => 1,
        Role::Operator => 2,
        Role::Bootstrap => 3,
        Role::Plain => 4,
        Role::Web => 5,
    }
}

fn fnv1a(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for p in parts {
        for &b in *p {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        // A separator no string holds, so ("ab", "c") and ("a", "bc") differ.
        h ^= 0xff;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A group, as messages name it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRef {
    pub class: u8,
    pub group: Box<str>,
    pub filter: Box<str>,
}

/// A message between shards about shared subscriptions. The kernel carries
/// it over the mesh (`CoreMsg::Shared`) and hands it to
/// [`Broker::shared_input`] on the shard it is for; `Deliver` holds the
/// message's `Arc`, so a delivery costs no copy and no allocation.
#[derive(Debug)]
pub enum SharedMsg {
    /// Member's shard → owner: session `sid` joins (or is restored into) the
    /// group; `share` names its subscription on that shard. Answered with
    /// `Joined` (`token` 0: no SUBACK waits for it).
    Join {
        at: Box<GroupRef>,
        sid: u32,
        share: u32,
        online: bool,
        token: u32,
    },
    /// Member's shard → owner: the member left (UNSUBSCRIBE, session end).
    Leave { at: Box<GroupRef>, sid: u32 },
    /// Member's shard → owner: the member's session came online or went
    /// offline (it stays a member: a persistent session).
    Presence {
        at: Box<GroupRef>,
        sid: u32,
        online: bool,
    },
    /// Owner → member's shard: the answer to a `Join` (refused: a limit).
    Joined {
        sid: u32,
        share: u32,
        token: u32,
        ok: bool,
    },
    /// Owner → member's shard: deliver `msg` (published at `qos`, with
    /// `retain`) to that member.
    Deliver {
        msg: Msg,
        group: u32,
        sid: u32,
        share: u32,
        class: u8,
        qos: QoS,
        retain: bool,
        tries: u8,
    },
    /// Member's shard → owner: member `sid` of `group` is not there any more;
    /// its message, if any, goes to another member.
    Bounce {
        msg: Option<Msg>,
        group: u32,
        sid: u32,
        qos: QoS,
        retain: bool,
        tries: u8,
    },
    /// Member's shard → owner: a QoS 1 message a member's session got and
    /// did not acknowledge before it ended, for another member.
    Redispatch {
        at: Box<GroupRef>,
        msg: Msg,
        qos: QoS,
    },
}

#[derive(Debug, Clone, Copy)]
struct Member {
    shard: u16,
    online: bool,
    sid: u32,
    share: u32,
}

struct Group {
    class: u8,
    node: NodeId,
    members: Vec<Member>,
    /// Where the round robin goes on.
    next: usize,
}

/// The groups this shard owns.
#[derive(Default)]
pub(crate) struct Owner {
    groups: BTreeMap<u32, Group>,
    /// (class, group, filter) → group id. Ids are never reused, so a late
    /// `Bounce` never reaches another group.
    index: BTreeMap<(u8, Box<str>, Box<str>), u32>,
    /// The groups' filters; a node's subscribers are group ids.
    trie: Topics,
    next_id: u32,
    members: usize,
}

impl Owner {
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }
}

/// A SUBACK that waits for owners on other shards.
pub(crate) struct Suback {
    token: u32,
    conn: ConnId,
    sid: SessionId,
    packet_id: u16,
    since_ms: u64,
    /// The reason codes; the waiting ones are filled in as answers come.
    codes: Vec<u8>,
    /// (index in `codes`, share, granted QoS) of the joins still open.
    waiting: Vec<(usize, u32, u8)>,
    /// The other granted filters, whose retained messages follow the SUBACK.
    retained: Vec<(Box<str>, SubOpts, bool)>,
}

/// Where the shards are: this one, the first, how many (ADR-275).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Shards {
    pub me: u16,
    pub first: u16,
    pub count: u16,
}

impl Default for Shards {
    fn default() -> Self {
        Self {
            me: 0,
            first: 0,
            count: 1,
        }
    }
}

impl Shards {
    pub fn owner(&self, class: u8, group: &str, filter: &str) -> u16 {
        let h = fnv1a(&[&[class], group.as_bytes(), filter.as_bytes()]);
        let n = u64::from(self.count.max(1));
        self.first + (h % n) as u16
    }
}

/// What a granted join of a SUBSCRIBE looks like before the SUBACK.
pub(crate) enum JoinState {
    /// The owner is this shard: answered.
    Done(bool),
    /// Sent to the owner; the SUBACK waits for it.
    Sent,
}

impl Broker {
    /// Names this shard among the broker's shards (ADR-275): `me`, the
    /// first shard's number and how many there are. Owners of shared groups
    /// are chosen among them; one shard (the default) owns every group.
    pub fn set_shards(&mut self, me: u16, first: u16, count: u16) {
        self.shards = Shards {
            me,
            first,
            count: count.max(1),
        };
    }

    /// Takes the messages for other shards since the last call: (shard,
    /// message), in order per shard.
    pub fn drain_shared(&mut self) -> alloc::vec::Drain<'_, (u16, SharedMsg)> {
        self.shared_out.drain(..)
    }

    fn shared_to(&mut self, to: u16, m: SharedMsg) {
        if to == self.shards.me {
            let me = self.shards.me;
            self.shared_handle(me, m);
        } else {
            self.shared_out.push((to, m));
        }
    }

    /// A message from shard `from` (from [`Broker::drain_shared`] there).
    pub fn shared_input(&mut self, from: u16, m: SharedMsg, now_ms: u64) {
        self.tick_clock(now_ms);
        self.shared_handle(from, m);
    }

    fn shared_handle(&mut self, from: u16, m: SharedMsg) {
        match m {
            SharedMsg::Join {
                at,
                sid,
                share,
                online,
                token,
            } => {
                let ok = self.owner_join(&at, from, sid, share, online);
                self.shared_to(
                    from,
                    SharedMsg::Joined {
                        sid,
                        share,
                        token,
                        ok,
                    },
                );
            }
            SharedMsg::Leave { at, sid } => {
                if let Some(gid) = self.group_id(&at) {
                    self.owner_remove(gid, from, sid);
                }
            }
            SharedMsg::Presence { at, sid, online } => {
                if let Some(g) = self
                    .group_id(&at)
                    .and_then(|gid| self.owner.groups.get_mut(&gid))
                    && let Some(m) = g
                        .members
                        .iter_mut()
                        .find(|m| m.shard == from && m.sid == sid)
                {
                    m.online = online;
                }
            }
            SharedMsg::Joined {
                sid,
                share,
                token,
                ok,
            } => self.member_joined(sid, share, token, ok),
            SharedMsg::Deliver {
                msg,
                group,
                sid,
                share,
                class,
                qos,
                retain,
                tries,
            } => self.member_deliver(from, group, sid, share, class, &msg, qos, retain, tries),
            SharedMsg::Bounce {
                msg,
                group,
                sid,
                qos,
                retain,
                tries,
            } => {
                self.owner_remove(group, from, sid);
                match msg {
                    Some(msg) if tries <= MAX_TRIES => {
                        self.stats.shared_redispatched += 1;
                        self.dispatch(group, &msg, qos, retain, tries);
                    }
                    Some(_) => self.stats.shared_dropped += 1,
                    None => {}
                }
            }
            SharedMsg::Redispatch { at, msg, qos } => match self.group_id(&at) {
                Some(gid) => {
                    self.stats.shared_redispatched += 1;
                    self.dispatch(gid, &msg, qos, false, 0);
                }
                None => self.stats.shared_dropped += 1,
            },
        }
    }

    // ---- owner side ----------------------------------------------------------

    fn group_id(&self, at: &GroupRef) -> Option<u32> {
        // The index is keyed by owned strings; a lookup builds the key once.
        self.owner
            .index
            .get(&(at.class, at.group.clone(), at.filter.clone()))
            .copied()
    }

    /// Adds (or updates) a member; false when a limit refuses it.
    fn owner_join(
        &mut self,
        at: &GroupRef,
        shard: u16,
        sid: u32,
        share: u32,
        online: bool,
    ) -> bool {
        let max_groups = self.cfg.mqtt5.max_shared_groups as usize;
        let max_members = self.cfg.mqtt5.max_shared_group_members as usize;
        let gid = match self.group_id(at) {
            Some(gid) => gid,
            None => {
                if self.owner.groups.len() >= max_groups {
                    self.stats.shared_refused += 1;
                    return false;
                }
                let gid = self.owner.next_id;
                self.owner.next_id = self.owner.next_id.wrapping_add(1);
                let node = self.owner.trie.intern_filter(&at.filter);
                self.owner.trie.subscribe(node, gid, SubOpts::default());
                self.owner.groups.insert(
                    gid,
                    Group {
                        class: at.class,
                        node,
                        members: Vec::new(),
                        next: 0,
                    },
                );
                self.owner
                    .index
                    .insert((at.class, at.group.clone(), at.filter.clone()), gid);
                gid
            }
        };
        let Some(g) = self.owner.groups.get_mut(&gid) else {
            return false;
        };
        if let Some(m) = g
            .members
            .iter_mut()
            .find(|m| m.shard == shard && m.sid == sid)
        {
            m.share = share;
            m.online = online;
            return true;
        }
        if g.members.len() >= max_members {
            self.stats.shared_refused += 1;
            if g.members.is_empty() {
                self.owner_drop_group(gid);
            }
            return false;
        }
        g.members.push(Member {
            shard,
            online,
            sid,
            share,
        });
        self.owner.members += 1;
        true
    }

    fn owner_remove(&mut self, gid: u32, shard: u16, sid: u32) {
        let Some(g) = self.owner.groups.get_mut(&gid) else {
            return;
        };
        if let Some(i) = g
            .members
            .iter()
            .position(|m| m.shard == shard && m.sid == sid)
        {
            g.members.remove(i);
            self.owner.members = self.owner.members.saturating_sub(1);
            if g.next > i {
                g.next -= 1;
            }
        }
        if g.members.is_empty() {
            self.owner_drop_group(gid);
        }
    }

    fn owner_drop_group(&mut self, gid: u32) {
        let Some(g) = self.owner.groups.remove(&gid) else {
            return;
        };
        self.owner.trie.unsubscribe(g.node, gid);
        self.owner.index.retain(|_, id| *id != gid);
    }

    /// The groups this shard owns whose filter matches `msg` get it, one
    /// member each. Free while the shard owns no group.
    pub(crate) fn shared_route(&mut self, msg: &Msg, qos: QoS, retain: bool) {
        if self.owner.is_empty() {
            return;
        }
        let mut gids = Vec::new();
        self.owner.trie.subscribers(&msg.topic, &mut gids);
        for (gid, _) in gids {
            self.dispatch(gid, msg, qos, retain, 0);
        }
    }

    /// Hands `msg` to the next member of `gid` that is online; with none
    /// online, a QoS 1 or 2 message goes to the next (persistent, offline)
    /// member in turn and is queued there, a QoS 0 message is dropped.
    fn dispatch(&mut self, gid: u32, msg: &Msg, qos: QoS, retain: bool, tries: u8) {
        let me = self.shards.me;
        let Some(g) = self.owner.groups.get_mut(&gid) else {
            self.stats.shared_dropped += 1;
            return;
        };
        let n = g.members.len();
        let online = (0..n)
            .map(|k| (g.next + k) % n.max(1))
            .find(|&i| g.members.get(i).is_some_and(|m| m.online));
        let pick = match online {
            Some(i) => Some(i),
            None if qos != QoS::AtMostOnce && n > 0 => Some(g.next % n),
            None => None,
        };
        let Some((i, m)) = pick.and_then(|i| Some((i, *g.members.get(i)?))) else {
            self.stats.shared_dropped += 1;
            return;
        };
        g.next = (i + 1) % n;
        let class = g.class;
        let d = SharedMsg::Deliver {
            msg: msg.clone(),
            group: gid,
            sid: m.sid,
            share: m.share,
            class,
            qos,
            retain,
            tries,
        };
        if m.shard == me {
            self.shared_handle(me, d);
        } else {
            self.shared_out.push((m.shard, d));
        }
    }

    // ---- member side ---------------------------------------------------------

    /// The shared subscription `share` (its node + 1) of `sid`, if the session
    /// is of role class `class` and has it.
    fn shared_sub(&self, sid: SessionId, share: u32, class_: u8) -> Option<Sub> {
        let s = self.sessions.get(sid)?;
        if class(s.role) != class_ {
            return None;
        }
        s.subs
            .as_slice()
            .iter()
            .find(|x| x.shared && x.node.wrapping_add(1) == share)
            .copied()
    }

    #[allow(clippy::too_many_arguments)]
    fn member_deliver(
        &mut self,
        owner: u16,
        gid: u32,
        sid: SessionId,
        share: u32,
        class_: u8,
        msg: &Msg,
        qos: QoS,
        retain: bool,
        tries: u8,
    ) {
        match self.shared_sub(sid, share, class_) {
            Some(x) => {
                self.stats.shared_delivered += 1;
                let q = qos.min(x.opts.max_qos());
                let r = retain && x.opts.retain_as_published();
                self.deliver_tagged(sid, msg, q, r, share);
            }
            None => {
                // Gone (left, ended, or another session in its slot): the
                // owner forgets it; a QoS 1 or 2 message goes elsewhere.
                let again = qos != QoS::AtMostOnce;
                if !again {
                    self.stats.shared_dropped += 1;
                }
                self.shared_to(
                    owner,
                    SharedMsg::Bounce {
                        msg: again.then(|| msg.clone()),
                        group: gid,
                        sid,
                        qos,
                        retain,
                        tries: tries.saturating_add(1),
                    },
                );
            }
        }
    }

    /// The group a shared subscription of `role` names, and its owner.
    pub(crate) fn group_of(&self, role: Role, share_node: NodeId) -> Option<(u16, GroupRef)> {
        let path = self.share_paths.path(share_node)?;
        let (g, f) = parse(path)?;
        let c = class(role);
        Some((
            self.shards.owner(c, g, f),
            GroupRef {
                class: c,
                group: g.into(),
                filter: f.into(),
            },
        ))
    }

    /// Joins the group of `sid`'s shared subscription on `share_node`.
    pub(crate) fn join(
        &mut self,
        sid: SessionId,
        share_node: NodeId,
        online: bool,
        token: u32,
    ) -> JoinState {
        let Some(role) = self.sessions.get(sid).map(|s| s.role) else {
            return JoinState::Done(false);
        };
        let Some((owner, at)) = self.group_of(role, share_node) else {
            return JoinState::Done(false);
        };
        let share = share_node.wrapping_add(1);
        if owner == self.shards.me {
            return JoinState::Done(self.owner_join(&at, owner, sid, share, online));
        }
        self.shared_out.push((
            owner,
            SharedMsg::Join {
                at: Box::new(at),
                sid,
                share,
                online,
                token,
            },
        ));
        JoinState::Sent
    }

    /// Tells the owners of `sid`'s shared subscriptions it came online or
    /// went offline.
    pub(crate) fn shared_presence(&mut self, sid: SessionId, online: bool) {
        let Some((role, nodes)) = self.sessions.get(sid).map(|s| {
            let n: Vec<NodeId> = s
                .subs
                .as_slice()
                .iter()
                .filter(|x| x.shared)
                .map(|x| x.node)
                .collect();
            (s.role, n)
        }) else {
            return;
        };
        for node in nodes {
            if let Some((owner, at)) = self.group_of(role, node) {
                self.shared_to(
                    owner,
                    SharedMsg::Presence {
                        at: Box::new(at),
                        sid,
                        online,
                    },
                );
            }
        }
    }

    /// `sid` leaves the group of its shared subscription on `node`.
    pub(crate) fn leave(&mut self, sid: SessionId, role: Role, node: NodeId) {
        if let Some((owner, at)) = self.group_of(role, node) {
            self.shared_to(
                owner,
                SharedMsg::Leave {
                    at: Box::new(at),
                    sid,
                },
            );
        }
    }

    /// The answer to a join: a refused one undoes the subscription; a
    /// SUBACK that waited for it may go out.
    fn member_joined(&mut self, sid: SessionId, share: u32, token: u32, ok: bool) {
        if !ok {
            self.undo_shared(sid, share);
        }
        if token == 0 {
            return;
        }
        let Some(i) = self.subacks.iter().position(|s| s.token == token) else {
            return;
        };
        // 3.1.1 knows only 0x80 for a refusal.
        let refused = match self.subacks.get(i).map(|s| s.conn) {
            Some(c) if self.is_v5(c) => ReasonCode::QuotaExceeded as u8,
            _ => urmqtt_mqtt::SUBACK_FAILURE,
        };
        let Some(s) = self.subacks.get_mut(i) else {
            return;
        };
        if let Some(w) = s.waiting.iter().position(|w| w.1 == share) {
            let (at, _, granted) = s.waiting.swap_remove(w);
            if let Some(code) = s.codes.get_mut(at) {
                *code = if ok { granted } else { refused };
            }
            if ok && s.sid == sid {
                self.persist_shared(sid, share);
            }
        }
        if self.subacks.get(i).is_some_and(|s| s.waiting.is_empty()) {
            let s = self.subacks.swap_remove(i);
            self.finish_suback(s);
        }
    }

    /// Removes the shared subscription `share` of `sid` (a refused join).
    fn undo_shared(&mut self, sid: SessionId, share: u32) {
        let Some(path) = self
            .share_paths
            .path(share.wrapping_sub(1))
            .map(alloc::string::String::from)
        else {
            return;
        };
        if self.sessions.get(sid).is_some_and(|s| {
            s.subs
                .as_slice()
                .iter()
                .any(|x| x.shared && x.node.wrapping_add(1) == share)
        }) && self.remove_sub(sid, &path)
        {
            let stored = self
                .sessions
                .get(sid)
                .filter(|s| s.persisted)
                .map(|s| s.client_id.clone());
            if let Some(client_id) = stored {
                self.emit(PersistOp::Unsubscribe {
                    client_id,
                    filter: path.into(),
                });
            }
        }
    }

    /// Records a granted shared subscription of a persistent session.
    pub(crate) fn persist_shared(&mut self, sid: SessionId, share: u32) {
        let node = share.wrapping_sub(1);
        let Some(s) = self.sessions.get(sid).filter(|s| s.persisted) else {
            return;
        };
        let Some(x) = s
            .subs
            .as_slice()
            .iter()
            .find(|x| x.shared && x.node == node)
            .copied()
        else {
            return;
        };
        let Some(filter) = self.share_paths.path(node).map(Box::<str>::from) else {
            return;
        };
        let client_id = s.client_id.clone();
        let sub_id = self.sub_id_of(sid, &x);
        self.emit(PersistOp::Subscribe {
            client_id,
            filter,
            qos: x.opts.max_qos(),
            options: x.opts.0,
            sub_id,
        });
    }

    /// Parks a SUBACK until the owners answered; the connection's input
    /// waits with it, so its later packets keep their order.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn park_suback(
        &mut self,
        token: u32,
        c: ConnId,
        sid: SessionId,
        packet_id: u16,
        codes: Vec<u8>,
        waiting: Vec<(usize, u32, u8)>,
        retained: Vec<(Box<str>, SubOpts, bool)>,
    ) {
        if let Some(k) = self.conns.get_mut(c) {
            k.flow |= crate::flow::WAIT_SUBACK;
        }
        let since_ms = self.now_ms;
        self.subacks.push(Suback {
            token,
            conn: c,
            sid,
            packet_id,
            since_ms,
            codes,
            waiting,
            retained,
        });
    }

    pub(crate) fn next_token(&mut self) -> u32 {
        self.next_token = self.next_token.wrapping_add(1).max(1);
        self.next_token
    }

    /// Sends a SUBACK that waited, then the retained messages of its other
    /// filters, and lets the connection's input go on.
    fn finish_suback(&mut self, s: Suback) {
        let c = s.conn;
        let attached = self
            .conns
            .get(c)
            .is_some_and(|k| k.session == Some(s.sid) && k.close.is_none());
        if let Some(k) = self.conns.get_mut(c) {
            k.flow &= !crate::flow::WAIT_SUBACK;
        }
        if !attached {
            return;
        }
        self.send_suback(c, s.packet_id, &s.codes);
        let list: Vec<(&str, SubOpts, bool)> =
            s.retained.iter().map(|(f, o, n)| (&**f, *o, *n)).collect();
        self.replay_retained(s.sid, &list);
        let now = self.now_ms;
        if self.conns.get(c).is_some_and(|k| k.flow == 0) {
            self.parse(c, now, usize::MAX);
        }
    }

    /// SUBACKs that waited too long ([`SUBACK_WAIT_MS`]): the joins still
    /// open are reported failed. Called by [`Broker::tick`].
    pub(crate) fn expire_subacks(&mut self) {
        let now = self.now_ms;
        while let Some(i) = self
            .subacks
            .iter()
            .position(|s| now.saturating_sub(s.since_ms) >= SUBACK_WAIT_MS)
        {
            let mut s = self.subacks.swap_remove(i);
            for (at, share, _) in core::mem::take(&mut s.waiting) {
                if let Some(code) = s.codes.get_mut(at) {
                    *code = ReasonCode::UnspecifiedError as u8;
                }
                self.undo_shared(s.sid, share);
            }
            self.finish_suback(s);
        }
    }

    /// Forgets the parked SUBACKs of `c` (it closed): the joins stay, as
    /// any subscription a client made before it went away.
    pub(crate) fn forget_subacks(&mut self, c: ConnId) {
        self.subacks.retain(|s| s.conn != c);
    }

    /// A session ends: it leaves its groups, then the QoS 1 messages it got
    /// through them and did not acknowledge, and those still queued for it,
    /// go back to their owners for another member (§4.8.2: SHOULD; QoS 2
    /// messages in flight never, [MQTT-4.8.2-5]).
    pub(crate) fn shared_session_end(
        &mut self,
        sid: SessionId,
        role: Role,
        subs: &[Sub],
        again: Vec<(Msg, QoS, u32)>,
    ) {
        let shared: Vec<NodeId> = subs.iter().filter(|x| x.shared).map(|x| x.node).collect();
        if shared.is_empty() {
            return;
        }
        let mut refs = Vec::new();
        for &node in &shared {
            refs.push((node, self.group_of(role, node)));
        }
        for &node in &shared {
            self.leave(sid, role, node);
        }
        for (msg, qos, share) in again {
            let target = refs
                .iter()
                .find(|(n, _)| n.wrapping_add(1) == share)
                .and_then(|(_, r)| r.clone());
            if let Some((owner, at)) = target {
                self.shared_to(
                    owner,
                    SharedMsg::Redispatch {
                        at: Box::new(at),
                        msg,
                        qos,
                    },
                );
            }
        }
        for node in shared {
            self.share_paths.unsubscribe(node, sid);
        }
    }

    /// Groups this shard owns and their members (for `$SYS`).
    pub fn shared_owned(&self) -> (usize, usize) {
        (self.owner.groups.len(), self.owner.members)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_filters_parse_and_owners_spread() {
        assert_eq!(parse("$share/g/a/b"), Some(("g", "a/b")));
        assert_eq!(parse("$share/g/#"), Some(("g", "#")));
        assert_eq!(parse("$share//a"), None);
        assert_eq!(parse("$share/g/"), None);
        assert_eq!(parse("$share/g+/a"), None);
        assert_eq!(parse("$share/g"), None);
        assert_eq!(parse("a/b"), None);
        let s = Shards {
            me: 1,
            first: 1,
            count: 3,
        };
        let owners: alloc::collections::BTreeSet<u16> = (0..64)
            .map(|i| s.owner(0, &alloc::format!("g{i}"), "t"))
            .collect();
        assert_eq!(owners.into_iter().collect::<Vec<_>>(), [1, 2, 3]);
        // The class is part of the name.
        assert_ne!(fnv1a(&[&[0], b"g", b"t"]), fnv1a(&[&[1], b"g", b"t"]));
        assert_ne!(fnv1a(&[b"ab", b"c"]), fnv1a(&[b"a", b"bc"]));
    }
}
