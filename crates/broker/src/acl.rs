//! Access control (PROMPT §7.3): compiled-in patterns, `{id}` replaced by
//! the session's identity, no database lookups.

/// Placeholder level replaced by the identity.
pub const ID: &str = "{id}";

#[derive(Debug, Clone, Copy)]
pub struct Acl {
    pub device_publish: &'static [&'static str],
    pub device_subscribe: &'static [&'static str],
    pub service_ids: &'static [&'static str],
    pub service_publish: &'static [&'static str],
    pub service_subscribe: &'static [&'static str],
    /// Operator identities (exact ids, O1/O2): the only ones that reach
    /// `$SYS/` (see [`OPERATOR_PUBLISH`] and [`OPERATOR_SUBSCRIBE`]). Their
    /// role needs an authenticated (TLS) identity; see the broker.
    pub operator_ids: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Device,
    Service,
    /// May use the `$SYS/` namespace and nothing else (O1, O2).
    Operator,
    /// A certificate from a bootstrap trust anchor (H1): provisioning only.
    Bootstrap,
}

/// The only topics a bootstrap identity may use, for publishing and
/// subscribing alike (H1, docs/PROVISIONING.md).
pub const BOOTSTRAP_RULES: &[&str] = &["provision/{id}/#"];

/// The reserved control namespace (H1): no identity subscribes there, and
/// publishes to it are handled before and apart from the ACL.
pub const RESERVED: &str = "$urmqtt";

/// `topic` (or a filter) lies in the reserved namespace.
pub fn reserved(topic: &str) -> bool {
    topic.split('/').next() == Some(RESERVED)
}

/// The system namespace (O1, O2): broker statistics, the console and the
/// query topics. Closed to every role but [`Role::Operator`], whatever the
/// configured patterns say.
pub const SYS: &str = "$SYS";

/// `topic` (or a filter) lies in the system namespace.
pub fn sys(topic: &str) -> bool {
    topic.split('/').next() == Some(SYS)
}

/// What an operator may publish: the console's input and the info query.
/// Both are handled by the broker and never routed or retained.
pub const OPERATOR_PUBLISH: &[&str] = &["$SYS/console/in", "$SYS/query/info"];

/// What an operator may subscribe to.
pub const OPERATOR_SUBSCRIBE: &[&str] = &["$SYS/#"];

impl Acl {
    pub fn role(&self, id: &str) -> Role {
        if self.operator_ids.contains(&id) {
            return Role::Operator;
        }
        let service = self.service_ids.iter().any(|p| match p.strip_suffix('*') {
            Some(prefix) => id.starts_with(prefix),
            None => *p == id,
        });
        if service { Role::Service } else { Role::Device }
    }

    fn rules(&self, role: Role, publish: bool) -> &'static [&'static str] {
        match (role, publish) {
            (Role::Device, true) => self.device_publish,
            (Role::Device, false) => self.device_subscribe,
            (Role::Service, true) => self.service_publish,
            (Role::Service, false) => self.service_subscribe,
            (Role::Bootstrap, _) => BOOTSTRAP_RULES,
            (Role::Operator, true) => OPERATOR_PUBLISH,
            (Role::Operator, false) => OPERATOR_SUBSCRIBE,
        }
    }

    /// May `id` publish to topic `topic`? Never in the reserved namespace;
    /// in `$SYS/` only an operator, and only the topics it may publish.
    pub fn may_publish(&self, role: Role, id: &str, topic: &str) -> bool {
        if reserved(topic) || (sys(topic) && role != Role::Operator) {
            return false;
        }
        self.rules(role, true)
            .iter()
            .any(|p| matches_topic(p, id, topic))
    }

    /// May `id` subscribe to `filter`? Every topic the filter can match must
    /// be allowed by one pattern. Never in the reserved namespace, whatever
    /// the configuration says; in `$SYS/` only an operator.
    pub fn may_subscribe(&self, role: Role, id: &str, filter: &str) -> bool {
        if reserved(filter) || (sys(filter) && role != Role::Operator) {
            return false;
        }
        self.rules(role, false)
            .iter()
            .any(|p| covers(p, id, filter))
    }
}

fn level<'a>(pattern_level: &'a str, id: &'a str) -> &'a str {
    if pattern_level == ID {
        id
    } else {
        pattern_level
    }
}

/// Topic name `topic` matches `pattern` (a filter that may contain `{id}`).
pub fn matches_topic(pattern: &str, id: &str, topic: &str) -> bool {
    let mut p = pattern.split('/');
    let mut t = topic.split('/');
    loop {
        match (p.next().map(|l| level(l, id)), t.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// Every topic matched by `filter` is matched by `pattern`.
pub fn covers(pattern: &str, id: &str, filter: &str) -> bool {
    let mut p = pattern.split('/');
    let mut f = filter.split('/');
    loop {
        match (p.next().map(|l| level(l, id)), f.next()) {
            (Some("#"), _) => return true,
            // `+` in the pattern covers any single level except `#`.
            (Some("+"), Some(l)) if l != "#" => {}
            // A literal covers only the same literal.
            (Some(a), Some(b)) if a != "+" && a == b && b != "+" && b != "#" => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACL: Acl = Acl {
        device_publish: &["devices/{id}/#"],
        device_subscribe: &["devices/{id}/cmd/#"],
        service_ids: &["backend", "svc-*"],
        service_publish: &["devices/+/cmd/#"],
        service_subscribe: &["devices/#"],
        operator_ids: &["ops"],
    };

    #[test]
    fn roles() {
        assert_eq!(ACL.role("ops"), Role::Operator);
        assert_eq!(ACL.role("ops2"), Role::Device);
        assert_eq!(ACL.role("backend"), Role::Service);
        assert_eq!(ACL.role("svc-export"), Role::Service);
        assert_eq!(ACL.role("backend2"), Role::Device);
        assert_eq!(ACL.role("d1"), Role::Device);
    }

    #[test]
    fn device_publish_rules() {
        assert!(ACL.may_publish(Role::Device, "d1", "devices/d1/telemetry/t"));
        assert!(ACL.may_publish(Role::Device, "d1", "devices/d1"));
        assert!(!ACL.may_publish(Role::Device, "d1", "devices/d2/telemetry"));
        assert!(!ACL.may_publish(Role::Device, "d1", "fleet/x"));
    }

    #[test]
    fn device_subscribe_rules() {
        assert!(ACL.may_subscribe(Role::Device, "d1", "devices/d1/cmd/#"));
        assert!(ACL.may_subscribe(Role::Device, "d1", "devices/d1/cmd/+/x"));
        assert!(ACL.may_subscribe(Role::Device, "d1", "devices/d1/cmd"));
        assert!(
            !ACL.may_subscribe(Role::Device, "d1", "devices/+/cmd/#"),
            "wildcard over identity"
        );
        assert!(
            !ACL.may_subscribe(Role::Device, "d1", "devices/d1/#"),
            "wider than cmd"
        );
        assert!(!ACL.may_subscribe(Role::Device, "d1", "#"));
        assert!(!ACL.may_subscribe(Role::Device, "d1", "devices/d2/cmd/x"));
    }

    #[test]
    fn service_rules() {
        assert!(ACL.may_subscribe(Role::Service, "backend", "devices/+/telemetry/#"));
        assert!(ACL.may_publish(Role::Service, "backend", "devices/d7/cmd/reboot"));
        assert!(!ACL.may_publish(Role::Service, "backend", "devices/d7/telemetry"));
    }

    /// H1: the reserved namespace is closed to every role, even if the
    /// configuration's patterns would cover it.
    #[test]
    fn reserved_namespace_is_never_allowed() {
        const OPEN: Acl = Acl {
            device_publish: &["#", "$urmqtt/#"],
            device_subscribe: &["#", "$urmqtt/#"],
            service_ids: &["backend"],
            service_publish: &["#", "$urmqtt/#", "+/#"],
            service_subscribe: &["#", "$urmqtt/#"],
            operator_ids: &[],
        };
        for role in [Role::Device, Role::Service, Role::Bootstrap] {
            for t in ["$urmqtt/control", "$urmqtt", "$urmqtt/x/y"] {
                assert!(!OPEN.may_publish(role, "backend", t), "{role:?} {t}");
                assert!(!OPEN.may_subscribe(role, "backend", t), "{role:?} {t}");
            }
            for f in ["$urmqtt/#", "$urmqtt/+"] {
                assert!(!OPEN.may_subscribe(role, "backend", f), "{role:?} {f}");
            }
        }
        assert!(reserved("$urmqtt/control"));
        assert!(!reserved("$urmqttx/control"));
        assert!(!reserved("devices/$urmqtt"));
    }

    /// H1: a bootstrap identity gets `provision/{id}/#` and nothing else,
    /// whatever its id.
    #[test]
    fn bootstrap_role_is_provisioning_only() {
        let b = Role::Bootstrap;
        assert!(ACL.may_publish(b, "d9", "provision/d9/csr"));
        assert!(ACL.may_subscribe(b, "d9", "provision/d9/#"));
        assert!(!ACL.may_publish(b, "d9", "provision/d8/csr"));
        assert!(!ACL.may_subscribe(b, "d9", "provision/+/#"));
        assert!(!ACL.may_publish(b, "d9", "devices/d9/telemetry"));
        assert!(!ACL.may_subscribe(b, "d9", "devices/d9/cmd/#"));
        // A bootstrap certificate named like a service gets no service rights.
        assert!(!ACL.may_publish(b, "backend", "devices/d7/cmd/x"));
    }

    /// O1, O2: `$SYS/` belongs to operators alone. No other role reaches it,
    /// however permissive its patterns; an operator reaches nothing else and
    /// publishes only the two request topics.
    #[test]
    fn sys_namespace_is_for_operators() {
        const OPEN: Acl = Acl {
            device_publish: &["#", "$SYS/#"],
            device_subscribe: &["#", "$SYS/#"],
            service_ids: &["backend"],
            service_publish: &["#", "$SYS/#"],
            service_subscribe: &["#", "$SYS/#"],
            operator_ids: &["ops"],
        };
        for role in [Role::Device, Role::Service, Role::Bootstrap] {
            for t in ["$SYS/console/in", "$SYS/broker/uptime", "$SYS"] {
                assert!(!OPEN.may_publish(role, "x", t), "{role:?} {t}");
                assert!(!OPEN.may_subscribe(role, "x", t), "{role:?} {t}");
            }
            for f in ["$SYS/#", "$SYS/+", "$SYS/broker/#", "$SYS/console/out"] {
                assert!(!OPEN.may_subscribe(role, "x", f), "{role:?} {f}");
            }
        }
        let op = Role::Operator;
        for f in ["$SYS/#", "$SYS/broker/#", "$SYS/console/out", "$SYS/+/x"] {
            assert!(OPEN.may_subscribe(op, "ops", f), "{f}");
        }
        for t in ["$SYS/console/in", "$SYS/query/info"] {
            assert!(OPEN.may_publish(op, "ops", t), "{t}");
        }
        // Not outside `$SYS/`, not elsewhere in it, never the control topic.
        assert!(!OPEN.may_publish(op, "ops", "$SYS/broker/uptime"));
        assert!(!OPEN.may_publish(op, "ops", "$SYS/console/out"));
        assert!(!OPEN.may_publish(op, "ops", "devices/ops/x"));
        assert!(!OPEN.may_subscribe(op, "ops", "#"));
        assert!(!OPEN.may_subscribe(op, "ops", "devices/#"));
        assert!(!OPEN.may_subscribe(op, "ops", "$urmqtt/#"));
        assert!(sys("$SYS/x") && sys("$SYS") && !sys("$SYSx/x") && !sys("a/$SYS"));
    }

    #[test]
    fn cover_edge_cases() {
        assert!(covers("a/+/c", "x", "a/b/c"));
        assert!(covers("a/+/c", "x", "a/+/c"));
        assert!(!covers("a/+/c", "x", "a/#"));
        assert!(!covers("a/b", "x", "a/+"));
        assert!(covers("#", "x", "a/#"));
        assert!(!covers("a/b/c", "x", "a/b"));
    }
}
