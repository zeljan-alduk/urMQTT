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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Device,
    Service,
}

impl Acl {
    pub fn role(&self, id: &str) -> Role {
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
        }
    }

    /// May `id` publish to topic `topic`?
    pub fn may_publish(&self, role: Role, id: &str, topic: &str) -> bool {
        self.rules(role, true)
            .iter()
            .any(|p| matches_topic(p, id, topic))
    }

    /// May `id` subscribe to `filter`? Every topic the filter can match must
    /// be allowed by one pattern.
    pub fn may_subscribe(&self, role: Role, id: &str, filter: &str) -> bool {
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
    };

    #[test]
    fn roles() {
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
