//! Who a plaintext CONNECT is (P1, ADR-229, ADR-230), in the three modes of
//! `plaintext.auth`:
//!
//! - **password**: the MQTT user name picks an account and the password must
//!   match its salted, iterated hash. The user name is the identity. Whatever
//!   the reason of a refusal (no credentials, unknown user, wrong password) the
//!   client is told the same thing, and exactly one hash is computed on every
//!   path, so neither the answer nor the time says whether a user exists.
//! - **anonymous**: every client is the configured identity; credentials the
//!   client sends are ignored.
//! - **ip**: the source address decides, by the longest matching network of
//!   `ip_identities`; credentials are ignored.
//!
//! No mode can return an identity that is a service, operator or control
//! identity: the configuration check refuses such names, and the broker gives
//! every plaintext session the plaintext role whatever its name is.

use alloc::vec::Vec;

use urmqtt_cfg::net::Cidr;
use urmqtt_cfg::passwd::PasswordHash;
use urmqtt_config::{PlainAuth, Plaintext};

/// Why a login was refused (for the log and the counters; the client only
/// learns the CONNACK code).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Password mode and no user name or no password in the CONNECT.
    NoCredentials,
    UnknownUser,
    WrongPassword,
    /// Per-network mode and the source is in no network of the list.
    NoNetwork,
}

impl Rejection {
    pub const fn text(self) -> &'static str {
        match self {
            Self::NoCredentials => "no user name or password",
            Self::UnknownUser => "unknown user",
            Self::WrongPassword => "wrong password",
            Self::NoNetwork => "source address in no configured network",
        }
    }
}

/// The outcome of [`Authenticator::authenticate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// The identity the session gets.
    Accept(&'a str),
    Reject(Rejection),
}

impl Verdict<'_> {
    /// The CONNACK return code for a refusal: 4 (bad user name or password) in
    /// password mode, 5 (not authorized) when the address is no one's.
    pub const fn connack_code(&self) -> Option<u8> {
        match self {
            Self::Accept(_) => None,
            Self::Reject(Rejection::NoNetwork) => Some(5),
            Self::Reject(_) => Some(4),
        }
    }
}

/// Runs a password hash of `iterations` over fixed data: for timing a check
/// at boot (the kernel sizes the watchdog's handshake budget and its login
/// admission rate from it).
pub fn probe(iterations: u32) -> [u8; 32] {
    urmqtt_cfg::passwd::pbkdf2_hmac_sha256(b"urmqtt-probe", &[0x5a; 16], iterations)
}

pub struct Authenticator<'a> {
    mode: PlainAuth,
    users: Vec<(&'a str, PasswordHash)>,
    anonymous: &'a str,
    networks: Vec<(Cidr, &'a str)>,
    /// What a login for an unknown user is checked against.
    decoy: PasswordHash,
}

impl<'a> Authenticator<'a> {
    /// From the configuration. An account whose hash does not parse (the
    /// configuration check refused it already) is left out: it can never log in.
    pub fn new(p: &'a Plaintext) -> Self {
        let users: Vec<(&str, PasswordHash)> = p
            .users
            .iter()
            .filter_map(|u| PasswordHash::parse(u.hash).ok().map(|h| (u.id, h)))
            .collect();
        // The decoy costs as much as the dearest real hash.
        let iterations = users
            .iter()
            .map(|(_, h)| h.iterations())
            .max()
            .unwrap_or(urmqtt_cfg::passwd::DEFAULT_ITERATIONS);
        Self {
            mode: p.auth,
            users,
            anonymous: p.anonymous_identity,
            networks: p.ip_identities.iter().map(|n| (n.net, n.id)).collect(),
            decoy: PasswordHash::decoy(iterations),
        }
    }

    pub fn mode(&self) -> PlainAuth {
        self.mode
    }

    /// The most iterations of any account's hash (0 outside password mode):
    /// what the watchdog budget and the admission rate are sized for.
    pub fn max_iterations(&self) -> u32 {
        if self.mode == PlainAuth::Password {
            self.decoy.iterations()
        } else {
            0
        }
    }

    pub fn accounts(&self) -> usize {
        self.users.len()
    }

    /// Decides a CONNECT from `src` with the credentials it carried.
    pub fn authenticate(
        &self,
        src: [u8; 4],
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Verdict<'a> {
        match self.mode {
            PlainAuth::Anonymous => Verdict::Accept(self.anonymous),
            PlainAuth::Ip => {
                let ip = u32::from_be_bytes(src);
                self.networks
                    .iter()
                    .filter(|(n, _)| n.contains(ip))
                    .max_by_key(|(n, _)| n.prefix)
                    .map_or(Verdict::Reject(Rejection::NoNetwork), |(_, id)| {
                        Verdict::Accept(id)
                    })
            }
            PlainAuth::Password => self.password(username, password),
        }
    }

    fn password(&self, username: Option<&str>, password: Option<&[u8]>) -> Verdict<'a> {
        let account = username.and_then(|u| self.users.iter().find(|(id, _)| *id == u));
        // One hash on every path.
        let (hash, ok_identity) = match account {
            Some((id, h)) => (h, Some(*id)),
            None => (&self.decoy, None),
        };
        let matched = hash.verify(password.unwrap_or(&[]));
        match (ok_identity, password, matched) {
            (Some(id), Some(_), true) => Verdict::Accept(id),
            (Some(_), Some(_), false) => Verdict::Reject(Rejection::WrongPassword),
            (Some(_), None, _) => Verdict::Reject(Rejection::NoCredentials),
            (None, _, _) if username.is_none() || password.is_none() => {
                Verdict::Reject(Rejection::NoCredentials)
            }
            (None, _, _) => Verdict::Reject(Rejection::UnknownUser),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use urmqtt_cfg::passwd;
    use urmqtt_config::{PlainNetwork, PlainUser};

    /// A configuration with leaked slices (the kernel's are `'static` too).
    fn config(
        auth: PlainAuth,
        users: &[(&str, &str, u32)],
        nets: &[(&str, &str)],
        anon: &str,
    ) -> Plaintext {
        let users: Vec<PlainUser> = users
            .iter()
            .map(|(id, pw, it)| PlainUser {
                id: Box::leak((*id).to_owned().into_boxed_str()),
                hash: Box::leak(
                    passwd::encode(pw.as_bytes(), b"0123456789abcdef", *it)
                        .unwrap()
                        .into_boxed_str(),
                ),
            })
            .collect();
        let nets: Vec<PlainNetwork> = nets
            .iter()
            .map(|(n, id)| PlainNetwork {
                net: Cidr::parse(n).unwrap(),
                id: Box::leak((*id).to_owned().into_boxed_str()),
            })
            .collect();
        let mut p = base();
        p.auth = auth;
        p.users = Box::leak(users.into_boxed_slice());
        p.ip_identities = Box::leak(nets.into_boxed_slice());
        p.anonymous_identity = Box::leak(anon.to_owned().into_boxed_str());
        p
    }

    fn base() -> Plaintext {
        Plaintext {
            enabled: true,
            port: 1883,
            allow_from: &[],
            allow_from_anywhere: true,
            auth: PlainAuth::Password,
            anonymous_identity: "lan",
            users: &[],
            ip_identities: &[],
            max_connections: 100,
            max_connections_per_ip: 8,
            max_packet_size: 1024,
            publish_rate_per_device: urmqtt_config::Rate {
                tokens: 5,
                per_ms: 1000,
            },
            max_failed_auths_per_ip: 5,
            lockout_s: 300,
            acl_publish: &[],
            acl_subscribe: &[],
            retain: false,
        }
    }

    const SRC: [u8; 4] = [10, 0, 0, 7];

    #[test]
    fn password_mode_accepts_the_right_password_for_the_right_user() {
        let p = config(
            PlainAuth::Password,
            &[("sensor-1", "alpha", 1000), ("sensor-2", "beta", 1000)],
            &[],
            "lan",
        );
        let a = Authenticator::new(&p);
        assert_eq!(a.accounts(), 2);
        assert_eq!(
            a.authenticate(SRC, Some("sensor-1"), Some(b"alpha")),
            Verdict::Accept("sensor-1")
        );
        assert_eq!(
            a.authenticate(SRC, Some("sensor-2"), Some(b"beta")),
            Verdict::Accept("sensor-2")
        );
        // The wrong user for a password, or the wrong password for a user.
        assert_eq!(
            a.authenticate(SRC, Some("sensor-1"), Some(b"beta")),
            Verdict::Reject(Rejection::WrongPassword)
        );
        assert_eq!(
            a.authenticate(SRC, Some("sensor-2"), Some(b"alpha")),
            Verdict::Reject(Rejection::WrongPassword)
        );
        assert_eq!(
            a.authenticate(SRC, Some("sensor-1"), Some(b"Alpha")),
            Verdict::Reject(Rejection::WrongPassword)
        );
        assert_eq!(
            a.authenticate(SRC, Some("sensor-1"), Some(b"")),
            Verdict::Reject(Rejection::WrongPassword)
        );
    }

    #[test]
    fn every_refusal_is_a_bad_login_with_one_code() {
        let p = config(PlainAuth::Password, &[("a", "pw", 1000)], &[], "lan");
        let a = Authenticator::new(&p);
        for (user, pw, why) in [
            (Some("a"), Some(&b"nope"[..]), Rejection::WrongPassword),
            (Some("ghost"), Some(&b"pw"[..]), Rejection::UnknownUser),
            (Some("A"), Some(&b"pw"[..]), Rejection::UnknownUser),
            (Some("a "), Some(&b"pw"[..]), Rejection::UnknownUser),
            (Some(""), Some(&b"pw"[..]), Rejection::UnknownUser),
            (None, Some(&b"pw"[..]), Rejection::NoCredentials),
            (Some("a"), None, Rejection::NoCredentials),
            (None, None, Rejection::NoCredentials),
            (Some("ghost"), None, Rejection::NoCredentials),
        ] {
            let v = a.authenticate(SRC, user, pw);
            assert_eq!(v, Verdict::Reject(why), "{user:?}");
            assert_eq!(v.connack_code(), Some(4));
        }
        assert_eq!(
            a.authenticate(SRC, Some("a"), Some(b"pw")).connack_code(),
            None
        );
    }

    #[test]
    fn the_source_address_does_not_matter_for_a_password() {
        let p = config(
            PlainAuth::Password,
            &[("a", "pw", 1000)],
            &[("10.0.0.0/8", "net")],
            "lan",
        );
        let a = Authenticator::new(&p);
        for src in [[10, 0, 0, 1], [192, 168, 1, 1], [8, 8, 8, 8]] {
            assert_eq!(
                a.authenticate(src, Some("a"), Some(b"pw")),
                Verdict::Accept("a")
            );
        }
    }

    #[test]
    fn anonymous_mode_gives_everyone_the_one_identity() {
        let p = config(PlainAuth::Anonymous, &[], &[], "house");
        let a = Authenticator::new(&p);
        assert_eq!(a.authenticate(SRC, None, None), Verdict::Accept("house"));
        assert_eq!(
            a.authenticate(SRC, Some("x"), Some(b"y")),
            Verdict::Accept("house")
        );
        assert_eq!(
            a.authenticate([8, 8, 8, 8], None, None),
            Verdict::Accept("house")
        );
        assert_eq!(a.max_iterations(), 0, "no hash is ever computed");
    }

    #[test]
    fn ip_mode_takes_the_longest_matching_network() {
        let p = config(
            PlainAuth::Ip,
            &[],
            &[
                ("10.0.0.0/8", "wide"),
                ("10.1.0.0/16", "plc"),
                ("10.1.2.0/24", "gate"),
                ("10.1.2.3/32", "pump"),
            ],
            "lan",
        );
        let a = Authenticator::new(&p);
        for (src, want) in [
            ([10, 9, 9, 9], "wide"),
            ([10, 1, 9, 9], "plc"),
            ([10, 1, 2, 9], "gate"),
            ([10, 1, 2, 3], "pump"),
            ([10, 1, 2, 4], "gate"),
            ([10, 0, 255, 255], "wide"),
        ] {
            assert_eq!(
                a.authenticate(src, None, None),
                Verdict::Accept(want),
                "{src:?}"
            );
        }
        // No network: refused as not authorised, whatever the client sends.
        let v = a.authenticate([11, 0, 0, 1], Some("u"), Some(b"p"));
        assert_eq!(v, Verdict::Reject(Rejection::NoNetwork));
        assert_eq!(v.connack_code(), Some(5));
        // Credentials are ignored.
        assert_eq!(
            a.authenticate([10, 1, 2, 3], Some("x"), Some(b"y")),
            Verdict::Accept("pump")
        );
    }

    #[test]
    fn the_work_does_not_depend_on_whether_the_user_exists() {
        // Same iteration count for a decoy as for the dearest account.
        let p = config(
            PlainAuth::Password,
            &[("cheap", "a", 1000), ("dear", "b", 4000)],
            &[],
            "lan",
        );
        let a = Authenticator::new(&p);
        assert_eq!(a.max_iterations(), 4000);
        assert_eq!(a.decoy.iterations(), 4000);
        // And with no account at all the default.
        let none = config(PlainAuth::Password, &[], &[], "lan");
        let a = Authenticator::new(&none);
        assert_eq!(a.max_iterations(), passwd::DEFAULT_ITERATIONS);
        assert_eq!(
            a.authenticate(SRC, Some("any"), Some(b"thing")),
            Verdict::Reject(Rejection::UnknownUser)
        );
    }

    #[test]
    fn an_unparsable_hash_never_logs_in() {
        let mut p = config(PlainAuth::Password, &[("ok", "pw", 1000)], &[], "lan");
        let bad = [
            p.users[0],
            PlainUser {
                id: "broken",
                hash: "not-a-hash",
            },
        ];
        p.users = Box::leak(Box::new(bad));
        let a = Authenticator::new(&p);
        assert_eq!(a.accounts(), 1);
        assert_eq!(
            a.authenticate(SRC, Some("broken"), Some(b"not-a-hash")),
            Verdict::Reject(Rejection::UnknownUser)
        );
        assert_eq!(
            a.authenticate(SRC, Some("ok"), Some(b"pw")),
            Verdict::Accept("ok")
        );
    }

    #[test]
    fn a_very_long_password_is_refused_without_a_long_computation() {
        let p = config(PlainAuth::Password, &[("a", "pw", 1000)], &[], "lan");
        let a = Authenticator::new(&p);
        let huge = vec![b'x'; 60_000];
        assert_eq!(
            a.authenticate(SRC, Some("a"), Some(&huge)),
            Verdict::Reject(Rejection::WrongPassword)
        );
    }
}
