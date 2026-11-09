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

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use urmqtt_cfg::net::Cidr;
use urmqtt_cfg::passwd::PasswordHash;
use urmqtt_config::{PlainAuth, PlainUser, Plaintext};

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

/// A password account added at run time through the control channel (NOW-15,
/// ADR-285): the id, the parsed PBKDF2 hash (never a password) and the ACL
/// class byte (`urmqtt_control::AccountClass`; the broker applies it).
#[derive(Clone, PartialEq, Eq)]
pub struct Account {
    pub id: String,
    pub hash: PasswordHash,
    pub class: u8,
}

/// Every run-time account, sorted by id (for a binary search).
pub type Accounts = Arc<Vec<Account>>;

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

/// New password logins a data core admits per second, from the measured cost
/// of one check in nanoseconds (0: no password mode) and the TLS handshake
/// rate `cap` (`limits.handshakes_per_core_per_sec`): as many as use **half
/// the core**, at least 1, at most `cap` (ADR-230, ADR-267).
///
/// Until ADR-267 the floor was 20 a second, which overrode the half-core rule
/// as soon as a check cost more than 25 ms (100 000 iterations on a VPS vCPU,
/// 200 000 on the test machine): a flood of failing logins from an allowed
/// address could then hold a whole core.
pub fn login_rate(cost_ns: u64, cap: u32) -> u32 {
    let cap = cap.max(1);
    if cost_ns == 0 {
        return cap;
    }
    u32::try_from(500_000_000 / cost_ns)
        .unwrap_or(u32::MAX)
        .clamp(1, cap)
}

pub struct Authenticator<'a> {
    mode: PlainAuth,
    users: Vec<(&'a str, PasswordHash)>,
    anonymous: &'a str,
    networks: Vec<(Cidr, &'a str)>,
    /// What a login for an unknown user is checked against.
    decoy: PasswordHash,
    /// Accounts added at run time (ADR-285), sorted by id. The image's
    /// accounts win: an id in both is the image's.
    runtime: Option<Accounts>,
    /// The most iterations of the accounts of the image alone.
    image_iterations: u32,
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
            runtime: None,
            image_iterations: iterations,
        }
    }

    /// Password mode over `users`, the accounts of another listener (the
    /// WebSocket one, ADR-272): the same check, the same decoy, the same
    /// answers.
    pub fn password_only(users: &'a [PlainUser]) -> Self {
        let users: Vec<(&str, PasswordHash)> = users
            .iter()
            .filter_map(|u| PasswordHash::parse(u.hash).ok().map(|h| (u.id, h)))
            .collect();
        let iterations = users
            .iter()
            .map(|(_, h)| h.iterations())
            .max()
            .unwrap_or(urmqtt_cfg::passwd::DEFAULT_ITERATIONS);
        Self {
            mode: PlainAuth::Password,
            users,
            anonymous: "",
            networks: Vec::new(),
            decoy: PasswordHash::decoy(iterations),
            runtime: None,
            image_iterations: iterations,
        }
    }

    /// Replaces the accounts added at run time (`None`: none). In password
    /// mode only; the decoy then costs as much as the dearest account of
    /// either kind, so an unknown user still takes as long as a known one.
    pub fn set_runtime(&mut self, accounts: Option<Accounts>) {
        let dearest = accounts
            .as_ref()
            .and_then(|a| a.iter().map(|x| x.hash.iterations()).max())
            .unwrap_or(0)
            .max(self.image_iterations);
        self.decoy = PasswordHash::decoy(dearest);
        self.runtime = accounts;
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

    /// The accounts of the image.
    pub fn accounts(&self) -> usize {
        self.users.len()
    }

    /// The accounts added at run time.
    pub fn runtime_accounts(&self) -> usize {
        self.runtime.as_ref().map_or(0, |a| a.len())
    }

    /// Decides a CONNECT from `src` with the credentials it carried.
    pub fn authenticate(
        &self,
        src: [u8; 4],
        username: Option<&str>,
        password: Option<&[u8]>,
    ) -> Verdict<'_> {
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

    fn password(&self, username: Option<&str>, password: Option<&[u8]>) -> Verdict<'_> {
        let image = username.and_then(|u| self.users.iter().find(|(id, _)| *id == u));
        let account: Option<(&str, &PasswordHash)> = match image {
            Some((id, h)) => Some((*id, h)),
            None => username.and_then(|u| {
                let list = self.runtime.as_ref()?;
                let i = list.binary_search_by(|a| a.id.as_str().cmp(u)).ok()?;
                let a = list.get(i)?;
                Some((a.id.as_str(), &a.hash))
            }),
        };
        // One hash on every path.
        let (hash, ok_identity) = match account {
            Some((id, h)) => (h, Some(id)),
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

    fn runtime(list: &[(&str, &str, u32, u8)]) -> Accounts {
        let mut v: Vec<Account> = list
            .iter()
            .map(|(id, pw, it, class)| Account {
                id: (*id).into(),
                hash: PasswordHash::parse(
                    &passwd::encode(pw.as_bytes(), b"0123456789abcdef", *it).unwrap(),
                )
                .unwrap(),
                class: *class,
            })
            .collect();
        v.sort_by(|a, b| a.id.cmp(&b.id));
        Arc::new(v)
    }

    /// NOW-15, ADR-285: accounts added at run time log in, in both
    /// authenticators; the image's accounts win; a removed or changed one is
    /// gone at the next `set_runtime`; unknown, wrong and missing credentials
    /// are told alike as before.
    #[test]
    fn runtime_accounts_log_in_and_the_image_wins() {
        let hash = passwd::encode(b"image-pw", b"0123456789abcdef", 1000).unwrap();
        let hash: &'static str = Box::leak(hash.into_boxed_str());
        let users: &'static [PlainUser] = Box::leak(Box::new([PlainUser { id: "img", hash }]));
        let mut a = Authenticator::password_only(users);
        let src = [10, 0, 0, 1];
        assert_eq!(
            a.authenticate(src, Some("dyn"), Some(b"dyn-pw")),
            Verdict::Reject(Rejection::UnknownUser)
        );
        a.set_runtime(Some(runtime(&[
            ("zed", "zed-pw", 2000, 0),
            ("dyn", "dyn-pw", 3000, 1),
            ("img", "other-pw", 1000, 0),
        ])));
        assert_eq!(a.runtime_accounts(), 3);
        assert_eq!(a.max_iterations(), 3000, "the decoy costs the dearest");
        assert_eq!(
            a.authenticate(src, Some("dyn"), Some(b"dyn-pw")),
            Verdict::Accept("dyn")
        );
        assert_eq!(
            a.authenticate(src, Some("zed"), Some(b"zed-pw")),
            Verdict::Accept("zed")
        );
        assert_eq!(
            a.authenticate(src, Some("dyn"), Some(b"zed-pw")),
            Verdict::Reject(Rejection::WrongPassword)
        );
        assert_eq!(
            a.authenticate(src, Some("dyn"), None),
            Verdict::Reject(Rejection::NoCredentials)
        );
        // The image's account of that id decides, not the run-time one.
        assert_eq!(
            a.authenticate(src, Some("img"), Some(b"image-pw")),
            Verdict::Accept("img")
        );
        assert_eq!(
            a.authenticate(src, Some("img"), Some(b"other-pw")),
            Verdict::Reject(Rejection::WrongPassword)
        );
        // Replaced: the old password stops working at once.
        a.set_runtime(Some(runtime(&[("dyn", "new-pw", 1000, 2)])));
        assert_eq!(
            a.authenticate(src, Some("dyn"), Some(b"dyn-pw")),
            Verdict::Reject(Rejection::WrongPassword)
        );
        assert_eq!(
            a.authenticate(src, Some("dyn"), Some(b"new-pw")),
            Verdict::Accept("dyn")
        );
        assert_eq!(a.max_iterations(), 1000);
        // Removed.
        a.set_runtime(None);
        assert_eq!(a.runtime_accounts(), 0);
        assert_eq!(
            a.authenticate(src, Some("dyn"), Some(b"new-pw")),
            Verdict::Reject(Rejection::UnknownUser)
        );
    }

    /// The plaintext authenticator takes them in password mode, and in no
    /// other mode.
    #[test]
    fn runtime_accounts_only_count_in_password_mode() {
        let p = config(PlainAuth::Password, &[], &[], "");
        let mut a = Authenticator::new(&p);
        a.set_runtime(Some(runtime(&[("dyn", "pw", 1000, 0)])));
        assert_eq!(
            a.authenticate([1, 2, 3, 4], Some("dyn"), Some(b"pw")),
            Verdict::Accept("dyn")
        );
        let p = config(PlainAuth::Anonymous, &[], &[], "anon");
        let mut a = Authenticator::new(&p);
        a.set_runtime(Some(runtime(&[("dyn", "pw", 1000, 0)])));
        assert_eq!(a.max_iterations(), 0);
        assert_eq!(
            a.authenticate([1, 2, 3, 4], Some("dyn"), Some(b"wrong")),
            Verdict::Accept("anon")
        );
    }

    /// ADR-272: the WebSocket listener's accounts, checked as in password
    /// mode: credentials, unknown user, wrong password, success.
    #[test]
    fn password_only_checks_another_account_list() {
        let hash = passwd::encode(b"secret", b"0123456789abcdef", 1000).unwrap();
        let hash: &'static str = Box::leak(hash.into_boxed_str());
        let users: &'static [PlainUser] = Box::leak(Box::new([PlainUser { id: "web-1", hash }]));
        let a = Authenticator::password_only(users);
        assert_eq!(a.mode(), PlainAuth::Password);
        assert_eq!(a.max_iterations(), 1000);
        let src = [10, 0, 0, 1];
        assert_eq!(
            a.authenticate(src, Some("web-1"), Some(b"secret")),
            Verdict::Accept("web-1")
        );
        assert_eq!(
            a.authenticate(src, Some("web-1"), Some(b"nope")),
            Verdict::Reject(Rejection::WrongPassword)
        );
        assert_eq!(
            a.authenticate(src, Some("web-2"), Some(b"secret")),
            Verdict::Reject(Rejection::UnknownUser)
        );
        assert_eq!(
            a.authenticate(src, None, None),
            Verdict::Reject(Rejection::NoCredentials)
        );
    }

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

    /// ADR-267: the login rate never hands a core more than half its time to
    /// password checks, whatever the cost, and never stops logins altogether.
    #[test]
    fn the_login_rate_keeps_half_the_core() {
        const MS: u64 = 1_000_000;
        // No password mode: the TLS rate.
        assert_eq!(login_rate(0, 2000), 2000);
        // 10 000 iterations under HVF (2.5 ms): 200 a second.
        assert_eq!(login_rate(2_500_000, 2000), 200);
        // 100 000 under HVF (25.5 ms) and on a VPS vCPU (about 50 ms).
        assert_eq!(login_rate(25_500_000, 2000), 19);
        assert_eq!(login_rate(50 * MS, 2000), 10);
        // 600 000 on a VPS vCPU (about 300 ms), and a check dearer than a
        // second: still one login a second, not none.
        assert_eq!(login_rate(300 * MS, 2000), 1);
        assert_eq!(login_rate(2_000 * MS, 2000), 1);
        // A cheap check is held to the TLS rate; a zero cap is treated as 1.
        assert_eq!(login_rate(1_000, 2000), 2000);
        assert_eq!(login_rate(1_000, 0), 1);
        // Whatever the cost, the admitted checks use at most half a second
        // of every second (where the floor of 1 does not bind).
        for cost in [MS, 3 * MS, 7 * MS, 26 * MS, 99 * MS, 333 * MS, 499 * MS] {
            let r = u64::from(login_rate(cost, 100_000));
            assert!(r * cost <= 500 * MS, "{cost}: {r}/s");
            assert!((r + 1) * cost > 500 * MS, "{cost}: {r}/s is not the most");
        }
    }

    /// ADR-267: accounts hashed with the old default and the new one live
    /// side by side; the decoy costs what the dearest of them costs.
    #[test]
    fn old_and_new_default_hashes_work_together() {
        let p = config(
            PlainAuth::Password,
            &[
                ("old", "a", 10_000),
                ("new", "b", passwd::DEFAULT_ITERATIONS),
            ],
            &[],
            "lan",
        );
        let a = Authenticator::new(&p);
        assert_eq!(a.accounts(), 2);
        assert_eq!(a.max_iterations(), passwd::DEFAULT_ITERATIONS);
        assert_eq!(
            a.authenticate(SRC, Some("old"), Some(b"a")),
            Verdict::Accept("old")
        );
        assert_eq!(
            a.authenticate(SRC, Some("new"), Some(b"b")),
            Verdict::Accept("new")
        );
        assert_eq!(
            a.authenticate(SRC, Some("old"), Some(b"b")),
            Verdict::Reject(Rejection::WrongPassword)
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
