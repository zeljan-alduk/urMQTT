//! `urmqtt-config`: pack, show and verify urMQTT configuration blobs
//! (C1, ADR-215, ADR-218). The same code the web builder compiles to
//! WebAssembly (ADR-225) lives in `urmqtt-cfg` and `urmqtt-config-schema`;
//! this crate holds everything around it that does not touch the file
//! system (packing from text, signing, the ISO patching, minisign and
//! `SHA256SUMS` checks), so the command line and the browser run the very
//! same functions. Only [`pack_blob`] and the `main` of the binary read
//! files.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use urmqtt_cfg::blob::{Blob, Hex, SlotKind, slot_blob};
use urmqtt_cfg::fields::{self, Kind};
use urmqtt_config_schema::pack::{PackOptions, pack, pack_with};

pub mod certs;
pub mod image;
pub mod keyring;
pub mod keys;
pub mod minisign;
pub mod release;

pub use urmqtt_config_schema::ConfigError;

/// Supplies the files a configuration names (the command line reads them from
/// disk next to the TOML, the browser from the files the user chose).
pub type ReadFile<'a> = &'a mut dyn FnMut(&str) -> Result<Vec<u8>, String>;

/// What `pack` needs.
#[derive(Debug, Default, Clone)]
pub struct PackArgs {
    /// The configuration TOML; the files it names are read relative to it.
    pub toml: PathBuf,
    /// Environment name; default: the TOML's `env` key, else `prod`.
    pub env: Option<String>,
    /// Ed25519 private key (PKCS#8 PEM) to sign the blob with (optional).
    pub sign_key: Option<PathBuf>,
    /// Directory the files named in the TOML are read from (default: the
    /// TOML's own directory).
    pub root: Option<PathBuf>,
    /// The clock for the certificate expiry checks (default: now, but never
    /// before `SOURCE_DATE_EPOCH`).
    pub now_unix: Option<u64>,
    /// Write the newest format version whatever the configuration needs (`--latest-format`): for the
    /// empty configuration of a template ISO, whose slot then tells what its kernel reads (ADR-233).
    pub latest_format: bool,
}

/// The packer's clock: the system time, never earlier than the commit time
/// the build is pinned to (as the kernel's own build did).
pub fn default_now() -> u64 {
    let sys = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let pinned = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0);
    sys.max(pinned)
}

/// Builds the blob (optionally signed) for `args`.
pub fn pack_blob(args: &PackArgs) -> Result<Vec<u8>, String> {
    let text = std::fs::read_to_string(&args.toml)
        .map_err(|e| format!("cannot read {}: {e}", args.toml.display()))?;
    let dir = args.root.clone().unwrap_or_else(|| {
        args.toml
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    });
    let mut read = |name: &str| std::fs::read(dir.join(name)).map_err(|e| e.to_string());
    let blob = pack_with(
        &text,
        PackOptions {
            read: &mut read,
            now_unix: args.now_unix.unwrap_or_else(default_now),
            env: args.env.as_deref(),
        },
        args.latest_format,
    )
    .map_err(|errors| {
        let list: Vec<String> = errors.iter().map(|e| format!("  - {e}")).collect();
        format!(
            "invalid configuration {}:\n{}",
            args.toml.display(),
            list.join("\n")
        )
    })?;
    match &args.sign_key {
        None => Ok(blob),
        Some(path) => sign(&blob, path),
    }
}

/// Builds the (unsigned) blob for the configuration `text`. The files it names
/// come from `read`; `env` is the environment name (`--env`); `now_unix` is the
/// clock for the certificate expiry rules. Every problem found is returned,
/// addressed by its TOML key, so a page can put each next to its field. This
/// is the function the command line and the browser (WebAssembly) both call.
pub fn pack_text(
    text: &str,
    read: ReadFile<'_>,
    env: Option<&str>,
    now_unix: u64,
) -> Result<Vec<u8>, Vec<ConfigError>> {
    pack(
        text,
        PackOptions {
            read,
            now_unix,
            env,
        },
    )
}

/// The message for a key that is not an Ed25519 PKCS#8 private key.
pub const NOT_AN_ED25519_KEY: &str =
    "expected an Ed25519 private key in PKCS#8 PEM (`openssl genpkey -algorithm ed25519`)";

/// Signs `blob` with the Ed25519 private key `pem` (PKCS#8, PEM or DER).
pub fn sign_pem(blob: &[u8], pem: &[u8]) -> Result<Vec<u8>, String> {
    use ed25519_dalek::{Signer, SigningKey};
    let seed = urmqtt_control::parse_private_key(pem).ok_or(NOT_AN_ED25519_KEY)?;
    let key = SigningKey::from_bytes(&seed);
    urmqtt_cfg::build::sign(blob, |m| {
        (key.verifying_key().to_bytes(), key.sign(m).to_bytes())
    })
    .map_err(|e| e.to_string())
}

/// Signs `blob` with the Ed25519 key in `path`.
pub fn sign(blob: &[u8], path: &Path) -> Result<Vec<u8>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    sign_pem(blob, &pem).map_err(|e| {
        if e == NOT_AN_ED25519_KEY {
            format!("{}: {e}", path.display())
        } else {
            e
        }
    })
}

/// The slot file (marker, blob, padding) for `blob`.
pub fn slot_of(blob: &[u8]) -> Result<Vec<u8>, String> {
    urmqtt_cfg::blob::make_slot(SlotKind::Boot, blob)
        .ok_or_else(|| "the configuration does not fit in a 256 KiB slot".to_owned())
}

/// The blob inside `bytes`: a bare blob, or a slot of either kind.
pub fn blob_of(bytes: &[u8]) -> Result<&[u8], String> {
    if bytes.starts_with(&urmqtt_cfg::MAGIC) {
        return Ok(bytes);
    }
    for kind in [SlotKind::Boot, SlotKind::Disk] {
        if bytes.starts_with(&kind.marker()) {
            return slot_blob(bytes, kind).map_err(|e| e.to_string());
        }
    }
    Err("not a urmqtt-cfg blob or configuration slot".into())
}

/// The first 8 bytes of the domain-separated SHA-256 (`fingerprint_of`) of a
/// public key: how the kernel's console line names a signer.
pub fn signer_id(key: &[u8; 32]) -> String {
    Hex(&urmqtt_cfg::blob::fingerprint_of(key)[..8]).to_string()
}

fn pem_summary(pem: &[u8]) -> String {
    let text = String::from_utf8_lossy(pem);
    if text.contains("PRIVATE KEY") {
        return format!("private key, {} bytes (not shown)", pem.len());
    }
    match urmqtt_config_schema::cert_validity(pem) {
        Ok(v) => v
            .iter()
            .map(|c| format!("{} (notAfter {})", c.subject, c.not_after))
            .collect::<Vec<_>>()
            .join("; "),
        Err(_) => format!("{} bytes", pem.len()),
    }
}

fn ip(a: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])
}

/// The value of one record as text.
fn value_text(f: &fields::Field, blob: &Blob<'_>) -> String {
    let t = f.tag;
    match f.kind {
        Kind::Bool(_) => blob.bool(t).to_string(),
        Kind::UInt { .. } => blob.uint(t).to_string(),
        Kind::Enum { variants, .. } => variants
            .get(usize::from(blob.variant(t)))
            .copied()
            .unwrap_or("?")
            .to_owned(),
        Kind::Str { .. } => format!("{:?}", blob.str(t)),
        // The accounts (plaintext.users, websocket.users) are shown without their
        // hashes (they are not secrets of the image, but they are not for a
        // screen or a log either).
        Kind::Strs { .. } if f.item == fields::Item::User => {
            let shown: Vec<String> = blob
                .strs(t)
                .map(|entry| match urmqtt_cfg::plain::parse_user(entry) {
                    Ok((id, h)) => format!(
                        "{id} ({}, {} iterations)",
                        urmqtt_cfg::passwd::SCHEME,
                        h.iterations()
                    ),
                    Err(_) => "<invalid>".to_owned(),
                })
                .collect();
            format!("{shown:?}")
        }
        Kind::Strs { .. } => format!("{:?}", blob.strs(t).collect::<Vec<_>>()),
        Kind::Bin { .. } => pem_summary(blob.bin(t)),
        Kind::BinList { .. } => blob.bins(t).map(pem_summary).collect::<Vec<_>>().join("; "),
        Kind::Ipv4 => blob.ipv4(t).map_or_else(String::new, ip),
        Kind::Cidr => blob
            .cidr(t)
            .map_or_else(String::new, |(a, p)| format!("{}/{p}", ip(a))),
        Kind::Rate { .. } => {
            let (n, ms) = blob.rate(t);
            let unit = match ms {
                1000 => "s",
                60_000 => "m",
                3_600_000 => "h",
                _ => "?",
            };
            format!("{n}/{unit}")
        }
        Kind::Addr => blob
            .addr(t)
            .map_or_else(String::new, |(a, p)| format!("{}:{p}", ip(a))),
        Kind::Addrs { .. } => blob
            .addrs(t)
            .map(|(a, p)| format!("{}:{p}", ip(a)))
            .collect::<Vec<_>>()
            .join(", "),
        Kind::Key32 => blob
            .key32(t)
            .map_or_else(String::new, |k| Hex(&k).to_string()),
    }
}

/// One line about the plaintext listener when it is on (P1, ADR-229): what
/// whoever ships the image has to know. `None` when it is off.
pub fn plaintext_summary(b: &Blob<'_>) -> Option<String> {
    use fields::tag;
    if !b.bool(tag::PL_ENABLED) {
        return None;
    }
    let from = if b.bool(tag::PL_ANYWHERE) {
        "ANY ADDRESS (allow_from_anywhere)".to_owned()
    } else {
        b.strs(tag::PL_ALLOW_FROM).collect::<Vec<_>>().join(", ")
    };
    let who = match b.variant(tag::PL_AUTH) {
        1 => format!("no login, everyone is {:?}", b.str(tag::PL_ANON_ID)),
        2 => format!(
            "the address decides, {} network(s)",
            b.strs(tag::PL_IP_IDENTITIES).count()
        ),
        _ => format!("password, {} account(s)", b.strs(tag::PL_USERS).count()),
    };
    Some(format!(
        "plaintext MQTT ON, NOT ENCRYPTED: port {}, {who}, from {from}",
        b.uint(tag::PL_PORT)
    ))
}

/// One line about the WebSocket listener when it is on with password logins
/// (ADR-272): those clients show no certificate, so whoever ships the image has
/// to know. `None` when it is off or uses client certificates (mtls).
pub fn websocket_summary(b: &Blob<'_>) -> Option<String> {
    use fields::tag;
    if !b.bool(tag::WS_ENABLED) || b.variant(tag::WS_AUTH) != 1 {
        return None;
    }
    Some(format!(
        "MQTT over WebSocket ON with PASSWORD logins (inside TLS, no client certificate): port {}, path {:?}, {} account(s), origins {}",
        b.uint(tag::WS_PORT),
        b.str(tag::WS_PATH),
        b.strs(tag::WS_USERS).count(),
        b.strs(tag::WS_ORIGINS).collect::<Vec<_>>().join(", ")
    ))
}

/// Whether the configuration allows the CPU-jitter entropy fallback
/// (`entropy.fallback = "jitter"`, the default; ADR-038, ADR-263).
pub fn jitter_allowed(b: &Blob<'_>) -> bool {
    b.variant(fields::tag::ENTROPY_JITTER) == 0
}

/// The warning for the weak entropy path, when it is allowed (ADR-263): what
/// whoever ships the image has to know. `None` when the image requires a
/// hardware source.
pub fn entropy_warning(b: &Blob<'_>) -> Option<String> {
    jitter_allowed(b).then(|| {
        "entropy.fallback = \"jitter\": on a host without virtio-rng or RNDR/RDRAND the generator is \
         seeded from CPU jitter and firmware values, which is weaker than a hardware source; \
         set it to \"none\" to refuse such hosts"
            .to_owned()
    })
}

/// The stored hash of `password` for the plaintext or WebSocket listener
/// (`pbkdf2-sha256$iterations$salt$key`, see `urmqtt_cfg::passwd`). The caller
/// supplies the salt (16 to 32 random bytes); the command line takes it from
/// the operating system, the browser from `crypto.getRandomValues`.
pub fn hash_password(password: &[u8], salt: &[u8], iterations: u32) -> Result<String, String> {
    if password.is_empty() {
        return Err("the password is empty".into());
    }
    if password.len() > urmqtt_cfg::passwd::MAX_PASSWORD {
        return Err(format!(
            "the password is longer than {} bytes, which no login can match",
            urmqtt_cfg::passwd::MAX_PASSWORD
        ));
    }
    urmqtt_cfg::passwd::encode(password, salt, iterations).map_err(|e| e.to_string())
}

/// Fills `buf` from the operating system's random source (host tools only).
pub fn os_random(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|e| format!("cannot read random bytes from /dev/urandom: {e}"))
}

/// A human-readable description of a blob: identity, signature and every
/// value that differs from the default (`all`: every field).
pub fn describe(blob_bytes: &[u8], all: bool) -> Result<String, String> {
    let b = Blob::parse(blob_bytes).map_err(|e| e.to_string())?;
    let mut o = String::new();
    let _ = writeln!(o, "format:      urmqtt-cfg version {}", b.version());
    let _ = writeln!(o, "fingerprint: {}", Hex(b.fingerprint()));
    let _ = writeln!(o, "size:        {} bytes", b.len());
    match b.signature() {
        Some(s) => {
            let _ = writeln!(
                o,
                "signature:   valid, signer key {} (public key {})",
                signer_id(&s.public_key),
                Hex(&s.public_key)
            );
        }
        None => {
            let _ = writeln!(o, "signature:   none");
        }
    }
    let env = b.str(fields::tag::ENV);
    let _ = writeln!(o, "env:         {env}");
    if let Some(p) = plaintext_summary(&b) {
        let _ = writeln!(o, "warning:     {p}");
    }
    if let Some(w) = websocket_summary(&b) {
        let _ = writeln!(o, "warning:     {w}");
    }
    let _ = writeln!(
        o,
        "entropy:     {}",
        if jitter_allowed(&b) {
            "CPU-jitter fallback ALLOWED (entropy.fallback = \"jitter\"): weaker than a hardware source"
        } else {
            "hardware source REQUIRED (entropy.fallback = \"none\"): refuses to boot without one"
        }
    );
    if let Some(w) = entropy_warning(&b) {
        let _ = writeln!(o, "WARNING:     {w}");
    }
    if b.is_empty() {
        let _ = writeln!(
            o,
            "\nEmpty configuration: every field is at its default; no certificates (the broker will not serve)."
        );
    }
    let _ = writeln!(o);
    let mut section = "";
    for f in fields::FIELDS {
        if !f.stored {
            continue;
        }
        let present = b.raw(f.tag).is_some();
        if !present && !all {
            continue;
        }
        let (sec, name) = f.key.split_once('.').unwrap_or(("", f.key));
        if sec != section {
            let _ = writeln!(o, "[{sec}]");
            section = sec;
        }
        let shown = value_text(f, &b);
        let mark = if present { "" } else { "  (default)" };
        let _ = writeln!(o, "  {name} = {shown}{mark}");
    }
    Ok(o)
}

/// Parses and checks a blob the way a kernel does. `dev`: as a dev kernel.
pub fn verify_blob(blob_bytes: &[u8], dev: bool) -> Result<String, String> {
    let b = Blob::parse(blob_bytes).map_err(|e| e.to_string())?;
    urmqtt_cfg::check::check(&b, dev).map_err(|e| e.to_string())?;
    let served = if b.bin(fields::tag::TLS_CERT).is_empty()
        || b.bin(fields::tag::TLS_KEY).is_empty()
        || b.bins(fields::tag::TRUST_OPERATIONAL).next().is_none()
    {
        "no certificate, key or operational CA: boots, but will not serve"
    } else {
        "complete: a kernel will serve with it"
    };
    let plaintext = plaintext_summary(&b).map_or_else(String::new, |p| format!("\nwarning: {p}"));
    let websocket = websocket_summary(&b).map_or_else(String::new, |w| format!("\nwarning: {w}"));
    let entropy = entropy_warning(&b).map_or_else(String::new, |w| format!("\nWARNING: {w}"));
    Ok(format!(
        "ok: fingerprint {}, {}, {served}{plaintext}{websocket}{entropy}",
        Hex(b.fingerprint()),
        if b.signature().is_some() {
            "signed"
        } else {
            "unsigned"
        }
    ))
}
