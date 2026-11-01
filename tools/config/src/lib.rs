//! `urmqtt-config`: pack, show and verify urMQTT configuration blobs
//! (C1, ADR-215, ADR-218). The same code the web builder compiles to
//! WebAssembly lives in `urmqtt-cfg` and `urmqtt-config-schema`; this crate
//! is the file handling around it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use urmqtt_cfg::blob::{Blob, Hex, SlotKind, slot_blob};
use urmqtt_cfg::fields::{self, Kind};
use urmqtt_config_schema::pack::{PackOptions, pack};

pub mod image;

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
    // `--env` becomes the top-level `env` key unless the TOML sets one.
    let text = match &args.env {
        Some(env) if !text.lines().any(|l| l.trim_start().starts_with("env")) => {
            format!("env = {env:?}\n{text}")
        }
        _ => text,
    };
    let mut read = |name: &str| std::fs::read(dir.join(name)).map_err(|e| e.to_string());
    let blob = pack(
        &text,
        PackOptions {
            read: &mut read,
            now_unix: args.now_unix.unwrap_or_else(default_now),
        },
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

/// Signs `blob` with the Ed25519 key in `path`.
pub fn sign(blob: &[u8], path: &Path) -> Result<Vec<u8>, String> {
    use ed25519_dalek::{Signer, SigningKey};
    let pem = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let seed = urmqtt_control::parse_private_key(&pem).ok_or_else(|| {
        format!(
            "{}: expected an Ed25519 private key in PKCS#8 PEM (`openssl genpkey -algorithm ed25519`)",
            path.display()
        )
    })?;
    let key = SigningKey::from_bytes(&seed);
    urmqtt_cfg::build::sign(blob, |m| {
        (key.verifying_key().to_bytes(), key.sign(m).to_bytes())
    })
    .map_err(|e| e.to_string())
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

/// The first 8 bytes of SHA-256 of a public key: how the kernel's console
/// line names a signer.
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

/// A human-readable description of a blob: identity, signature and every
/// value that differs from the default (`all`: every field).
pub fn describe(blob_bytes: &[u8], all: bool) -> Result<String, String> {
    let b = Blob::parse(blob_bytes).map_err(|e| e.to_string())?;
    let mut o = String::new();
    let _ = writeln!(
        o,
        "format:      urmqtt-cfg version {}",
        urmqtt_cfg::FORMAT_VERSION
    );
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
    Ok(format!(
        "ok: fingerprint {}, {}, {served}",
        Hex(b.fingerprint()),
        if b.signature().is_some() {
            "signed"
        } else {
            "unsigned"
        }
    ))
}
