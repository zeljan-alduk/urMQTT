//! Turns `deploy/$URMQTT_ENV/config.toml` (default `dev`) into Rust constants.
//!
//! Any invalid key, value or embedded file fails the build with a message
//! naming the offending key, so a broken configuration never reaches a VM.

use std::path::{Path, PathBuf};
use std::{env, fs, process};

use urmqtt_config_schema::{EmbeddedFiles, PemKind, check_pem, parse, render};

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}

fn main() {
    println!("cargo::rerun-if-env-changed=URMQTT_ENV");
    let env_name = env::var("URMQTT_ENV").unwrap_or_else(|_| "dev".to_owned());

    let manifest = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| fail("CARGO_MANIFEST_DIR not set")),
    );
    let root = manifest
        .ancestors()
        .nth(2)
        .unwrap_or_else(|| fail("cannot locate workspace root"));
    let dir = root.join("deploy").join(&env_name);
    let config_path = dir.join("config.toml");
    println!("cargo::rerun-if-changed={}", config_path.display());

    let text = fs::read_to_string(&config_path).unwrap_or_else(|e| {
        fail(&format!(
            "cannot read {}: {e} (is URMQTT_ENV={env_name:?} a directory under deploy/?)",
            config_path.display()
        ))
    });

    let cfg = parse(&env_name, &text).unwrap_or_else(|errors| {
        let list: Vec<String> = errors.iter().map(|e| format!("  - {e}")).collect();
        fail(&format!(
            "invalid configuration {}:\n{}",
            config_path.display(),
            list.join("\n")
        ))
    });

    let embed = |name: &str, kind: PemKind| -> String {
        let path = dir.join(name);
        println!("cargo::rerun-if-changed={}", path.display());
        let bytes =
            fs::read(&path).unwrap_or_else(|e| fail(&missing_file_hint(&env_name, &path, &e)));
        if let Err(m) = check_pem(&bytes, kind) {
            fail(&format!("{}: {m}", path.display()));
        }
        path.to_str()
            .unwrap_or_else(|| fail(&format!("{} is not valid UTF-8", path.display())))
            .to_owned()
    };
    let revoked = if cfg.tls.revocation_list.is_empty() {
        Vec::new()
    } else {
        let path = dir.join(&cfg.tls.revocation_list);
        println!("cargo::rerun-if-changed={}", path.display());
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| fail(&missing_file_hint(&env_name, &path, &e)));
        urmqtt_config_schema::parse_revocation_list(&text)
            .unwrap_or_else(|m| fail(&format!("{}: {m}", path.display())))
    };
    let files = EmbeddedFiles {
        ca: embed(&cfg.tls.ca, PemKind::Certificate),
        cert: embed(&cfg.tls.cert, PemKind::Certificate),
        key: embed(&cfg.tls.key, PemKind::PrivateKey),
        revoked,
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| fail("OUT_DIR not set")));
    let out = out_dir.join("generated.rs");
    let mut generated = render(&cfg, &files);
    // Dev builds only: a device certificate for in-kernel self-tests that
    // need a TLS client (`test=dp-bench`). Production images carry none.
    let (client_cert, client_key) = if env_name == "dev" {
        (
            format!(
                "include_bytes!({:?})",
                embed("devices/device-001.pem", PemKind::Certificate)
            ),
            format!(
                "include_bytes!({:?})",
                embed("devices/device-001.key", PemKind::PrivateKey)
            ),
        )
    } else {
        ("&[]".to_owned(), "&[]".to_owned())
    };
    generated.push_str(&format!(
        "\n/// Dev builds: device-001's certificate for self-tests (empty otherwise).\n\
         pub static SELFTEST_CLIENT_CERT_PEM: &[u8] = {client_cert};\n\
         /// Dev builds: device-001's key for self-tests (empty otherwise).\n\
         pub static SELFTEST_CLIENT_KEY_PEM: &[u8] = {client_key};\n"
    ));
    fs::write(&out, generated)
        .unwrap_or_else(|e| fail(&format!("cannot write {}: {e}", out.display())));
}

fn missing_file_hint(env_name: &str, path: &Path, e: &std::io::Error) -> String {
    if env_name == "dev" {
        format!(
            "cannot read {}: {e}\n  hint: run `make certs` to generate development certificates",
            path.display()
        )
    } else {
        format!(
            "cannot read {}: {e}\n  hint: production certificates are never committed; see docs/DEPLOY.md",
            path.display()
        )
    }
}
