//! The example edition's `urmqtt-config pack`: the open configuration plus
//! the edition's `[ext.example]` keys (NOW-18, ADR-337).
//!
//!   urmqtt-example-config <config.toml> (--out <blob> | --out-slot <slot>) [--env dev] [--root <dir>]
//!
//! `--out-slot` writes the 256 KiB slot file the bootloader loads, for
//! `scripts/mkiso.sh --config-slot`.
//!
//! The files the TOML names are read relative to `--root` (default: the
//! TOML's directory). The open `urmqtt-config` refuses an `[ext]` table.

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (mut toml, mut out, mut env, mut root) = (None, None, None, None);
    let mut slot = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out = args.next().map(PathBuf::from),
            "--out-slot" => {
                out = args.next().map(PathBuf::from);
                slot = true;
            }
            "--env" => env = args.next(),
            "--root" => root = args.next().map(PathBuf::from),
            _ if toml.is_none() => toml = Some(PathBuf::from(a)),
            _ => {
                eprintln!("unexpected argument {a}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(toml), Some(out)) = (toml, out) else {
        eprintln!(
            "usage: urmqtt-example-config <config.toml> (--out <blob> | --out-slot <slot>) [--env dev] [--root <dir>]"
        );
        return ExitCode::from(2);
    };
    let root = root.unwrap_or_else(|| toml.parent().map(PathBuf::from).unwrap_or_default());
    let text = match std::fs::read_to_string(&toml) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{}: {e}", toml.display());
            return ExitCode::FAILURE;
        }
    };
    let mut read = |name: &str| std::fs::read(root.join(name)).map_err(|e| format!("{name}: {e}"));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let opts = urmqtt_config_schema::pack::PackOptions {
        read: &mut read,
        now_unix: now,
        env: env.as_deref(),
    };
    match urmqtt_config_schema::pack::pack_ext(&text, opts, false, urmqtt_edition_example::FIELDS) {
        Ok(blob) => {
            let fp = urmqtt_cfg::Blob::parse_ext(&blob, urmqtt_edition_example::FIELDS)
                .map(|b| urmqtt_cfg::blob::Hex(b.fingerprint()).to_string())
                .unwrap_or_default();
            let bytes = if slot {
                match urmqtt_cfg::blob::make_slot(urmqtt_cfg::SlotKind::Boot, &blob) {
                    Some(s) => s,
                    None => {
                        eprintln!("the configuration does not fit in a slot");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                blob.clone()
            };
            if let Err(e) = std::fs::write(&out, &bytes) {
                eprintln!("{}: {e}", out.display());
                return ExitCode::FAILURE;
            }
            println!(
                "packed {} ({} bytes, fingerprint {fp})",
                out.display(),
                blob.len()
            );
            ExitCode::SUCCESS
        }
        Err(errors) => {
            for e in errors {
                eprintln!("error: {e}");
            }
            ExitCode::FAILURE
        }
    }
}
