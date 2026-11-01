//! `urmqtt-config`: build, inspect and check urMQTT configurations
//! (C1, ADR-215, ADR-218).
//!
//! ```text
//! urmqtt-config pack CONFIG.toml [--env NAME] [--sign KEY.pem] [--root DIR] [--now UNIX]
//!                    --out BLOB | --out-slot SLOT
//!                    | --iso TEMPLATE.iso --out OUT.iso
//!                    | --image DISK.img --out OUT.img
//!     Builds the configuration blob from CONFIG.toml and the PEM files it
//!     names (paths relative to the TOML). Keys left out take the documented
//!     defaults. Prints the fingerprint the kernel prints at boot.
//!       --out BLOB        the bare blob
//!       --out-slot SLOT   the 256 KiB slot file the bootloader loads
//!       --iso/--image     write the configuration into a template ISO or a
//!                         raw disk image (a copy; the template is not changed)
//! urmqtt-config slot BLOB OUT
//!     Wraps a blob (or re-marks a slot) as the 256 KiB file the bootloader loads.
//! urmqtt-config show FILE [--all]
//!     Prints a blob, a slot, an ISO or a raw image's configuration:
//!     fingerprint, signature, every non-default value (certificates are
//!     summarised, keys are never printed).
//! urmqtt-config verify FILE [--dev]
//!     Checks it the way a (release, or with --dev, dev) kernel does; for
//!     an image also that every copy of the configuration and every module
//!     hash agree. Non-zero exit on any problem.
//! urmqtt-config schema
//!     The field table as JSON: key, type, default, range, help, dev-only.
//! ```

use std::path::PathBuf;
use std::process::ExitCode;

use urmqtt_config_tool::{PackArgs, image};

fn usage() -> String {
    "usage:\n  urmqtt-config pack CONFIG.toml [--env NAME] [--sign KEY.pem] [--root DIR] [--now UNIX] \
     (--out BLOB | --out-slot SLOT | --iso TEMPLATE.iso --out OUT.iso | --image DISK.img --out OUT.img)\n  \
     urmqtt-config slot BLOB OUT\n  urmqtt-config show FILE [--all]\n  urmqtt-config verify FILE [--dev]\n  urmqtt-config schema\n"
        .to_owned()
}

fn take(args: &mut Vec<String>, flag: &str) -> Result<Option<String>, String> {
    match args.iter().position(|a| a == flag) {
        None => Ok(None),
        Some(i) => {
            if i + 1 >= args.len() {
                return Err(format!("{flag} needs a value"));
            }
            let v = args.remove(i + 1);
            args.remove(i);
            Ok(Some(v))
        }
    }
}

fn flag(args: &mut Vec<String>, name: &str) -> bool {
    args.iter()
        .position(|a| a == name)
        .map(|i| args.remove(i))
        .is_some()
}

fn write(path: &str, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("cannot write {path}: {e}"))
}

fn run(mut args: Vec<String>) -> Result<(), String> {
    if args.is_empty() {
        return Err(usage());
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "schema" => {
            print!("{}", urmqtt_config_schema::pack::schema_json());
            Ok(())
        }
        "pack" => {
            let env = take(&mut args, "--env")?;
            let sign_key = take(&mut args, "--sign")?.map(PathBuf::from);
            let root = take(&mut args, "--root")?.map(PathBuf::from);
            let now_unix = take(&mut args, "--now")?
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| "--now takes Unix seconds".to_owned())
                })
                .transpose()?;
            let out = take(&mut args, "--out")?;
            let out_slot = take(&mut args, "--out-slot")?;
            let iso = take(&mut args, "--iso")?;
            let img = take(&mut args, "--image")?;
            let [toml] = args.as_slice() else {
                return Err(usage());
            };
            let blob = urmqtt_config_tool::pack_blob(&PackArgs {
                toml: PathBuf::from(toml),
                env,
                sign_key,
                root,
                now_unix,
            })?;
            let desc = urmqtt_config_tool::verify_blob(&blob, true)?;
            match (out, out_slot, iso, img) {
                (Some(o), None, None, None) => write(&o, &blob)?,
                (None, Some(o), None, None) => write(&o, &urmqtt_config_tool::slot_of(&blob)?)?,
                (Some(o), None, Some(template), None) => {
                    let data = std::fs::read(&template)
                        .map_err(|e| format!("cannot read {template}: {e}"))?;
                    let patched = image::configure_iso(&data, &blob)?;
                    write(&o, &patched.bytes)?;
                    eprintln!("{}", patched.report);
                }
                (Some(o), None, None, Some(image_path)) => {
                    let data = std::fs::read(&image_path)
                        .map_err(|e| format!("cannot read {image_path}: {e}"))?;
                    let patched = image::configure_raw(&data, &blob)?;
                    write(&o, &patched.bytes)?;
                    eprintln!("{}", patched.report);
                }
                _ => return Err(usage()),
            }
            println!("{desc}");
            Ok(())
        }
        "slot" => {
            // Wraps a blob (or re-marks a slot) as the file the bootloader loads.
            let [file, out] = args.as_slice() else {
                return Err(usage());
            };
            let data = std::fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
            let blob = urmqtt_config_tool::blob_of(&data)?;
            urmqtt_config_tool::verify_blob(blob, true)?;
            write(out, &urmqtt_config_tool::slot_of(blob)?)
        }
        "show" => {
            let all = flag(&mut args, "--all");
            let [file] = args.as_slice() else {
                return Err(usage());
            };
            let data = std::fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
            print!("{}", image::show(&data, all)?);
            Ok(())
        }
        "verify" => {
            let dev = flag(&mut args, "--dev");
            let [file] = args.as_slice() else {
                return Err(usage());
            };
            let data = std::fs::read(file).map_err(|e| format!("cannot read {file}: {e}"))?;
            println!("{}", image::verify(&data, dev)?);
            Ok(())
        }
        _ => Err(usage()),
    }
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
