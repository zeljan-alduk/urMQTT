//! The configuration slot in the ESP of a boot disk (C1c, ADR-217): read it,
//! describe it, and carry it over when the ESP is replaced.

use urmqtt_cfg::blob::{Blob, Hex, SLOT_SIZE, SlotKind, find_slots, slot_blob};

/// What an ESP holds as its configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EspConfig {
    /// A configured slot (marker `SLOT`).
    Configured {
        offset: usize,
        fingerprint: String,
        signer: Option<String>,
        env: String,
        empty: bool,
    },
    /// The installation image's unconfigured slot (marker `DISK`): the
    /// installed kernel runs with the defaults and will not serve.
    Template { offset: usize },
    /// No slot: an ESP from before the runtime configuration.
    NoSlot,
}

fn slot_at(esp: &[u8], off: usize) -> Option<&[u8]> {
    esp.get(off..off + SLOT_SIZE)
}

/// Classifies the ESP's configuration slot.
pub fn read(esp: &[u8]) -> EspConfig {
    if let [off] = find_slots(esp, SlotKind::Boot).as_slice()
        && let Some(slot) = slot_at(esp, *off)
        && let Ok(bytes) = slot_blob(slot, SlotKind::Boot)
        && let Ok(b) = Blob::parse(bytes)
    {
        return EspConfig::Configured {
            offset: *off,
            fingerprint: Hex(b.fingerprint()).to_string(),
            signer: b.signature().map(|s| {
                let fp = urmqtt_cfg::blob::fingerprint_of(&s.public_key);
                Hex(fp.get(..8).unwrap_or(&[])).to_string()
            }),
            env: b.str(urmqtt_cfg::fields::tag::ENV).to_owned(),
            empty: b.is_empty(),
        };
    }
    match find_slots(esp, SlotKind::Disk).as_slice() {
        [off] => EspConfig::Template { offset: *off },
        _ => EspConfig::NoSlot,
    }
}

/// One line for `urmqtt-disk info`.
pub fn describe(c: &EspConfig) -> String {
    match c {
        EspConfig::Configured {
            fingerprint,
            signer,
            env,
            empty,
            ..
        } => format!(
            "config: fingerprint {fingerprint} ({}), env={env}{}",
            match signer {
                Some(k) => format!("signed by key {k}"),
                None => "unsigned".to_owned(),
            },
            if *empty {
                "; EMPTY: all defaults, the broker will not serve"
            } else {
                ""
            }
        ),
        EspConfig::Template { .. } => {
            "config: not configured (the installation image's template slot): defaults, the broker will not serve"
                .to_owned()
        }
        EspConfig::NoSlot => "config: none (an ESP from before the runtime configuration)".to_owned(),
    }
}

/// The boot slot for a file given with `--config`: a blob (wrapped), or a
/// slot file (either marker; re-marked as a boot slot).
pub fn slot_from_file(bytes: &[u8]) -> Result<Vec<u8>, String> {
    use urmqtt_cfg::blob::{DISK_MARKER, SLOT_MARKER, make_slot};
    let blob = if bytes.starts_with(&urmqtt_cfg::MAGIC) {
        bytes
    } else if bytes.starts_with(&SLOT_MARKER) || bytes.starts_with(&DISK_MARKER) {
        bytes.get(16..).ok_or("slot is cut off")?
    } else {
        return Err("not a urmqtt-cfg blob or configuration slot".into());
    };
    let n = Blob::parse(blob).map_err(|e| e.to_string())?.len();
    make_slot(SlotKind::Boot, blob.get(..n).ok_or("blob is cut off")?)
        .ok_or_else(|| "the configuration does not fit in a slot".to_owned())
}

/// What to do with the configuration when the ESP is replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Policy {
    /// Keep the disk's configuration when it has a real one (not empty);
    /// otherwise use the new ESP's own. An update never silently replaces
    /// the customer's configuration with the one of the ESP it brings.
    Auto,
    /// Keep the disk's current configuration.
    Keep,
    /// Use the new ESP's own.
    Replace,
    /// Use this slot (a boot slot file).
    Set(Vec<u8>),
}

/// LATER-6 (ADR-320): whether `esp` is sealed for Secure Boot (its
/// `limine.conf` pins the configuration module) and whether its own slot is
/// the pinned one.
pub fn seal(esp: &[u8]) -> urmqtt_cfg::seal::Seal {
    use urmqtt_cfg::seal::check;
    match read(esp) {
        EspConfig::Configured { offset, .. } | EspConfig::Template { offset } => {
            let slot = slot_at(esp, offset).unwrap_or(&[]);
            check(esp, offset..offset + SLOT_SIZE, slot)
        }
        EspConfig::NoSlot => check(esp, 0..0, &[]),
    }
}

/// One line for `urmqtt-disk info` and the update commands.
pub fn describe_seal(esp: &[u8]) -> String {
    use urmqtt_cfg::seal::Seal;
    match seal(esp) {
        Seal::Open => "secure boot: not sealed (the configuration module has no hash: this ESP does not boot with Secure Boot enforced)".into(),
        Seal::Matches { .. } => "secure boot: sealed to its configuration (the module is pinned; the loaders must be signed by a key the firmware trusts)".into(),
        Seal::Differs { .. } => "secure boot: SEALED TO ANOTHER CONFIGURATION: the loader refuses this ESP (Blake2b hash ... does not match)".into(),
    }
}

/// Refuses to replace a sealed ESP (one that boots under Secure Boot) with
/// an unsealed one, unless `allow` (`--allow-unsealed`): on a machine with
/// Secure Boot enforced the new ESP's loader or Limine refuses it, and the
/// firmware has no other ESP to fall back to (an A/B switch changes which
/// partition is the ESP, so the trial never starts and nothing rolls back).
/// The official release images are unsigned and unsealed, so this is the
/// trap a routine update of a sealed disk would fall into (ADR-320).
pub fn keep_sealed(old: &[u8], new: &[u8], allow: bool) -> Result<Option<String>, String> {
    if !seal(old).sealed() || seal(new).sealed() {
        return Ok(None);
    }
    if allow {
        return Ok(Some(
            "WARNING: the disk's ESP is sealed for Secure Boot and the new one is not (--allow-unsealed): \
             it does not boot with Secure Boot enforced"
                .into(),
        ));
    }
    Err(
        "the disk's ESP is sealed for Secure Boot and the new one is not (an unsigned release image, or one built \
         without --sb-key): with Secure Boot enforced the firmware or Limine refuses it and there is no way back \
         short of the console. Stage an ESP signed and sealed with your key (scripts/sign-loaders.sh sign-iso ... \
         --esp-out; docs/DEPLOY.md, Secure Boot), or say --allow-unsealed if this machine runs without Secure Boot"
            .into(),
    )
}

/// The new ESP with its configuration slot decided; the second value says
/// what was done. A new ESP that is sealed for Secure Boot (ADR-320) takes
/// only the configuration it pins: anything else is refused here, because
/// the loader would refuse the disk.
pub fn carry_over(old: &[u8], new: Vec<u8>, policy: &Policy) -> Result<(Vec<u8>, String), String> {
    use urmqtt_cfg::seal::Seal;
    let sealed = seal(&new).sealed();
    let (out, what) = carry_over_open(old, new, policy)?;
    match seal(&out) {
        Seal::Differs { .. } => {
            let pin = urmqtt_cfg::seal::first_pin(&out, 0..0)
                .and_then(|p| p.get(..16))
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .unwrap_or_default();
            Err(format!(
                "the new ESP is sealed for Secure Boot to the configuration module with blake2b {pin}…, and the \
                 configuration it would get ({what}) is a different one: its loader would refuse to boot. Take the \
                 ESP's own with --replace-config, or seal an ESP for this configuration \
                 (scripts/sign-loaders.sh sign-iso ... --esp-out; docs/DEPLOY.md, Secure Boot)"
            ))
        }
        Seal::Matches { .. } if sealed => {
            Ok((out, format!("{what}; sealed for Secure Boot to it")))
        }
        _ => Ok((out, what)),
    }
}

fn carry_over_open(
    old: &[u8],
    mut new: Vec<u8>,
    policy: &Policy,
) -> Result<(Vec<u8>, String), String> {
    let old_cfg = read(old);
    let new_cfg = read(&new);
    let put = |new: &mut Vec<u8>, off: usize, slot: &[u8]| -> Result<(), String> {
        new.get_mut(off..off + SLOT_SIZE)
            .ok_or("the new ESP's slot is cut off")?
            .copy_from_slice(slot);
        Ok(())
    };
    let new_off = match &new_cfg {
        EspConfig::Configured { offset, .. } | EspConfig::Template { offset } => Some(*offset),
        EspConfig::NoSlot => None,
    };
    match policy {
        Policy::Set(slot) => {
            let off = new_off.ok_or("the new ESP has no configuration slot to put it in")?;
            let ok = slot_blob(slot, SlotKind::Boot).is_ok_and(|b| Blob::parse(b).is_ok());
            if !ok {
                return Err("--config: not a valid configuration slot".into());
            }
            put(&mut new, off, slot)?;
            Ok((new, "configuration set from --config".into()))
        }
        Policy::Replace => Ok((new, "configuration: the new ESP's own".into())),
        Policy::Keep | Policy::Auto => {
            // What the disk has that is worth keeping.
            let old_slot = match &old_cfg {
                EspConfig::Configured { empty, .. } if *empty && matches!(policy, Policy::Auto) => {
                    None
                }
                EspConfig::Configured { offset, .. } => Some(*offset),
                _ => None,
            };
            let Some(old_off) = old_slot else {
                return Ok((
                    new,
                    match (&old_cfg, matches!(policy, Policy::Keep)) {
                        (EspConfig::NoSlot, _) => {
                            "configuration: the disk had none (an old image): the new ESP's own"
                        }
                        (_, true) => "configuration: the disk had none to keep: the new ESP's own",
                        _ => {
                            "configuration: the disk's is empty or unconfigured: the new ESP's own"
                        }
                    }
                    .into(),
                ));
            };
            let Some(off) = new_off else {
                return Ok((
                    new,
                    "configuration: the new ESP has no configuration slot (an old image); the disk's cannot be carried over"
                        .into(),
                ));
            };
            let slot = slot_at(old, old_off)
                .ok_or("the old slot is cut off")?
                .to_vec();
            put(&mut new, off, &slot)?;
            let differs = match (&new_cfg, &old_cfg) {
                (
                    EspConfig::Configured { fingerprint: a, .. },
                    EspConfig::Configured { fingerprint: b, .. },
                ) => a != b,
                _ => false,
            };
            Ok((
                new,
                if differs {
                    "configuration: kept the disk's own (the new ESP carries a different one; --replace-config takes it)"
                } else {
                    "configuration: kept the disk's own"
                }
                .into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use urmqtt_cfg::blob::{DISK_MARKER, make_slot};
    use urmqtt_cfg::build::Builder;
    use urmqtt_cfg::fields::tag;

    fn slot(kind: SlotKind, port: u64) -> Vec<u8> {
        let mut b = Builder::new();
        b.uint(tag::NET_TLS_PORT, port).unwrap();
        make_slot(kind, &b.finish(false).unwrap()).unwrap()
    }

    fn esp(slot: &[u8]) -> Vec<u8> {
        let mut v = vec![0xEEu8; 4096];
        v.extend_from_slice(slot);
        v.extend_from_slice(&[0x11; 8192]);
        v
    }

    fn template() -> Vec<u8> {
        let mut s = slot(SlotKind::Boot, 8883);
        s[..16].copy_from_slice(&DISK_MARKER);
        s
    }

    #[test]
    fn classifies_the_three_cases() {
        assert!(matches!(
            read(&esp(&slot(SlotKind::Boot, 9000))),
            EspConfig::Configured { .. }
        ));
        assert!(matches!(
            read(&esp(&template())),
            EspConfig::Template { .. }
        ));
        assert_eq!(read(&[0u8; 8192]), EspConfig::NoSlot);
        assert!(describe(&read(&esp(&slot(SlotKind::Boot, 9000)))).contains("fingerprint"));
    }

    #[test]
    fn an_update_keeps_the_disks_configuration() {
        let old = esp(&slot(SlotKind::Boot, 9000));
        // The new ESP is the unconfigured template, or brings a configuration
        // of its own (a release's dev image): the disk's is kept either way.
        for new in [esp(&template()), esp(&slot(SlotKind::Boot, 9001))] {
            let (out, what) = carry_over(&old, new.clone(), &Policy::Auto).unwrap();
            assert!(what.contains("kept the disk's own"), "{what}");
            assert_eq!(read(&out), read(&old));
            // Everything but the slot is the new ESP's.
            assert_eq!(out.len(), new.len());
            assert_eq!(&out[..4096], &new[..4096]);
            assert_eq!(&out[4096 + SLOT_SIZE..], &new[4096 + SLOT_SIZE..]);
        }
        let (_, what) = carry_over(&old, esp(&slot(SlotKind::Boot, 9001)), &Policy::Auto).unwrap();
        assert!(what.contains("--replace-config"), "{what}");
    }

    #[test]
    fn a_disk_without_a_real_configuration_takes_the_new_esps() {
        let new = esp(&slot(SlotKind::Boot, 9001));
        let empty = {
            let e = Builder::new().finish(false).unwrap();
            esp(&make_slot(SlotKind::Boot, &e).unwrap())
        };
        for old in [esp(&template()), empty, vec![0u8; 8192]] {
            let (out, what) = carry_over(&old, new.clone(), &Policy::Auto).unwrap();
            assert_eq!(read(&out), read(&new), "{what}");
        }
    }

    #[test]
    fn replace_and_set_and_the_missing_cases() {
        let old = esp(&slot(SlotKind::Boot, 9000));
        let new = esp(&template());
        let (out, _) = carry_over(&old, new.clone(), &Policy::Replace).unwrap();
        assert!(matches!(read(&out), EspConfig::Template { .. }));
        let s = slot(SlotKind::Boot, 7000);
        let (out, _) = carry_over(&old, new.clone(), &Policy::Set(s.clone())).unwrap();
        assert_eq!(read(&out), read(&esp(&s)));
        assert!(carry_over(&old, new.clone(), &Policy::Set(vec![0; 10])).is_err());
        // Keep with nothing to keep leaves the new ESP's own.
        let (out, _) = carry_over(&esp(&template()), new.clone(), &Policy::Keep).unwrap();
        assert!(matches!(read(&out), EspConfig::Template { .. }));
        // An old-style new ESP has no slot to carry into.
        let (out, what) = carry_over(&old, vec![0u8; 4096], &Policy::Auto).unwrap();
        assert_eq!(out, vec![0u8; 4096]);
        assert!(what.contains("no configuration slot"), "{what}");
    }

    /// An ESP sealed to `slot` (ADR-320): its limine.conf pins the module.
    fn sealed_esp(own: &[u8], pinned_to: &[u8]) -> Vec<u8> {
        let hex: String = urmqtt_cfg::blake2b::hash(pinned_to)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut v = esp(own);
        let conf = format!("    module_path: boot():/boot/urmqtt.cfg#{hex}\n");
        v[100..100 + conf.len()].copy_from_slice(conf.as_bytes());
        v
    }

    #[test]
    fn a_sealed_esp_takes_only_the_configuration_it_pins() {
        let mine = slot(SlotKind::Boot, 9000);
        let other = slot(SlotKind::Boot, 9001);
        let sealed = sealed_esp(&mine, &mine);
        assert!(describe_seal(&sealed).contains("sealed to its configuration"));
        assert!(describe_seal(&esp(&mine)).contains("not sealed"));
        // The disk has the same configuration: kept, and said so.
        let (out, what) = carry_over(&esp(&mine), sealed.clone(), &Policy::Auto).unwrap();
        assert!(what.contains("sealed for Secure Boot"), "{what}");
        assert_eq!(out, sealed);
        // The disk has another real one: Auto, Keep and Set are refused, with the way out named.
        for p in [Policy::Auto, Policy::Keep, Policy::Set(other.clone())] {
            let e = carry_over(&esp(&other), sealed.clone(), &p).unwrap_err();
            assert!(
                e.contains("--replace-config") && e.contains("sign-iso"),
                "{p:?}: {e}"
            );
        }
        // --replace-config takes the ESP's own, which is the pinned one.
        let (out, _) = carry_over(&esp(&other), sealed.clone(), &Policy::Replace).unwrap();
        assert_eq!(out, sealed);
        // A fresh image (create) with the pinned configuration, and with another.
        assert!(
            carry_over(
                &[],
                sealed_esp(&template(), &mine),
                &Policy::Set(mine.clone())
            )
            .is_ok()
        );
        assert!(
            carry_over(
                &[],
                sealed_esp(&template(), &mine),
                &Policy::Set(other.clone())
            )
            .is_err()
        );
        // The installation image's template slot under a pin is not bootable as it is.
        let tpl = sealed_esp(&template(), &mine);
        assert!(carry_over(&esp(&template()), tpl.clone(), &Policy::Auto).is_err());
        assert!(describe_seal(&tpl).contains("ANOTHER CONFIGURATION"));
        // An open ESP behaves exactly as before.
        let (_, what) = carry_over(&esp(&other), esp(&mine), &Policy::Auto).unwrap();
        assert!(!what.contains("sealed"), "{what}");
    }

    /// A sealed disk (it boots under Secure Boot) does not take an unsealed ESP by accident: the
    /// firmware would refuse it and nothing rolls back. --allow-unsealed does it with a warning.
    #[test]
    fn a_sealed_disk_does_not_take_an_unsealed_esp_by_accident() {
        let mine = slot(SlotKind::Boot, 9000);
        let sealed = sealed_esp(&mine, &mine);
        let open = esp(&mine);
        let e = keep_sealed(&sealed, &open, false).unwrap_err();
        assert!(
            e.contains("--allow-unsealed") && e.contains("sign-iso"),
            "{e}"
        );
        let w = keep_sealed(&sealed, &open, true).unwrap().unwrap();
        assert!(w.contains("WARNING"), "{w}");
        // Sealed to sealed, open to anything, and an old disk without a slot: nothing to say.
        assert_eq!(keep_sealed(&sealed, &sealed, false), Ok(None));
        assert_eq!(keep_sealed(&open, &open, false), Ok(None));
        assert_eq!(keep_sealed(&open, &sealed, false), Ok(None));
        assert_eq!(keep_sealed(&[0u8; 8192], &open, false), Ok(None));
    }
}
