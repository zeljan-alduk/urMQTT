//! The C ABI of the module. Everything crosses as a *buffer handle* (a `u32`,
//! 0 meaning "none" or "failed"): the page asks the module for a buffer
//! (`ub_buf_new`), writes into it through the module's memory at
//! `ub_buf_ptr`, calls a function with handles and reads the answer from the
//! returned handle the same way. Buffers live in a table inside the module and
//! the page frees them (`ub_buf_free`). No pointer ever crosses the boundary
//! as an argument, so the module needs no `unsafe` code at all; the only
//! unsafe-flavoured construct is the attribute that exports the symbol names.
//!
//! A function that fails returns 0; the reason is then in the buffer
//! `ub_error` returns (text, or for `ub_pack` a JSON array of problems).

#![allow(unsafe_code)] // `#[unsafe(no_mangle)]` on the exports; no unsafe blocks.

use std::cell::RefCell;

use crate::core::{self, Files};

#[derive(Default)]
pub(crate) struct Store {
    /// Handle `n` is `bufs[n - 1]`; freed slots are reused.
    pub(crate) bufs: Vec<Option<Vec<u8>>>,
    files: Files,
    last_error: Option<String>,
}

thread_local! {
    static STORE: RefCell<Store> = RefCell::new(Store::default());
}

pub(crate) fn with<R>(f: impl FnOnce(&mut Store) -> R) -> R {
    STORE.with(|s| f(&mut s.borrow_mut()))
}

impl Store {
    pub(crate) fn get(&self, h: u32) -> Option<&[u8]> {
        let i = usize::try_from(h).ok()?.checked_sub(1)?;
        self.bufs.get(i)?.as_deref()
    }

    fn put(&mut self, v: Vec<u8>) -> u32 {
        let i = match self.bufs.iter().position(Option::is_none) {
            Some(i) => {
                if let Some(slot) = self.bufs.get_mut(i) {
                    *slot = Some(v);
                }
                i
            }
            None => {
                self.bufs.push(Some(v));
                self.bufs.len() - 1
            }
        };
        u32::try_from(i + 1).unwrap_or(0)
    }

    fn text(&self, h: u32) -> Result<&str, String> {
        let b = self.get(h).ok_or("bad buffer handle")?;
        std::str::from_utf8(b).map_err(|_| "the text is not valid UTF-8".to_owned())
    }

    /// The bytes of an optional argument: handle 0 is "not given".
    fn opt(&self, h: u32) -> Result<Option<&[u8]>, String> {
        if h == 0 {
            Ok(None)
        } else {
            self.get(h)
                .map(Some)
                .ok_or_else(|| "bad buffer handle".to_owned())
        }
    }

    fn bytes(&self, h: u32) -> Result<&[u8], String> {
        self.get(h).ok_or_else(|| "bad buffer handle".to_owned())
    }

    /// Overwrites a buffer with zeros (a secret the module was handed).
    fn wipe(&mut self, h: u32) {
        if let Some(b) = usize::try_from(h)
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| self.bufs.get_mut(i))
            .and_then(Option::as_mut)
        {
            b.fill(0);
        }
    }

    fn done(&mut self, r: Result<Vec<u8>, String>) -> u32 {
        match r {
            Ok(v) => {
                self.last_error = None;
                self.put(v)
            }
            Err(e) => {
                self.last_error = Some(e);
                0
            }
        }
    }

    fn done_text(&mut self, r: Result<String, String>) -> u32 {
        self.done(r.map(String::into_bytes))
    }
}

/// The interface version (`core::ABI_VERSION`).
// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_abi_version() -> u32 {
    core::ABI_VERSION
}

/// The configuration format version this module reads and writes.
#[unsafe(no_mangle)]
pub extern "C" fn ub_format_version() -> u32 {
    u32::from(urmqtt_cfg::FORMAT_VERSION)
}

/// A zero-filled buffer of `len` bytes, or 0 if the memory cannot be had.
// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_buf_new(len: u32) -> u32 {
    let Ok(n) = usize::try_from(len) else {
        return 0;
    };
    let mut v: Vec<u8> = Vec::new();
    if v.try_reserve_exact(n).is_err() {
        return 0;
    }
    v.resize(n, 0);
    with(|s| s.put(v))
}

/// Where the buffer is in the module's memory (valid until the module's
/// memory grows or the buffer is freed; ask again after any call).
// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_buf_ptr(h: u32) -> u32 {
    with(|s| {
        s.get(h)
            .and_then(|b| u32::try_from(b.as_ptr() as usize).ok())
            .unwrap_or(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ub_buf_len(h: u32) -> u32 {
    with(|s| {
        s.get(h)
            .and_then(|b| u32::try_from(b.len()).ok())
            .unwrap_or(0)
    })
}

// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_buf_free(h: u32) {
    with(|s| {
        if let Some(slot) = usize::try_from(h)
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| s.bufs.get_mut(i))
        {
            *slot = None;
        }
    });
}

/// The reason the last failed call failed (0 if none). The text is consumed.
// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_error() -> u32 {
    with(|s| match s.last_error.take() {
        Some(e) => s.put(e.into_bytes()),
        None => 0,
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ub_schema() -> u32 {
    with(|s| s.done_text(Ok(core::schema())))
}

// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_default_toml() -> u32 {
    with(|s| s.done_text(Ok(core::default_toml())))
}

/// Forgets the files given to `ub_file_put`.
#[unsafe(no_mangle)]
pub extern "C" fn ub_file_clear() {
    with(|s| s.files.clear());
}

/// Makes `data` available to `ub_pack` under the name `name` (the name the
/// TOML uses for it). Returns 1, or 0 on a bad handle.
// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_file_put(name_h: u32, data_h: u32) -> u32 {
    with(|s| {
        let r = (|| {
            let name = s.text(name_h)?.to_owned();
            let data = s.bytes(data_h)?.to_vec();
            Ok::<_, String>((name, data))
        })();
        match r {
            Ok((name, data)) => {
                s.files.insert(name, data);
                1
            }
            Err(e) => {
                s.last_error = Some(e);
                0
            }
        }
    })
}

/// Packs the TOML in `toml_h` with the files given so far. `env_h` (0: none)
/// is the environment name, `now_unix` the clock (seconds), `sign_h` (0: none)
/// an Ed25519 PKCS#8 private key to sign with. Returns the blob.
// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_pack(toml_h: u32, env_h: u32, now_unix: f64, sign_h: u32) -> u32 {
    with(|s| {
        let r = (|| {
            let toml = s.text(toml_h)?;
            let env = match s.opt(env_h)? {
                Some(b) => Some(std::str::from_utf8(b).map_err(|_| "env is not UTF-8")?),
                None => None,
            };
            // Saturating casts: a negative or NaN clock is 0.
            core::pack(toml, &s.files, env, now_unix as u64, s.opt(sign_h)?)
        })();
        s.done(r)
    })
}

// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_blob_info(blob_h: u32) -> u32 {
    with(|s| {
        let r = s.bytes(blob_h).and_then(core::blob_info);
        s.done_text(r)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ub_describe_all(blob_h: u32) -> u32 {
    with(|s| {
        let r = s.bytes(blob_h).and_then(core::describe_all);
        s.done_text(r)
    })
}

// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_toml_to_json(text_h: u32) -> u32 {
    with(|s| {
        let r = s.text(text_h).and_then(core::toml_to_json);
        s.done_text(r)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ub_cert_info(pem_h: u32) -> u32 {
    with(|s| {
        let r = s.bytes(pem_h).and_then(core::cert_info);
        s.done_text(r)
    })
}

// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_key_info(pem_h: u32) -> u32 {
    with(|s| {
        let r = s.bytes(pem_h).and_then(core::key_info);
        s.done_text(r)
    })
}

/// Any of the three handles may be 0 (not chosen).
#[unsafe(no_mangle)]
pub extern "C" fn ub_cross_check(cert_h: u32, key_h: u32, ca_h: u32) -> u32 {
    with(|s| {
        let r = (|| {
            core::cross_check(
                s.opt(cert_h)?.unwrap_or_default(),
                s.opt(key_h)?.unwrap_or_default(),
                s.opt(ca_h)?.unwrap_or_default(),
            )
        })();
        s.done_text(r)
    })
}

// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_control_key(pem_h: u32) -> u32 {
    with(|s| {
        let r = s.bytes(pem_h).and_then(core::control_key);
        s.done_text(r)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ub_new_signing_key(seed_h: u32) -> u32 {
    with(|s| {
        let r = s.bytes(seed_h).and_then(core::new_signing_key);
        s.done_text(r)
    })
}

/// The stored hash (`pbkdf2-sha256$...`) of the password in `password_h`, with
/// the salt in `salt_h` (16 random bytes from the page) and `iterations`.
/// **The password buffer is overwritten with zeros before this returns**, so
/// the clear password does not stay in the module's memory.
// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_hash_password(password_h: u32, salt_h: u32, iterations: u32) -> u32 {
    with(|s| {
        let r = (|| core::hash_password(s.bytes(password_h)?, s.bytes(salt_h)?, iterations))();
        s.wipe(password_h);
        s.done_text(r)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ub_signing_key_info(pem_h: u32) -> u32 {
    with(|s| {
        let r = s.bytes(pem_h).and_then(core::signing_key_info);
        s.done_text(r)
    })
}

// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_iso_probe(iso_h: u32) -> u32 {
    with(|s| {
        let r = s.bytes(iso_h).and_then(core::iso_probe);
        s.done_text(r)
    })
}

/// Writes the blob into the ISO, in place; returns a one-line report.
#[unsafe(no_mangle)]
pub extern "C" fn ub_iso_configure(iso_h: u32, blob_h: u32) -> u32 {
    with(|s| {
        let r = (|| {
            let blob = s.bytes(blob_h)?.to_vec();
            let i = usize::try_from(iso_h)
                .ok()
                .and_then(|i| i.checked_sub(1))
                .ok_or("bad buffer handle")?;
            let iso = s
                .bufs
                .get_mut(i)
                .and_then(Option::as_mut)
                .ok_or("bad buffer handle")?;
            core::iso_configure(iso, &blob)
        })();
        s.done_text(r)
    })
}

// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_iso_verify(iso_h: u32) -> u32 {
    with(|s| {
        let r = s.bytes(iso_h).and_then(core::iso_verify);
        s.done_text(r)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ub_verify_release(pubkey_h: u32, sums_h: u32, sig_h: u32) -> u32 {
    with(|s| {
        let r = (|| core::verify_release(s.text(pubkey_h)?, s.bytes(sums_h)?, s.text(sig_h)?))();
        s.done_text(r)
    })
}

// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_minisign_key_id(pubkey_h: u32) -> u32 {
    with(|s| {
        let r = s.text(pubkey_h).and_then(core::minisign_key_id);
        s.done_text(r)
    })
}

/// SHA-256 of a buffer (32 bytes).
#[unsafe(no_mangle)]
pub extern "C" fn ub_sha256(h: u32) -> u32 {
    with(|s| {
        let r = s
            .bytes(h)
            .map(|b| urmqtt_config_tool::release::sha256(b).to_vec());
        s.done(r)
    })
}

/// BLAKE2b-512 of a buffer (64 bytes), the hash Limine checks.
// SAFETY: `no_mangle` only fixes the exported symbol name; the `ub_` prefix keeps it unique in the
// module, and the page (the only caller) passes buffer handles, never pointers.
#[unsafe(no_mangle)]
pub extern "C" fn ub_blake2b(h: u32) -> u32 {
    with(|s| {
        let r = s.bytes(h).map(|b| urmqtt_cfg::blake2b::hash(b).to_vec());
        s.done(r)
    })
}
