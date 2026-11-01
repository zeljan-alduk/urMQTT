//! The lists of the `[plaintext]` section (P1, ADR-229): the grammar of their
//! entries, shared by the semantic check, the packer, the host tool, the
//! browser and the kernel.
//!
//! The blob stores each list as strings (see [`crate::fields::Item`]):
//!
//! | list | entry |
//! |---|---|
//! | `plaintext.allow_from` | `10.0.0.0/8` |
//! | `plaintext.users` | `sensor-1 pbkdf2-sha256$10000$<salt>$<key>` |
//! | `plaintext.ip_identities` | `10.0.1.0/24 plc` |
//!
//! In the TOML file `users` and `ip_identities` are arrays of tables
//! (`{ id = ..., password_hash = ... }`, `{ from = ..., id = ... }`); the
//! packer joins the two values with one space, and no value contains a space.

use crate::fields::MAX_IDENTITY_LEN;
use crate::net::{Cidr, CidrError};
use crate::passwd::{PasswdError, PasswordHash};

/// An identity (an MQTT user name, the anonymous identity, a network's id): it
/// becomes a topic level (`{id}`) and part of a session key, so it uses the
/// characters of the certificate identities and nothing else.
pub fn check_identity(id: &str) -> Result<(), &'static str> {
    if id.is_empty() {
        return Err("an identity must not be empty");
    }
    if id.len() > MAX_IDENTITY_LEN {
        return Err("an identity is at most 64 characters");
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err("an identity uses only the characters A-Z a-z 0-9 - _ . :");
    }
    Ok(())
}

/// An `allow_from` entry: a network, not `0.0.0.0/0` (which is spelled
/// `allow_from_anywhere` so that it is never an accident).
pub fn parse_allow(entry: &str) -> Result<Cidr, &'static str> {
    let c = Cidr::parse(entry).map_err(CidrError::msg)?;
    if c.prefix == 0 {
        return Err("0.0.0.0/0 would allow every address: say so with allow_from_anywhere = true");
    }
    Ok(c)
}

/// A `users` entry: the id and the parsed password hash.
pub fn parse_user(entry: &str) -> Result<(&str, PasswordHash), &'static str> {
    let (id, hash) = entry
        .split_once(' ')
        .ok_or("an account is an id and a password hash")?;
    check_identity(id)?;
    let hash = PasswordHash::parse(hash).map_err(PasswdError::msg)?;
    Ok((id, hash))
}

/// An `ip_identities` entry: the network and the identity it gets.
pub fn parse_ip_identity(entry: &str) -> Result<(Cidr, &str), &'static str> {
    let (net, id) = entry
        .split_once(' ')
        .ok_or("an entry is a network and an identity")?;
    let net = Cidr::parse(net).map_err(CidrError::msg)?;
    if net.prefix == 0 {
        return Err("0.0.0.0/0 is every address: use auth = \"anonymous\" for that");
    }
    check_identity(id)?;
    Ok((net, id))
}

/// The text of a `users` entry, from its two parts (the packer's side of
/// [`parse_user`]).
#[cfg(any(test, feature = "alloc"))]
pub fn user_entry(id: &str, password_hash: &str) -> alloc::string::String {
    alloc::format!("{id} {password_hash}")
}

/// The text of an `ip_identities` entry, from its two parts.
#[cfg(any(test, feature = "alloc"))]
pub fn ip_identity_entry(from: &str, id: &str) -> alloc::string::String {
    alloc::format!("{from} {id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passwd;

    fn hash() -> String {
        passwd::encode(b"pw", b"0123456789abcdef", 1000).unwrap()
    }

    #[test]
    fn identities_are_topic_safe() {
        for ok in ["a", "sensor-1", "A_b.c:d", &"x".repeat(64), "0"] {
            assert!(check_identity(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            &"x".repeat(65),
            "a/b",
            "a+b",
            "a#b",
            "$SYS",
            "a b",
            "é",
            "a\0",
            "*",
            "a*",
            "{id}",
            "a\n",
        ] {
            assert!(check_identity(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn allow_entries() {
        assert_eq!(parse_allow("10.0.0.0/8").unwrap().prefix, 8);
        assert_eq!(parse_allow("192.168.1.7/32").unwrap().prefix, 32);
        assert!(
            parse_allow("0.0.0.0/0")
                .unwrap_err()
                .contains("allow_from_anywhere")
        );
        assert!(
            parse_allow("10.0.0.1/8")
                .unwrap_err()
                .contains("below the prefix")
        );
        assert!(parse_allow("nonsense").is_err());
    }

    #[test]
    fn user_entries() {
        let e = user_entry("sensor-1", &hash());
        let (id, h) = parse_user(&e).unwrap();
        assert_eq!(id, "sensor-1");
        assert!(h.verify(b"pw"));
        assert!(parse_user("sensor-1").is_err());
        assert!(
            parse_user(&format!("sensor 1 {}", hash())).is_err(),
            "space in the id"
        );
        assert!(parse_user(&format!("bad/id {}", hash())).is_err());
        assert!(
            parse_user(&format!("sensor-1  {}", hash())).is_err(),
            "two spaces"
        );
        assert!(parse_user("sensor-1 plain-text-password").is_err());
        assert!(
            parse_user(&format!("sensor-1 {} x", hash())).is_err(),
            "a third part"
        );
    }

    #[test]
    fn ip_identity_entries() {
        let entry = ip_identity_entry("10.0.1.0/24", "plc");
        let (n, id) = parse_ip_identity(&entry).unwrap();
        assert_eq!((n.prefix, id), (24, "plc"));
        assert!(parse_ip_identity("0.0.0.0/0 plc").is_err());
        assert!(parse_ip_identity("10.0.1.0/24").is_err());
        assert!(parse_ip_identity("10.0.1.0/24 pl/c").is_err());
        assert!(parse_ip_identity("10.0.1.5/24 plc").is_err());
        assert!(parse_ip_identity("10.0.1.0/24 plc extra").is_err());
    }
}
