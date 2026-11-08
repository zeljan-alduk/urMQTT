//! The text values of the `[websocket]` section (ADR-272): the request path
//! and the allowed origins, shared by the semantic check, the packer, the host
//! tool, the browser and (through the check) the kernel.

/// `websocket.path`: what a client puts in its URL after the port. It must be
/// compared byte for byte with the request target, so it is kept to the
/// characters that need no percent-encoding.
pub fn check_path(p: &str) -> Result<(), &'static str> {
    if !p.starts_with('/') {
        return Err("must start with /");
    }
    if p.len() > crate::fields::MAX_WS_PATH_LEN {
        return Err("is at most 64 characters");
    }
    if !p
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'.' | b'_' | b'~'))
    {
        return Err("uses only the characters A-Z a-z 0-9 / - . _ ~");
    }
    if p.split('/').any(|seg| seg == "." || seg == "..") {
        return Err("must not contain . or .. segments");
    }
    Ok(())
}

/// A `websocket.origins` entry, as a browser sends it in `Origin` (RFC 6454
/// section 6.1): `http` or `https`, `://`, a lower-case host name, IPv4
/// address or bracketed IPv6 address, and a port only when it is not the
/// scheme's default (browsers leave 80 and 443 out, so an entry with them
/// could never match). No path, no trailing slash, no wildcard, not `null`.
pub fn check_origin(o: &str) -> Result<(), &'static str> {
    const FORM: &str = "an origin is scheme://host[:port], e.g. https://app.example.com (no path, no trailing slash)";
    if o.len() > crate::fields::MAX_WS_ORIGIN_LEN {
        return Err("an origin is at most 255 characters");
    }
    if o == "null" || o.contains('*') {
        return Err("an origin must name one site: null and wildcards are refused");
    }
    let (scheme, rest) = o.split_once("://").ok_or(FORM)?;
    let default_port = match scheme {
        "https" => "443",
        "http" => "80",
        _ => return Err("an origin's scheme is http or https"),
    };
    if rest.is_empty() || rest.contains('/') {
        return Err(FORM);
    }
    // The host, and what follows it.
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (addr, after) = v6.split_once(']').ok_or(FORM)?;
        if addr.is_empty()
            || !addr
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f' | b':' | b'.'))
        {
            return Err("an IPv6 origin is [lower-case hex and colons]");
        }
        match after {
            "" => (addr, None),
            p => (addr, Some(p.strip_prefix(':').ok_or(FORM)?)),
        }
    } else {
        let (h, p) = match rest.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        };
        if h.is_empty()
            || h.starts_with(['-', '.'])
            || h.ends_with(['-', '.'])
            || h.contains("..")
            || !h
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
        {
            return Err(
                "an origin's host is lower-case letters, digits, - and . (browsers send it lower-cased)",
            );
        }
        (h, p)
    };
    let _ = host;
    if let Some(p) = port {
        if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) || p.starts_with('0') {
            return Err("an origin's port is 1 to 65535");
        }
        if p.parse::<u32>().map_or(true, |n| n > 65_535) {
            return Err("an origin's port is 1 to 65535");
        }
        if p == default_port {
            return Err(
                "leave out the scheme's default port (443 for https, 80 for http): browsers do, so the entry would never match",
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        for ok in ["/mqtt", "/", "/a/b-c_d.e~f", "/ws/mqtt"] {
            assert_eq!(check_path(ok), Ok(()), "{ok}");
        }
        for bad in ["", "mqtt", "/mqtt?x", "/a b", "/a/../b", "/./x", "/é", "/%20"] {
            assert!(check_path(bad).is_err(), "{bad}");
        }
        assert!(check_path(&format!("/{}", "a".repeat(64))).is_err());
    }

    #[test]
    fn origins() {
        for ok in [
            "https://app.example.com",
            "http://localhost:3000",
            "https://10.0.0.5:8443",
            "https://[2001:db8::1]",
            "https://[::1]:8443",
            "http://a",
        ] {
            assert_eq!(check_origin(ok), Ok(()), "{ok}");
        }
        for bad in [
            "",
            "null",
            "*",
            "https://*.example.com",
            "app.example.com",
            "ftp://x",
            "wss://x",
            "https://",
            "https://App.example.com",
            "https://app.example.com/",
            "https://app.example.com/path",
            "https://app.example.com:443",
            "http://app.example.com:80",
            "https://x:0",
            "https://x:65536",
            "https://x:08",
            "https://x:",
            "https://-x",
            "https://x..y",
            "https://[]",
            "https://[::1]x",
            "https://x y",
        ] {
            assert!(check_origin(bad).is_err(), "{bad}");
        }
    }
}
