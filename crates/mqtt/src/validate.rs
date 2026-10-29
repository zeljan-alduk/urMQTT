//! UTF-8 string, topic name and topic filter rules (MQTT 3.1.1 §1.5.3, §4.7).

use crate::{Error, Limits};

/// MQTT UTF-8 string: valid UTF-8 (so no surrogates) and no U+0000.
pub(crate) fn utf8(bytes: &[u8]) -> Result<&str, Error> {
    let s = core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
    if s.contains('\0') {
        return Err(Error::InvalidUtf8);
    }
    Ok(s)
}

fn check_len_levels(t: &str, limits: &Limits) -> Result<(), Error> {
    if t.len() > usize::from(limits.max_topic_len) {
        return Err(Error::TopicTooLong);
    }
    if t.split('/').count() > usize::from(limits.max_topic_levels) {
        return Err(Error::TooManyTopicLevels);
    }
    Ok(())
}

/// Topic name in PUBLISH: non-empty, no wildcards.
pub fn is_valid_topic_name(t: &str) -> bool {
    !t.is_empty() && !t.contains(['+', '#'])
}

/// Topic filter in SUBSCRIBE/UNSUBSCRIBE: non-empty, `#` only as the whole
/// last level, `+` only as a whole level.
pub fn is_valid_topic_filter(f: &str) -> bool {
    if f.is_empty() {
        return false;
    }
    let mut levels = f.split('/').peekable();
    while let Some(level) = levels.next() {
        let last = levels.peek().is_none();
        if level.contains('#') && (level != "#" || !last) {
            return false;
        }
        if level.contains('+') && level != "+" {
            return false;
        }
    }
    true
}

pub(crate) fn topic_name<'a>(bytes: &'a [u8], limits: &Limits) -> Result<&'a str, Error> {
    let t = utf8(bytes)?;
    if !is_valid_topic_name(t) {
        return Err(Error::InvalidTopicName);
    }
    check_len_levels(t, limits)?;
    Ok(t)
}

pub(crate) fn topic_filter<'a>(bytes: &'a [u8], limits: &Limits) -> Result<&'a str, Error> {
    let f = utf8(bytes)?;
    if !is_valid_topic_filter(f) {
        return Err(Error::InvalidTopicFilter);
    }
    check_len_levels(f, limits)?;
    Ok(f)
}

/// Whether topic `name` matches `filter` (§4.7). Topics starting with `$`
/// are not matched by filters starting with a wildcard (§4.7.2).
pub fn topic_matches(filter: &str, name: &str) -> bool {
    if name.starts_with('$') && (filter.starts_with('+') || filter.starts_with('#')) {
        return false;
    }
    let mut f = filter.split('/');
    let mut n = name.split('/');
    loop {
        match (f.next(), n.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}
