//! A small JSON writer: objects, arrays, strings with escaping, integers,
//! tenths as decimals. Compact output on one line, so a log line holds the
//! whole document.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

#[derive(Default)]
pub struct Json {
    out: String,
    /// One entry per open container: whether it already has an element.
    stack: Vec<bool>,
}

impl Json {
    pub fn new() -> Self {
        Self::default()
    }

    fn sep(&mut self, key: Option<&str>) {
        if let Some(has) = self.stack.last_mut() {
            if *has {
                self.out.push(',');
            }
            *has = true;
        }
        if let Some(k) = key {
            self.string_raw(k);
            self.out.push(':');
        }
    }

    fn string_raw(&mut self, s: &str) {
        self.out.push('"');
        for c in s.chars() {
            match c {
                '"' => self.out.push_str("\\\""),
                '\\' => self.out.push_str("\\\\"),
                '\n' => self.out.push_str("\\n"),
                '\r' => self.out.push_str("\\r"),
                '\t' => self.out.push_str("\\t"),
                c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                    let _ = write!(self.out, "\\u{:04x}", c as u32);
                }
                c => self.out.push(c),
            }
        }
        self.out.push('"');
    }

    pub fn begin_obj(&mut self, key: Option<&str>) {
        self.sep(key);
        self.out.push('{');
        self.stack.push(false);
    }

    pub fn end_obj(&mut self) {
        self.stack.pop();
        self.out.push('}');
    }

    pub fn begin_arr(&mut self, key: Option<&str>) {
        self.sep(key);
        self.out.push('[');
        self.stack.push(false);
    }

    pub fn end_arr(&mut self) {
        self.stack.pop();
        self.out.push(']');
    }

    pub fn str(&mut self, key: Option<&str>, v: &str) {
        self.sep(key);
        self.string_raw(v);
    }

    pub fn u64(&mut self, key: Option<&str>, v: u64) {
        self.sep(key);
        let _ = write!(self.out, "{v}");
    }

    pub fn bool(&mut self, key: Option<&str>, v: bool) {
        self.sep(key);
        self.out.push_str(if v { "true" } else { "false" });
    }

    pub fn null(&mut self, key: Option<&str>) {
        self.sep(key);
        self.out.push_str("null");
    }

    /// A value in tenths as a decimal number (`123` is `12.3`).
    pub fn x10(&mut self, key: Option<&str>, v: u64) {
        self.sep(key);
        let _ = write!(self.out, "{}.{}", v / 10, v % 10);
    }

    pub fn opt_u64(&mut self, key: Option<&str>, v: Option<u64>) {
        match v {
            Some(v) => self.u64(key, v),
            None => self.null(key),
        }
    }

    pub fn opt_str(&mut self, key: Option<&str>, v: Option<&str>) {
        match v {
            Some(v) => self.str(key, v),
            None => self.null(key),
        }
    }

    /// The finished document (all containers must be closed).
    pub fn finish(self) -> String {
        self.out
    }

    pub fn is_balanced(&self) -> bool {
        self.stack.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nesting_and_commas() {
        let mut j = Json::new();
        j.begin_obj(None);
        j.str(Some("a"), "x");
        j.begin_arr(Some("list"));
        j.u64(None, 1);
        j.u64(None, 2);
        j.begin_obj(None);
        j.bool(Some("t"), true);
        j.null(Some("n"));
        j.end_obj();
        j.end_arr();
        j.x10(Some("f"), 123);
        j.opt_u64(Some("o"), None);
        j.opt_str(Some("s"), Some("v"));
        j.end_obj();
        assert!(j.is_balanced());
        assert_eq!(
            j.finish(),
            r#"{"a":"x","list":[1,2,{"t":true,"n":null}],"f":12.3,"o":null,"s":"v"}"#
        );
    }

    #[test]
    fn escaping() {
        let mut j = Json::new();
        j.begin_obj(None);
        j.str(Some("q\"k"), "a\"b\\c\nd\te\u{1}\u{7f}é");
        j.end_obj();
        assert_eq!(
            j.finish(),
            "{\"q\\\"k\":\"a\\\"b\\\\c\\nd\\te\\u0001\\u007fé\"}"
        );
    }

    #[test]
    fn empty_containers() {
        let mut j = Json::new();
        j.begin_arr(None);
        j.begin_obj(None);
        j.end_obj();
        j.begin_arr(None);
        j.end_arr();
        j.end_arr();
        assert_eq!(j.finish(), "[{},[]]");
    }
}
