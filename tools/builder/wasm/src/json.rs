//! A very small JSON writer: the module answers the page with JSON text, and
//! the answers are flat enough that a dependency on a JSON library is not
//! worth carrying in the browser.

use std::fmt::Write as _;

/// A JSON string literal.
pub fn string(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(o, "\\u{:04x}", u32::from(c));
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// `["a","b"]`.
pub fn strings<S: AsRef<str>>(items: &[S]) -> String {
    let parts: Vec<String> = items.iter().map(|s| string(s.as_ref())).collect();
    format!("[{}]", parts.join(","))
}

/// An object under construction: `{"k":v,...}` with values already encoded.
#[derive(Default)]
pub struct Object {
    parts: Vec<String>,
}

impl Object {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a member whose value is already JSON.
    pub fn raw(mut self, key: &str, json: impl AsRef<str>) -> Self {
        self.parts
            .push(format!("{}:{}", string(key), json.as_ref()));
        self
    }

    pub fn str(self, key: &str, value: &str) -> Self {
        self.raw(key, string(value))
    }

    pub fn opt_str(self, key: &str, value: Option<&str>) -> Self {
        match value {
            Some(v) => self.str(key, v),
            None => self.raw(key, "null"),
        }
    }

    pub fn num(self, key: &str, value: u64) -> Self {
        self.raw(key, value.to_string())
    }

    pub fn bool(self, key: &str, value: bool) -> Self {
        self.raw(key, if value { "true" } else { "false" })
    }

    pub fn opt_bool(self, key: &str, value: Option<bool>) -> Self {
        match value {
            Some(v) => self.bool(key, v),
            None => self.raw(key, "null"),
        }
    }

    pub fn strs<S: AsRef<str>>(self, key: &str, items: &[S]) -> Self {
        self.raw(key, strings(items))
    }

    pub fn build(self) -> String {
        format!("{{{}}}", self.parts.join(","))
    }
}

/// `[a,b,c]` from already encoded values.
pub fn array(items: &[String]) -> String {
    format!("[{}]", items.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped() {
        assert_eq!(string("a\"b\\c\n\u{1}é"), "\"a\\\"b\\\\c\\n\\u0001é\"");
        assert_eq!(strings(&["x", "y"]), "[\"x\",\"y\"]");
    }

    #[test]
    fn objects_nest() {
        let o = Object::new()
            .str("a", "b")
            .num("n", 3)
            .bool("t", true)
            .opt_str("none", None)
            .raw("list", array(&["1".into(), "2".into()]))
            .build();
        assert_eq!(o, r#"{"a":"b","n":3,"t":true,"none":null,"list":[1,2]}"#);
    }
}
