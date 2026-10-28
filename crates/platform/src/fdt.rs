//! Minimal, panic-free Flattened Device Tree (DTB) reader.
//!
//! Supports what hardware discovery needs: walking nodes, reading
//! properties, `compatible` matching and `reg` decoding with the parent's
//! `#address-cells`/`#size-cells`. Every offset is bounds-checked; malformed
//! input yields [`FdtError`], never a panic.

use core::str;

const MAGIC: u32 = 0xd00d_feed;
const TOKEN_BEGIN_NODE: u32 = 1;
const TOKEN_END_NODE: u32 = 2;
const TOKEN_PROP: u32 = 3;
const TOKEN_NOP: u32 = 4;
const TOKEN_END: u32 = 9;
/// Deepest nesting accepted; real trees are < 10 levels deep.
const MAX_DEPTH: usize = 32;
/// Largest blob accepted, guards against absurd `totalsize` values.
pub const MAX_SIZE: usize = 16 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdtError {
    TooShort,
    BadMagic,
    BadVersion,
    BadLayout,
    Truncated,
    BadToken(u32),
    TooDeep,
    BadString,
}

fn be32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([
        *s.first()?,
        *s.get(1)?,
        *s.get(2)?,
        *s.get(3)?,
    ]))
}

const fn align4(x: usize) -> usize {
    (x + 3) & !3
}

/// A parsed, validated blob header.
#[derive(Clone, Copy)]
pub struct Fdt<'a> {
    structs: &'a [u8],
    strings: &'a [u8],
}

impl<'a> Fdt<'a> {
    /// Reads `totalsize` from a header so callers can bound the slice.
    pub fn total_size(header: &[u8]) -> Result<usize, FdtError> {
        if be32(header, 0).ok_or(FdtError::TooShort)? != MAGIC {
            return Err(FdtError::BadMagic);
        }
        let size = be32(header, 4).ok_or(FdtError::TooShort)? as usize;
        if !(40..=MAX_SIZE).contains(&size) {
            return Err(FdtError::BadLayout);
        }
        Ok(size)
    }

    pub fn new(blob: &'a [u8]) -> Result<Self, FdtError> {
        let total = Self::total_size(blob)?;
        let blob = blob.get(..total).ok_or(FdtError::Truncated)?;
        let field = |off| be32(blob, off).ok_or(FdtError::TooShort);
        let off_struct = field(8)? as usize;
        let off_strings = field(12)? as usize;
        let version = field(20)?;
        let last_compat = field(24)?;
        if version < 17 || last_compat > 17 {
            return Err(FdtError::BadVersion);
        }
        let size_strings = field(32)? as usize;
        let size_struct = field(36)? as usize;
        let range = |off: usize, len: usize| {
            off.checked_add(len)
                .and_then(|end| blob.get(off..end))
                .ok_or(FdtError::BadLayout)
        };
        Ok(Self {
            structs: range(off_struct, size_struct)?,
            strings: range(off_strings, size_strings)?,
        })
    }

    fn string_at(&self, off: usize) -> Result<&'a str, FdtError> {
        let tail = self.strings.get(off..).ok_or(FdtError::BadString)?;
        let end = tail
            .iter()
            .position(|&b| b == 0)
            .ok_or(FdtError::BadString)?;
        str::from_utf8(tail.get(..end).ok_or(FdtError::BadString)?).map_err(|_| FdtError::BadString)
    }

    /// Visits every node in document order. Stops at the first error.
    pub fn for_each_node<F>(&self, mut f: F) -> Result<(), FdtError>
    where
        F: FnMut(&Node<'a>) -> Visit,
    {
        // Cells of each open node, inherited by children as the "parent" cells.
        let mut cells = [(2u32, 1u32); MAX_DEPTH + 1];
        let mut depth = 0usize;
        let mut off = 0usize;
        loop {
            let token = be32(self.structs, off).ok_or(FdtError::Truncated)?;
            off += 4;
            match token {
                TOKEN_BEGIN_NODE => {
                    let tail = self.structs.get(off..).ok_or(FdtError::Truncated)?;
                    let len = tail
                        .iter()
                        .position(|&b| b == 0)
                        .ok_or(FdtError::Truncated)?;
                    let name = str::from_utf8(tail.get(..len).ok_or(FdtError::Truncated)?)
                        .map_err(|_| FdtError::BadString)?;
                    off = align4(off + len + 1);
                    if depth >= MAX_DEPTH {
                        return Err(FdtError::TooDeep);
                    }
                    let parent_cells = *cells.get(depth).ok_or(FdtError::TooDeep)?;
                    let node = Node {
                        fdt: *self,
                        name,
                        depth,
                        props_off: off,
                        parent_address_cells: parent_cells.0,
                        parent_size_cells: parent_cells.1,
                    };
                    let own = (
                        node.prop_u32("#address-cells")?.unwrap_or(2),
                        node.prop_u32("#size-cells")?.unwrap_or(1),
                    );
                    depth += 1;
                    if let Some(slot) = cells.get_mut(depth) {
                        *slot = own;
                    }
                    if f(&node) == Visit::Stop {
                        return Ok(());
                    }
                }
                TOKEN_END_NODE => {
                    depth = depth.checked_sub(1).ok_or(FdtError::BadToken(token))?;
                }
                TOKEN_PROP => {
                    let len = be32(self.structs, off).ok_or(FdtError::Truncated)? as usize;
                    off = align4(off.checked_add(8 + len).ok_or(FdtError::Truncated)?);
                    if off > self.structs.len() {
                        return Err(FdtError::Truncated);
                    }
                }
                TOKEN_NOP => {}
                TOKEN_END => return Ok(()),
                other => return Err(FdtError::BadToken(other)),
            }
        }
    }

    /// First node whose `compatible` list contains `compat`.
    pub fn find_compatible(&self, compat: &str) -> Result<Option<Node<'a>>, FdtError> {
        let mut found = None;
        let mut err = None;
        self.for_each_node(|n| match n.is_compatible(compat) {
            Ok(true) => {
                found = Some(*n);
                Visit::Stop
            }
            Ok(false) => Visit::Continue,
            Err(e) => {
                err = Some(e);
                Visit::Stop
            }
        })?;
        err.map_or(Ok(found), Err)
    }

    /// Node at an absolute path such as `/psci` or `/cpus`.
    pub fn find_path(&self, path: &str) -> Result<Option<Node<'a>>, FdtError> {
        const MAX_COMPONENTS: usize = 8;
        let mut parts = [""; MAX_COMPONENTS];
        let mut n_parts = 0usize;
        for c in path.split('/').filter(|c| !c.is_empty()) {
            *parts.get_mut(n_parts).ok_or(FdtError::TooDeep)? = c;
            n_parts += 1;
        }
        // `matched` = how many leading components the current branch matches.
        let mut matched = 0usize;
        let mut found = None;
        self.for_each_node(|n| {
            if n.depth == 0 {
                if n_parts == 0 {
                    found = Some(*n);
                    return Visit::Stop;
                }
                return Visit::Continue;
            }
            // A node at depth d replaces everything at depth >= d.
            matched = matched.min(n.depth - 1);
            if n.depth == matched + 1 && parts.get(matched) == Some(&n.name) {
                matched += 1;
                if matched == n_parts {
                    found = Some(*n);
                    return Visit::Stop;
                }
            }
            Visit::Continue
        })?;
        Ok(found)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visit {
    Continue,
    Stop,
}

/// A node, with enough context to decode its properties.
#[derive(Clone, Copy)]
pub struct Node<'a> {
    fdt: Fdt<'a>,
    pub name: &'a str,
    /// 0 for the root node.
    pub depth: usize,
    props_off: usize,
    pub parent_address_cells: u32,
    pub parent_size_cells: u32,
}

impl core::fmt::Debug for Node<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Node")
            .field("name", &self.name)
            .field("depth", &self.depth)
            .finish()
    }
}

impl<'a> Node<'a> {
    /// Raw value of property `name`, if present.
    pub fn prop(&self, name: &str) -> Result<Option<&'a [u8]>, FdtError> {
        let s = self.fdt.structs;
        let mut off = self.props_off;
        loop {
            let token = be32(s, off).ok_or(FdtError::Truncated)?;
            match token {
                TOKEN_PROP => {
                    let len = be32(s, off + 4).ok_or(FdtError::Truncated)? as usize;
                    let nameoff = be32(s, off + 8).ok_or(FdtError::Truncated)? as usize;
                    let start = off + 12;
                    let value = start
                        .checked_add(len)
                        .and_then(|end| s.get(start..end))
                        .ok_or(FdtError::Truncated)?;
                    if self.fdt.string_at(nameoff)? == name {
                        return Ok(Some(value));
                    }
                    off = align4(start + len);
                }
                TOKEN_NOP => off += 4,
                // Properties precede children; the first child or the end of
                // this node ends the search.
                TOKEN_BEGIN_NODE | TOKEN_END_NODE | TOKEN_END => return Ok(None),
                other => return Err(FdtError::BadToken(other)),
            }
        }
    }

    pub fn prop_u32(&self, name: &str) -> Result<Option<u32>, FdtError> {
        Ok(self.prop(name)?.and_then(|v| be32(v, 0)))
    }

    /// A property holding a single NUL-terminated string.
    pub fn prop_str(&self, name: &str) -> Result<Option<&'a str>, FdtError> {
        Ok(self
            .prop(name)?
            .map(|v| v.split(|&b| b == 0).next().unwrap_or(&[]))
            .and_then(|b| str::from_utf8(b).ok()))
    }

    /// Iterates the strings of a string-list property such as `compatible`.
    pub fn prop_strings(&self, name: &str) -> Result<impl Iterator<Item = &'a str>, FdtError> {
        let v = self.prop(name)?.unwrap_or(&[]);
        Ok(v.split(|&b| b == 0)
            .filter(|s| !s.is_empty())
            .filter_map(|s| str::from_utf8(s).ok()))
    }

    pub fn is_compatible(&self, compat: &str) -> Result<bool, FdtError> {
        Ok(self.prop_strings("compatible")?.any(|c| c == compat))
    }

    /// Node name without the unit address (`pl011@9000000` → `pl011`).
    pub fn base_name(&self) -> &'a str {
        self.name.split('@').next().unwrap_or(self.name)
    }

    /// The `index`-th (address, size) pair of `reg`.
    pub fn reg(&self, index: usize) -> Result<Option<(u64, u64)>, FdtError> {
        let Some(v) = self.prop("reg")? else {
            return Ok(None);
        };
        let ac = self.parent_address_cells as usize;
        let sc = self.parent_size_cells as usize;
        if ac > 2 || sc > 2 || ac == 0 {
            return Err(FdtError::BadLayout);
        }
        let stride = (ac + sc) * 4;
        let start = index.checked_mul(stride).ok_or(FdtError::BadLayout)?;
        let Some(entry) = v.get(start..start + stride) else {
            return Ok(None);
        };
        Ok(Some((
            read_cells(entry, 0, ac),
            read_cells(entry, ac * 4, sc),
        )))
    }
}

/// Reads `cells` big-endian u32 cells starting at byte `off` as one number.
pub fn read_cells(b: &[u8], off: usize, cells: usize) -> u64 {
    (0..cells).fold(0u64, |acc, i| {
        (acc << 32) | u64::from(be32(b, off + i * 4).unwrap_or(0))
    })
}
