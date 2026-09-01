//! Canonical Neural ICE release-manifest v1 reader and delta planner.
//!
//! This is the CoreOS side of ONE contract. The exact Fabric producer inputs,
//! schema, consumer pack, and generated vectors are copied and hash-pinned under
//! `tests/fixtures/release-manifest-v1/producer/`; any drift is a test failure
//! rather than a field surprise.
//!
//! What this module does: bounded strict JSON in, one normalized value out,
//! canonical bytes and a digest that depend on the MEANING of the manifest and
//! not on how the producer happened to format it, plus a pure classification of
//! the transition between an installed and a candidate manifest.
//!
//! What this module deliberately does NOT do — and must never grow: signature
//! verification, download, USB/LAN carriage, staging, activation, `bootc`,
//! reboot, entitlement evaluation, or channel policy. `required_entitlement` is
//! carried as a signed fact for a later gate; reading it is not enforcing it.
//!
//! The canonical digest is computed IN-PROCESS (`sha2`), not by shelling out to
//! coreutils like the other artifact hashes in this binary. That difference is
//! deliberate: this digest decides anti-rollback, so a `sha256sum` planted on
//! PATH could otherwise collapse two different manifests onto one digest and
//! turn a rollback into a no-op. Signature crypto is still the image's pinned
//! cosign — nothing here verifies a signature.
//!
//! Refusal is a first-class plan result, not an exception at the boundary: a
//! caller that ignores errors still gets `Classification::Refusal`, never a
//! silently-permissive plan.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use sha2::{Digest, Sha256};

pub(crate) const SCHEMA: &str = "neural-ice-release-manifest-v1";
pub(crate) const PLAN_SCHEMA: &str = "neural-ice-release-plan-v1";

pub(crate) const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_COMPONENTS: usize = 256;
const MAX_CONTENT: usize = 1024;
const MAX_EVIDENCE: usize = 2048;
const MAX_RESTART_SCOPE: usize = 32;
const MAX_REQUIRED_CONTRACTS: usize = 128;

/// `Number.MAX_SAFE_INTEGER`. The manifest crosses a JSON boundary shared with
/// producers that have no 64-bit integer type; anything above this is not a
/// value both sides can agree on.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Structural nesting cap. A v1 manifest is at most 4 levels deep, so this only
/// exists to keep a hostile input from driving the parser's recursion; it can
/// never reject a manifest that `normalize` would have accepted.
const MAX_DEPTH: usize = 64;

/// `[a-z0-9]` + up to 126 inner bytes + `[a-z0-9]`.
const MAX_IDENTIFIER_BYTES: usize = 128;
/// The unit STEM is bounded; the `.service`-style suffix is extra.
const MAX_UNIT_STEM_BYTES: usize = 128;

const UNIT_SUFFIXES: &[&str] = &["service", "socket", "target", "timer", "path", "mount"];

const EVIDENCE_KINDS: &[&str] = &[
    "attestation",
    "bom",
    "channel-snapshot",
    "lockfile",
    "receipt",
];

const TOP_KEYS: &[&str] = &[
    "bundle_seq",
    "compatibility",
    "components",
    "content",
    "evidence",
    "hardware_target",
    "host",
    "release_id",
    "schema",
];
const COMPATIBILITY_KEYS: &[&str] = &["minimum_reader", "required_contracts"];
const PAYLOAD_KEYS: &[&str] = &[
    "contract",
    "digest",
    "reboot_required",
    "repository",
    "required_entitlement",
    "restart_scope",
];
const COMPONENT_KEYS: &[&str] = &[
    "component_id",
    "contract",
    "digest",
    "reboot_required",
    "repository",
    "required_entitlement",
    "restart_scope",
];
const CONTENT_KEYS: &[&str] = &[
    "content_id",
    "contract",
    "digest",
    "media_type",
    "reboot_required",
    "repository",
    "required_entitlement",
    "restart_scope",
];
const EVIDENCE_KEYS: &[&str] = &["digest", "kind"];

/// The supplied bytes cannot be a release-manifest v1 authority.
///
/// The message is part of the contract: it is reproduced verbatim inside a
/// refusal plan and compared byte-for-byte against Fabric's own text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal(pub(crate) String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn refuse<T>(reason: impl Into<String>) -> Result<T, Refusal> {
    Err(Refusal(reason.into()))
}

// ---------------------------------------------------------------------------
// Strict bounded JSON
// ---------------------------------------------------------------------------
//
// Hand-written rather than delegated to a general-purpose reader because the
// strictness IS the contract: duplicate keys must refuse instead of last-wins,
// a float must refuse instead of truncating, and an out-of-range integer must
// refuse instead of degrading to a float. Those are the properties that make
// two independent implementations agree on one digest.

#[derive(Debug, Clone, PartialEq, Eq)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

/// Parse strict UTF-8 JSON with no duplicate keys, no floats, no non-finite
/// constants and no trailing data.
fn parse_json(data: &[u8]) -> Result<Json, Refusal> {
    // Strict UTF-8 first: a lossy decode would let invalid bytes reach a regex
    // check as U+FFFD and quietly pass or fail for the wrong reason.
    if std::str::from_utf8(data).is_err() {
        return refuse("release manifest is not strict UTF-8 JSON: invalid UTF-8 encoding");
    }
    let mut parser = Parser {
        bytes: data,
        pos: 0,
    };
    let value = parser.value(0)?;
    parser.skip_whitespace();
    if parser.pos != parser.bytes.len() {
        return refuse("release manifest is not strict UTF-8 JSON: extra data after the value");
    }
    Ok(value)
}

fn syntax<T>(detail: &str) -> Result<T, Refusal> {
    refuse(format!(
        "release manifest is not strict UTF-8 JSON: {detail}"
    ))
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    /// Only the four JSON whitespace bytes; anything else is data.
    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn eat(&mut self, literal: &str) -> bool {
        let bytes = literal.as_bytes();
        if self.bytes[self.pos..].starts_with(bytes) {
            self.pos += bytes.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, Refusal> {
        if depth > MAX_DEPTH {
            return syntax("nesting exceeds the depth limit");
        }
        self.skip_whitespace();
        match self.peek() {
            None => syntax("unexpected end of input"),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') if self.eat("true") => Ok(Json::Bool(true)),
            Some(b'f') if self.eat("false") => Ok(Json::Bool(false)),
            Some(b'n') if self.eat("null") => Ok(Json::Null),
            // Python's json accepts these by default, so a producer can emit
            // them; the contract rejects them explicitly rather than by luck.
            Some(b'N') if self.eat("NaN") => refuse("non-finite JSON number is forbidden: NaN"),
            Some(b'I') if self.eat("Infinity") => {
                refuse("non-finite JSON number is forbidden: Infinity")
            }
            Some(b'-') if self.bytes[self.pos..].starts_with(b"-Infinity") => {
                self.pos += b"-Infinity".len();
                refuse("non-finite JSON number is forbidden: -Infinity")
            }
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(byte) => syntax(&format!("unexpected byte 0x{byte:02x}")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, Refusal> {
        self.pos += 1; // '{'
        let mut map = BTreeMap::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return syntax("expected an object key");
            }
            let key = self.string()?;
            self.skip_whitespace();
            if self.peek() != Some(b':') {
                return syntax("expected ':' after an object key");
            }
            self.pos += 1;
            let value = self.value(depth + 1)?;
            // Last-wins would let a producer show one manifest to a reviewer and
            // another to the device, under one signature.
            if map.insert(key.clone(), value).is_some() {
                return refuse(format!("duplicate JSON object key: {key}"));
            }
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(map));
                }
                _ => return syntax("expected ',' or '}' in an object"),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, Refusal> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return syntax("expected ',' or ']' in an array"),
            }
        }
    }

    fn string(&mut self) -> Result<String, Refusal> {
        self.pos += 1; // '"'
        let mut out = String::new();
        loop {
            let byte = match self.peek() {
                None => return syntax("unterminated string"),
                Some(byte) => byte,
            };
            match byte {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    out.push(self.escape()?);
                }
                // Raw control characters are invalid JSON in strict mode.
                0x00..=0x1f => return syntax("unescaped control character in a string"),
                _ => {
                    // The whole input was UTF-8 validated, so the next character
                    // boundary is well defined.
                    let rest = std::str::from_utf8(&self.bytes[self.pos..]).map_err(|_| {
                        Refusal(
                            "release manifest is not strict UTF-8 JSON: invalid UTF-8 encoding"
                                .to_owned(),
                        )
                    })?;
                    let ch = match rest.chars().next() {
                        Some(ch) => ch,
                        None => return syntax("unterminated string"),
                    };
                    self.pos += ch.len_utf8();
                    out.push(ch);
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, Refusal> {
        let byte = match self.peek() {
            None => return syntax("unterminated escape sequence"),
            Some(byte) => byte,
        };
        self.pos += 1;
        Ok(match byte {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let first = self.hex4()?;
                let code = if (0xd800..0xdc00).contains(&first) {
                    // High surrogate: a low surrogate must follow.
                    if !self.eat("\\u") {
                        return syntax("unpaired UTF-16 surrogate in a string");
                    }
                    let second = self.hex4()?;
                    if !(0xdc00..0xe000).contains(&second) {
                        return syntax("unpaired UTF-16 surrogate in a string");
                    }
                    0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                } else if (0xdc00..0xe000).contains(&first) {
                    return syntax("unpaired UTF-16 surrogate in a string");
                } else {
                    first
                };
                match char::from_u32(code) {
                    Some(ch) => ch,
                    None => return syntax("invalid \\u escape in a string"),
                }
            }
            _ => return syntax("invalid escape sequence in a string"),
        })
    }

    fn hex4(&mut self) -> Result<u32, Refusal> {
        if self.pos + 4 > self.bytes.len() {
            return syntax("truncated \\u escape in a string");
        }
        let mut code = 0u32;
        for _ in 0..4 {
            let byte = self.bytes[self.pos];
            let digit = match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'a'..=b'f' => u32::from(byte - b'a') + 10,
                b'A'..=b'F' => u32::from(byte - b'A') + 10,
                _ => return syntax("invalid \\u escape in a string"),
            };
            code = code * 16 + digit;
            self.pos += 1;
        }
        Ok(code)
    }

    fn number(&mut self) -> Result<Json, Refusal> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let int_start = self.pos;
        match self.peek() {
            // No leading zeros: `0` alone, or a non-zero first digit.
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return syntax("invalid number"),
        }
        let digits = self.pos - int_start;

        let mut fractional = false;
        if self.peek() == Some(b'.') {
            fractional = true;
            self.pos += 1;
            let frac_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == frac_start {
                return syntax("invalid number");
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            fractional = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            let exp_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
            if self.pos == exp_start {
                return syntax("invalid number");
            }
        }

        let literal = std::str::from_utf8(&self.bytes[start..self.pos]).unwrap_or_default();
        if fractional {
            // `1.0` and `1e0` are floats even though they are integral: the
            // producer's serializer, not its intent, decides the digest.
            return refuse(format!(
                "floating-point JSON number is forbidden: {literal}"
            ));
        }
        // Bounded before conversion, so an absurd literal cannot overflow i64
        // and cannot silently become a float the way a general reader would.
        if digits > 16 {
            return refuse("JSON integer exceeds the safe integer range");
        }
        match literal.parse::<i64>() {
            Ok(value) => Ok(Json::Int(value)),
            Err(_) => refuse("JSON integer exceeds the safe integer range"),
        }
    }
}

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// `^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$` — also `hardware_target` and
/// `contract`, which share the pattern in the schema.
///
/// The bound is 1 + 126 + 1 = 128 bytes. Reading it as 127 silently rejects a
/// manifest Fabric signs and accepts.
fn is_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_IDENTIFIER_BYTES {
        return false;
    }
    let alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !alnum(bytes[0]) || !alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes
        .iter()
        .all(|&b| alnum(b) || b == b'.' || b == b'_' || b == b'-')
}

/// `^[A-Z][A-Z0-9-]{0,63}$`
fn is_entitlement(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 || !bytes[0].is_ascii_uppercase() {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
}

/// `^sha256:[0-9a-f]{64}$`
fn is_digest(value: &str) -> bool {
    match value.strip_prefix("sha256:") {
        Some(hex) => {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

/// One path segment of a repository: `[a-z0-9]+([._-][a-z0-9]+)*`.
fn is_repository_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let mut previous_separator = true; // a separator may not lead
    for &byte in bytes {
        let alnum = byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if alnum {
            previous_separator = false;
        } else if matches!(byte, b'.' | b'_' | b'-') {
            // Exactly one separator between runs, and never trailing.
            if previous_separator {
                return false;
            }
            previous_separator = true;
        } else {
            return false;
        }
    }
    !previous_separator
}

fn is_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    let alnum = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    alnum(bytes[0])
        && alnum(bytes[bytes.len() - 1])
        && bytes.iter().all(|&byte| alnum(byte) || byte == b'-')
}

fn is_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && !port.starts_with('0')
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|value| value <= 65_535)
}

fn ipv6_hextet(text: &str) -> Option<u16> {
    if text.is_empty()
        || text.len() > 4
        || (text.len() > 1 && text.starts_with('0'))
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    u16::from_str_radix(text, 16).ok()
}

/// Validate Fabric's published lowercase RFC 5952 hextet language directly.
///
/// In particular, this deliberately does not compare against `Ipv6Addr`'s
/// display output: Rust renders IPv4-mapped addresses with dotted quads, while
/// the signed contract admits only compressed hexadecimal hextets.
fn is_canonical_ipv6_text(text: &str) -> bool {
    let (left, right, compressed) = if let Some((left, right)) = text.split_once("::") {
        if left.contains("::") || right.contains("::") {
            return false;
        }
        (left, right, true)
    } else {
        (text, "", false)
    };

    let parse_side = |side: &str| -> Option<Vec<u16>> {
        if side.is_empty() {
            return Some(Vec::new());
        }
        side.split(':').map(ipv6_hextet).collect()
    };
    let Some(left_groups) = parse_side(left) else {
        return false;
    };
    let Some(right_groups) = parse_side(right) else {
        return false;
    };
    let explicit = left_groups.len() + right_groups.len();
    let compressed_length = if compressed {
        let Some(length) = 8_usize.checked_sub(explicit) else {
            return false;
        };
        if length < 2 {
            return false;
        }
        length
    } else {
        if explicit != 8 {
            return false;
        }
        0
    };

    let mut groups = left_groups.clone();
    groups.extend(std::iter::repeat_n(0, compressed_length));
    groups.extend(right_groups);

    let mut best_start = 0;
    let mut best_length = 0;
    let mut index = 0;
    while index < groups.len() {
        if groups[index] != 0 {
            index += 1;
            continue;
        }
        let start = index;
        while index < groups.len() && groups[index] == 0 {
            index += 1;
        }
        let length = index - start;
        if length > best_length {
            best_start = start;
            best_length = length;
        }
    }

    if best_length < 2 {
        !compressed
    } else {
        compressed && left_groups.len() == best_start && compressed_length == best_length
    }
}

/// Validate one canonical generic OCI registry authority.
///
/// The accepted forms match Fabric exactly: lowercase DNS, canonical IPv4, or
/// bracketed canonical IPv6, each optionally followed by a canonical port.
fn is_registry_authority(value: &str) -> bool {
    if value.bytes().any(|byte| b"/@?#".contains(&byte)) {
        return false;
    }

    if let Some(bracketed) = value.strip_prefix('[') {
        let Some((literal, suffix)) = bracketed.split_once(']') else {
            return false;
        };
        let canonical = is_canonical_ipv6_text(literal);
        return canonical && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(is_port));
    }

    if value.matches(':').count() > 1 {
        return false;
    }
    let (host, port) = value
        .rsplit_once(':')
        .map_or((value, None), |(host, port)| (host, Some(port)));
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let valid_host = if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        host.parse::<Ipv4Addr>()
            .is_ok_and(|address| address.to_string() == host)
    } else {
        (host == "localhost" || host.contains('.')) && host.split('.').all(is_dns_label)
    };
    valid_host && port.is_none_or(is_port)
}

fn registry_authority(value: Option<&str>, context: &str) -> Result<String, Refusal> {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return refuse(format!("{context} is required"));
    };
    if !is_registry_authority(value) {
        return refuse(format!("{context} is malformed"));
    }
    Ok(value.to_owned())
}

fn repository(value: &Json, context: &str) -> Result<String, Refusal> {
    let Json::Str(repository) = value else {
        return refuse(format!("{context} has an invalid value"));
    };
    let Some((authority, path)) = repository.split_once('/') else {
        return refuse(format!("{context} has an invalid value"));
    };
    let Some(rest) = path
        .strip_prefix("neural-ice/")
        .or_else(|| path.strip_prefix("vendor/"))
    else {
        return refuse(format!("{context} has an invalid value"));
    };
    if rest.is_empty() || !rest.split('/').all(is_repository_segment) {
        return refuse(format!("{context} has an invalid value"));
    }
    if !is_registry_authority(authority) {
        return refuse(format!("{context} has an invalid value"));
    }
    Ok(repository.clone())
}

/// `^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$`
fn is_media_type(value: &str) -> bool {
    let Some((kind, subtype)) = value.split_once('/') else {
        return false;
    };
    let valid = |part: &str, max: usize| {
        let bytes = part.as_bytes();
        if bytes.is_empty() || bytes.len() > max {
            return false;
        }
        if !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()) {
            return false;
        }
        bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"!#$&^_.+-".contains(&b))
    };
    valid(kind, 64) && valid(subtype, 127)
}

/// `^[A-Za-z0-9](?:[A-Za-z0-9:_.@-]{0,126}[A-Za-z0-9])?\.(?:service|socket|target|timer|path|mount)$`
///
/// The length bound and the "ends alphanumeric" constraint both apply to the
/// STEM, not to the whole unit name. Testing the last byte of the full name
/// always sees the suffix's own letter, so `foo-.service` — which Fabric
/// rejects — slips through; and bounding the full name at 128 rejects a
/// legitimate 136-byte unit whose stem is exactly 128.
fn is_unit_stem(stem: &str) -> bool {
    let bytes = stem.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_UNIT_STEM_BYTES {
        return false;
    }
    let alnum = |b: u8| b.is_ascii_alphanumeric();
    if !alnum(bytes[0]) || !alnum(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.iter().all(|&b| alnum(b) || b":_.@-".contains(&b))
}

fn is_systemd_unit(value: &str) -> bool {
    UNIT_SUFFIXES.iter().any(|suffix| {
        value
            .strip_suffix(suffix)
            .is_some_and(|stem| stem.ends_with('.') && is_unit_stem(&stem[..stem.len() - 1]))
    })
}

fn field<'a>(object: &'a BTreeMap<String, Json>, key: &str) -> &'a Json {
    // Only ever called after `strict_object` proved the key set is exact.
    object
        .get(key)
        .expect("strict_object guarantees the key is present")
}

fn strict_object<'a>(
    value: &'a Json,
    keys: &[&str],
    context: &str,
) -> Result<&'a BTreeMap<String, Json>, Refusal> {
    let Json::Object(object) = value else {
        return refuse(format!("{context} must be an object"));
    };
    // Missing before unknown, and both sorted: the message is compared verbatim.
    let missing: Vec<&str> = keys
        .iter()
        .filter(|key| !object.contains_key(**key))
        .copied()
        .collect();
    if !missing.is_empty() {
        return refuse(format!(
            "{context} is missing fields: {}",
            missing.join(", ")
        ));
    }
    let unknown: Vec<&str> = object
        .keys()
        .filter(|key| !keys.contains(&key.as_str()))
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        return refuse(format!(
            "{context} has unknown fields: {}",
            unknown.join(", ")
        ));
    }
    Ok(object)
}

fn bounded_list<'a>(value: &'a Json, limit: usize, context: &str) -> Result<&'a [Json], Refusal> {
    let Json::Array(items) = value else {
        return refuse(format!("{context} must be an array"));
    };
    if items.len() > limit {
        return refuse(format!(
            "{context} exceeds its cardinality limit of {limit}"
        ));
    }
    Ok(items)
}

fn string(value: &Json, valid: fn(&str) -> bool, context: &str) -> Result<String, Refusal> {
    match value {
        Json::Str(text) if valid(text) => Ok(text.clone()),
        _ => refuse(format!("{context} has an invalid value")),
    }
}

fn safe_uint(value: &Json, context: &str, positive: bool) -> Result<u64, Refusal> {
    let Json::Int(number) = value else {
        return refuse(format!("{context} must be an integer"));
    };
    let minimum = i64::from(positive);
    if *number < minimum || *number > MAX_SAFE_INTEGER {
        return refuse(format!("{context} is outside the safe integer range"));
    }
    Ok(*number as u64)
}

fn boolean(value: &Json, context: &str) -> Result<bool, Refusal> {
    match value {
        Json::Bool(flag) => Ok(*flag),
        _ => refuse(format!("{context} must be a boolean")),
    }
}

fn restart_scope(value: &Json, context: &str) -> Result<Vec<String>, Refusal> {
    let items = bounded_list(value, MAX_RESTART_SCOPE, context)?;
    let entry_context = format!("{context} entry");
    let mut units = Vec::with_capacity(items.len());
    for item in items {
        units.push(string(item, is_systemd_unit, &entry_context)?);
    }
    let unique: BTreeSet<&String> = units.iter().collect();
    if unique.len() != units.len() {
        return refuse(format!("{context} contains duplicate units"));
    }
    units.sort();
    Ok(units)
}

/// The fields every payload carries, in the contract's validation order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Payload {
    pub(crate) contract: String,
    pub(crate) digest: String,
    pub(crate) reboot_required: bool,
    pub(crate) repository: String,
    pub(crate) required_entitlement: String,
    pub(crate) restart_scope: Vec<String>,
}

impl Payload {
    /// True when a replacement changed only the digest — the definition of a
    /// transition that does not need an explicit host delta.
    fn differs_only_by_digest(&self, other: &Self) -> bool {
        self.contract == other.contract
            && self.reboot_required == other.reboot_required
            && self.repository == other.repository
            && self.required_entitlement == other.required_entitlement
            && self.restart_scope == other.restart_scope
    }
}

fn payload_common(object: &BTreeMap<String, Json>, context: &str) -> Result<Payload, Refusal> {
    // Order matters: with several faults in one payload, the reported one must
    // be the same on both sides of the contract.
    let repository = repository(
        field(object, "repository"),
        &format!("{context}.repository"),
    )?;
    let digest = string(
        field(object, "digest"),
        is_digest,
        &format!("{context}.digest"),
    )?;
    let contract = string(
        field(object, "contract"),
        is_identifier,
        &format!("{context}.contract"),
    )?;
    let required_entitlement = string(
        field(object, "required_entitlement"),
        is_entitlement,
        &format!("{context}.required_entitlement"),
    )?;
    let reboot_required = boolean(
        field(object, "reboot_required"),
        &format!("{context}.reboot_required"),
    )?;
    let restart_scope = restart_scope(
        field(object, "restart_scope"),
        &format!("{context}.restart_scope"),
    )?;
    Ok(Payload {
        contract,
        digest,
        reboot_required,
        repository,
        required_entitlement,
        restart_scope,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Component {
    pub(crate) component_id: String,
    pub(crate) payload: Payload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Content {
    pub(crate) content_id: String,
    pub(crate) media_type: String,
    pub(crate) payload: Payload,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Evidence {
    pub(crate) digest: String,
    pub(crate) kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Compatibility {
    pub(crate) minimum_reader: u64,
    pub(crate) required_contracts: Vec<String>,
}

/// A normalized manifest: array order and object-key order are gone, so two
/// producers that mean the same thing hash the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub(crate) bundle_seq: u64,
    pub(crate) compatibility: Compatibility,
    pub(crate) components: Vec<Component>,
    pub(crate) content: Vec<Content>,
    pub(crate) evidence: Vec<Evidence>,
    pub(crate) hardware_target: String,
    pub(crate) host: Payload,
    pub(crate) release_id: String,
}

/// A parsed manifest with the bytes and digest the whole system agrees on.
#[derive(Debug, Clone)]
pub(crate) struct ParsedManifest {
    pub(crate) value: Manifest,
    /// The exact bytes the digest covers, i.e. the bytes a producer signs.
    /// The planner only needs the digest, but dropping this would remove the
    /// only way to prove byte-for-byte agreement with Fabric's canonical form,
    /// which is what the golden vectors assert.
    #[allow(dead_code, reason = "asserted byte-for-byte by the golden vectors")]
    pub(crate) canonical_bytes: Vec<u8>,
    pub(crate) digest: String,
}

fn compatibility(value: &Json) -> Result<Compatibility, Refusal> {
    let object = strict_object(value, COMPATIBILITY_KEYS, "compatibility")?;
    let items = bounded_list(
        field(object, "required_contracts"),
        MAX_REQUIRED_CONTRACTS,
        "required_contracts",
    )?;
    let mut contracts = Vec::with_capacity(items.len());
    for item in items {
        contracts.push(string(item, is_identifier, "required_contracts entry")?);
    }
    if contracts.is_empty() {
        return refuse("required_contracts must not be empty");
    }
    let unique: BTreeSet<&String> = contracts.iter().collect();
    if unique.len() != contracts.len() {
        return refuse("required_contracts contains duplicates");
    }
    contracts.sort();
    Ok(Compatibility {
        minimum_reader: safe_uint(
            field(object, "minimum_reader"),
            "compatibility.minimum_reader",
            true,
        )?,
        required_contracts: contracts,
    })
}

fn components(value: &Json) -> Result<Vec<Component>, Refusal> {
    let items = bounded_list(value, MAX_COMPONENTS, "components")?;
    let mut normalized: Vec<Component> = Vec::with_capacity(items.len());
    let mut seen = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let context = format!("components[{index}]");
        let object = strict_object(item, COMPONENT_KEYS, &context)?;
        let component_id = string(
            field(object, "component_id"),
            is_identifier,
            &format!("{context}.component_id"),
        )?;
        if !seen.insert(component_id.clone()) {
            return refuse(format!("duplicate component_id: {component_id}"));
        }
        normalized.push(Component {
            component_id,
            payload: payload_common(object, &context)?,
        });
    }
    normalized.sort_by(|a, b| a.component_id.cmp(&b.component_id));
    Ok(normalized)
}

fn content(value: &Json) -> Result<Vec<Content>, Refusal> {
    let items = bounded_list(value, MAX_CONTENT, "content")?;
    let mut normalized: Vec<Content> = Vec::with_capacity(items.len());
    let mut seen = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let context = format!("content[{index}]");
        let object = strict_object(item, CONTENT_KEYS, &context)?;
        let content_id = string(
            field(object, "content_id"),
            is_identifier,
            &format!("{context}.content_id"),
        )?;
        if !seen.insert(content_id.clone()) {
            return refuse(format!("duplicate content_id: {content_id}"));
        }
        // media_type is validated before the shared payload fields.
        let media_type = string(
            field(object, "media_type"),
            is_media_type,
            &format!("{context}.media_type"),
        )?;
        normalized.push(Content {
            content_id,
            media_type,
            payload: payload_common(object, &context)?,
        });
    }
    normalized.sort_by(|a, b| a.content_id.cmp(&b.content_id));
    Ok(normalized)
}

fn evidence(value: &Json) -> Result<Vec<Evidence>, Refusal> {
    let items = bounded_list(value, MAX_EVIDENCE, "evidence")?;
    let mut normalized: Vec<Evidence> = Vec::with_capacity(items.len());
    let mut seen = BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let context = format!("evidence[{index}]");
        let object = strict_object(item, EVIDENCE_KEYS, &context)?;
        let kind = match field(object, "kind") {
            Json::Str(kind) if EVIDENCE_KINDS.contains(&kind.as_str()) => kind.clone(),
            _ => return refuse(format!("{context}.kind is unsupported")),
        };
        let digest = string(
            field(object, "digest"),
            is_digest,
            &format!("{context}.digest"),
        )?;
        if !seen.insert((kind.clone(), digest.clone())) {
            return refuse(format!("duplicate evidence entry: {kind}/{digest}"));
        }
        normalized.push(Evidence { digest, kind });
    }
    normalized.sort_by(|a, b| (&a.kind, &a.digest).cmp(&(&b.kind, &b.digest)));
    Ok(normalized)
}

fn normalize(
    value: &Json,
    configured_registry_authority: Option<&str>,
) -> Result<Manifest, Refusal> {
    let object = strict_object(value, TOP_KEYS, "release manifest")?;
    match field(object, "schema") {
        Json::Str(schema) if schema == SCHEMA => {}
        _ => return refuse("unsupported release manifest schema"),
    }
    // Field order is the contract's, so the first fault reported matches.
    let manifest = Manifest {
        bundle_seq: safe_uint(field(object, "bundle_seq"), "bundle_seq", true)?,
        compatibility: compatibility(field(object, "compatibility"))?,
        components: components(field(object, "components"))?,
        content: content(field(object, "content"))?,
        evidence: evidence(field(object, "evidence"))?,
        hardware_target: string(
            field(object, "hardware_target"),
            is_identifier,
            "hardware_target",
        )?,
        host: {
            let host = strict_object(field(object, "host"), PAYLOAD_KEYS, "host")?;
            payload_common(host, "host")?
        },
        release_id: string(field(object, "release_id"), is_identifier, "release_id")?,
    };

    // Every contract a payload relies on must be declared, or a device could
    // pass the compatibility gate and then meet a payload it cannot activate.
    let declared: BTreeSet<&str> = manifest
        .compatibility
        .required_contracts
        .iter()
        .map(String::as_str)
        .collect();
    let mut used: BTreeSet<&str> = BTreeSet::new();
    used.insert(manifest.host.contract.as_str());
    used.extend(
        manifest
            .components
            .iter()
            .map(|item| item.payload.contract.as_str()),
    );
    used.extend(
        manifest
            .content
            .iter()
            .map(|item| item.payload.contract.as_str()),
    );
    let undeclared: Vec<&str> = used.difference(&declared).copied().collect();
    if !undeclared.is_empty() {
        return refuse(format!(
            "payload contracts are absent from compatibility.required_contracts: {}",
            undeclared.join(", ")
        ));
    }
    let authority = registry_authority(
        configured_registry_authority,
        "configured registry authority",
    )?;
    let repositories = std::iter::once(("host.repository".to_owned(), &manifest.host.repository))
        .chain(manifest.components.iter().enumerate().map(|(index, item)| {
            (
                format!("components[{index}].repository"),
                &item.payload.repository,
            )
        }))
        .chain(manifest.content.iter().enumerate().map(|(index, item)| {
            (
                format!("content[{index}].repository"),
                &item.payload.repository,
            )
        }));
    for (context, repository) in repositories {
        let actual = repository
            .split_once('/')
            .expect("repository validation guarantees an authority")
            .0;
        if actual != authority {
            return refuse(format!(
                "{context} authority '{actual}' does not match configured registry authority '{authority}'"
            ));
        }
    }
    Ok(manifest)
}

// ---------------------------------------------------------------------------
// Canonical bytes
// ---------------------------------------------------------------------------

/// Compact separators, keys in sorted order, UTF-8, one trailing LF — the exact
/// shape Fabric's `canonical_bytes` produces.
fn write_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Non-ASCII is emitted literally: `ensure_ascii=False`. Every field
            // is pattern-checked ASCII, so this branch is defensive only.
            ch if (ch as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn write_string_array(out: &mut String, values: &[String]) {
    out.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(out, value);
    }
    out.push(']');
}

/// Payload members, emitted in sorted-key order.
fn write_payload_fields(out: &mut String, payload: &Payload) {
    out.push_str("\"contract\":");
    write_string(out, &payload.contract);
    out.push_str(",\"digest\":");
    write_string(out, &payload.digest);
    let _ = write!(out, ",\"reboot_required\":{}", payload.reboot_required);
    out.push_str(",\"repository\":");
    write_string(out, &payload.repository);
    out.push_str(",\"required_entitlement\":");
    write_string(out, &payload.required_entitlement);
    out.push_str(",\"restart_scope\":");
    write_string_array(out, &payload.restart_scope);
}

fn canonical_bytes(manifest: &Manifest) -> Vec<u8> {
    let mut out = String::new();
    let _ = write!(out, "{{\"bundle_seq\":{}", manifest.bundle_seq);

    let _ = write!(
        out,
        ",\"compatibility\":{{\"minimum_reader\":{},\"required_contracts\":",
        manifest.compatibility.minimum_reader
    );
    write_string_array(&mut out, &manifest.compatibility.required_contracts);
    out.push('}');

    out.push_str(",\"components\":[");
    for (index, component) in manifest.components.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"component_id\":");
        write_string(&mut out, &component.component_id);
        out.push(',');
        write_payload_fields(&mut out, &component.payload);
        out.push('}');
    }
    out.push(']');

    out.push_str(",\"content\":[");
    for (index, item) in manifest.content.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"content_id\":");
        write_string(&mut out, &item.content_id);
        out.push_str(",\"contract\":");
        write_string(&mut out, &item.payload.contract);
        out.push_str(",\"digest\":");
        write_string(&mut out, &item.payload.digest);
        out.push_str(",\"media_type\":");
        write_string(&mut out, &item.media_type);
        let _ = write!(out, ",\"reboot_required\":{}", item.payload.reboot_required);
        out.push_str(",\"repository\":");
        write_string(&mut out, &item.payload.repository);
        out.push_str(",\"required_entitlement\":");
        write_string(&mut out, &item.payload.required_entitlement);
        out.push_str(",\"restart_scope\":");
        write_string_array(&mut out, &item.payload.restart_scope);
        out.push('}');
    }
    out.push(']');

    out.push_str(",\"evidence\":[");
    for (index, item) in manifest.evidence.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str("{\"digest\":");
        write_string(&mut out, &item.digest);
        out.push_str(",\"kind\":");
        write_string(&mut out, &item.kind);
        out.push('}');
    }
    out.push(']');

    out.push_str(",\"hardware_target\":");
    write_string(&mut out, &manifest.hardware_target);

    out.push_str(",\"host\":{");
    write_payload_fields(&mut out, &manifest.host);
    out.push('}');

    out.push_str(",\"release_id\":");
    write_string(&mut out, &manifest.release_id);
    out.push_str(",\"schema\":");
    write_string(&mut out, SCHEMA);
    out.push_str("}\n");

    out.into_bytes()
}

/// Parse bounded bytes into the one normalized value, its canonical bytes and
/// their digest.
///
/// The digest covers the CANONICAL bytes including the trailing LF — never the
/// input bytes. Hashing the input would make re-serialization a rollback and
/// re-indentation a new release.
pub(crate) fn parse(
    data: &[u8],
    configured_registry_authority: Option<&str>,
) -> Result<ParsedManifest, Refusal> {
    if data.len() > MAX_MANIFEST_BYTES {
        return refuse("release manifest exceeds the byte limit");
    }
    let manifest = normalize(&parse_json(data)?, configured_registry_authority)?;
    let encoded = canonical_bytes(&manifest);
    if encoded.len() > MAX_MANIFEST_BYTES {
        return refuse("canonical release manifest exceeds the byte limit");
    }
    Ok(ParsedManifest {
        digest: canonical_digest(&encoded),
        value: manifest,
        canonical_bytes: encoded,
    })
}

/// SHA-256 of the canonical bytes, computed in this process.
///
/// Never routed through `sha256sum`: this digest is the anti-rollback identity,
/// and a hostile PATH entry that returned a constant would make two different
/// manifests compare equal and downgrade a refusal to a no-op.
fn canonical_digest(canonical: &[u8]) -> String {
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in Sha256::digest(canonical) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Classification {
    NoOp,
    ComponentContent,
    Host,
    Refusal,
}

impl Classification {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NoOp => "no-op",
            Self::ComponentContent => "component-content",
            Self::Host => "host",
            Self::Refusal => "refusal",
        }
    }
}

/// What this device can actually activate. Supplied by the caller; this module
/// never reads it from the environment, so a plan is reproducible off-device.
#[derive(Debug, Clone)]
pub(crate) struct DeviceCompatibility {
    pub(crate) hardware_target: String,
    pub(crate) reader_version: u64,
    pub(crate) supported_contracts: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub(crate) classification: Classification,
    pub(crate) current_manifest_digest: Option<String>,
    pub(crate) candidate_manifest_digest: Option<String>,
    pub(crate) bundle_seq: Option<u64>,
    pub(crate) changed_components: Vec<String>,
    pub(crate) changed_content: Vec<String>,
    pub(crate) restart_scope: Vec<String>,
    pub(crate) reboot_required: bool,
    pub(crate) refusal_reason: Option<String>,
}

impl Plan {
    fn decided(
        classification: Classification,
        current: &ParsedManifest,
        candidate: &ParsedManifest,
        bundle_seq: u64,
    ) -> Self {
        Self {
            classification,
            current_manifest_digest: Some(current.digest.clone()),
            candidate_manifest_digest: Some(candidate.digest.clone()),
            bundle_seq: Some(bundle_seq),
            changed_components: Vec::new(),
            changed_content: Vec::new(),
            restart_scope: Vec::new(),
            reboot_required: false,
            refusal_reason: None,
        }
    }

    fn refusal(
        reason: impl Into<String>,
        current: Option<&ParsedManifest>,
        candidate: Option<&ParsedManifest>,
    ) -> Self {
        Self {
            classification: Classification::Refusal,
            current_manifest_digest: current.map(|parsed| parsed.digest.clone()),
            candidate_manifest_digest: candidate.map(|parsed| parsed.digest.clone()),
            bundle_seq: candidate.map(|parsed| parsed.value.bundle_seq),
            changed_components: Vec::new(),
            changed_content: Vec::new(),
            restart_scope: Vec::new(),
            reboot_required: false,
            refusal_reason: Some(reason.into()),
        }
    }

    /// Canonical plan bytes: compact separators, sorted keys, one trailing LF.
    ///
    /// The comparison target is
    /// `json.dumps(plan.as_dict(), ensure_ascii=False, allow_nan=False,
    /// separators=(",", ":"), sort_keys=True) + "\n"`. Fabric's classifier
    /// returns a dict and defines no canonical encoding of its own, so this
    /// encoding is CoreOS's and is pinned by the golden vectors.
    pub(crate) fn to_canonical_json(&self) -> Vec<u8> {
        let mut out = String::new();
        match self.bundle_seq {
            Some(seq) => {
                let _ = write!(out, "{{\"bundle_seq\":{seq}");
            }
            None => out.push_str("{\"bundle_seq\":null"),
        }
        out.push_str(",\"candidate_manifest_digest\":");
        match &self.candidate_manifest_digest {
            Some(digest) => write_string(&mut out, digest),
            None => out.push_str("null"),
        }
        out.push_str(",\"changed_components\":");
        write_string_array(&mut out, &self.changed_components);
        out.push_str(",\"changed_content\":");
        write_string_array(&mut out, &self.changed_content);
        out.push_str(",\"classification\":");
        write_string(&mut out, self.classification.as_str());
        out.push_str(",\"current_manifest_digest\":");
        match &self.current_manifest_digest {
            Some(digest) => write_string(&mut out, digest),
            None => out.push_str("null"),
        }
        let _ = write!(out, ",\"reboot_required\":{}", self.reboot_required);
        // Present only on a refusal, and sorted between the two `re...` keys.
        if let Some(reason) = &self.refusal_reason {
            out.push_str(",\"refusal_reason\":");
            write_string(&mut out, reason);
        }
        out.push_str(",\"restart_scope\":");
        write_string_array(&mut out, &self.restart_scope);
        out.push_str(",\"schema\":");
        write_string(&mut out, PLAN_SCHEMA);
        out.push_str("}\n");
        out.into_bytes()
    }
}

fn compatible(manifest: &ParsedManifest, device: &DeviceCompatibility) -> Option<String> {
    let value = &manifest.value;
    if value.hardware_target != device.hardware_target {
        return Some("manifest hardware_target does not match the device".to_owned());
    }
    if value.compatibility.minimum_reader > device.reader_version {
        return Some("manifest requires a newer release-manifest reader".to_owned());
    }
    let missing: Vec<&str> = value
        .compatibility
        .required_contracts
        .iter()
        .filter(|contract| !device.supported_contracts.contains(*contract))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        return Some(format!(
            "device does not support required contracts: {}",
            missing.join(", ")
        ));
    }
    None
}

fn components_by_id(manifest: &Manifest) -> BTreeMap<&str, &Payload> {
    manifest
        .components
        .iter()
        .map(|item| (item.component_id.as_str(), &item.payload))
        .collect()
}

/// Content is keyed by id but compared on `(media_type, payload)`: a media-type
/// change is a real delta even when every payload field is identical.
fn content_by_id(manifest: &Manifest) -> BTreeMap<&str, (&str, &Payload)> {
    manifest
        .content
        .iter()
        .map(|item| {
            (
                item.content_id.as_str(),
                (item.media_type.as_str(), &item.payload),
            )
        })
        .collect()
}

fn changed_ids<T: PartialEq>(
    current: &BTreeMap<&str, T>,
    candidate: &BTreeMap<&str, T>,
) -> Vec<String> {
    let mut ids: BTreeSet<&str> = current.keys().copied().collect();
    ids.extend(candidate.keys().copied());
    ids.into_iter()
        .filter(|id| current.get(id) != candidate.get(id))
        .map(str::to_owned)
        .collect()
}

fn union_restart_scope(payloads: &[&Payload]) -> Vec<String> {
    let units: BTreeSet<&String> = payloads
        .iter()
        .flat_map(|payload| payload.restart_scope.iter())
        .collect();
    units.into_iter().cloned().collect()
}

/// Both sides of every changed payload.
///
/// A replacement must keep the installed payload's deactivation requirements as
/// well as the candidate's activation requirements; additions and removals
/// naturally contribute only the side that exists.
fn changed_payloads<'a, T: Copy>(
    current: &BTreeMap<&str, T>,
    candidate: &BTreeMap<&str, T>,
    changed: &[String],
    payload_of: fn(T) -> &'a Payload,
) -> Vec<&'a Payload> {
    let mut payloads = Vec::new();
    for id in changed {
        if let Some(entry) = current.get(id.as_str()) {
            payloads.push(payload_of(*entry));
        }
        if let Some(entry) = candidate.get(id.as_str()) {
            payloads.push(payload_of(*entry));
        }
    }
    payloads
}

/// Classify already-authenticated manifest bytes. A pure function: no I/O, no
/// subprocess, no environment read. The canonical digest is hashed in-process
/// with `sha2`, so nothing on `PATH` can influence the verdict.
///
/// Signature and provenance are the caller's job and are NOT re-checked here;
/// an unauthenticated pair of byte strings will still classify.
pub(crate) fn classify(
    current_bytes: &[u8],
    candidate_bytes: &[u8],
    device: &DeviceCompatibility,
    configured_registry_authority: Option<&str>,
) -> Plan {
    let current = match parse(current_bytes, configured_registry_authority) {
        Ok(parsed) => parsed,
        Err(refusal) => {
            return Plan::refusal(format!("current manifest refused: {refusal}"), None, None)
        }
    };
    let candidate = match parse(candidate_bytes, configured_registry_authority) {
        Ok(parsed) => parsed,
        Err(refusal) => {
            return Plan::refusal(
                format!("candidate manifest refused: {refusal}"),
                Some(&current),
                None,
            )
        }
    };

    // The installed manifest is checked too: a device that drifted out of its
    // own manifest's compatibility must refuse rather than plan from it.
    if let Some(reason) = compatible(&current, device) {
        return Plan::refusal(
            format!("current manifest incompatible: {reason}"),
            Some(&current),
            Some(&candidate),
        );
    }
    if let Some(reason) = compatible(&candidate, device) {
        return Plan::refusal(
            format!("candidate manifest incompatible: {reason}"),
            Some(&current),
            Some(&candidate),
        );
    }

    let old_seq = current.value.bundle_seq;
    let new_seq = candidate.value.bundle_seq;
    if new_seq < old_seq {
        return Plan::refusal(
            "candidate bundle_seq is below the installed floor",
            Some(&current),
            Some(&candidate),
        );
    }
    if new_seq == old_seq {
        // Equality is admitted only for the byte-identical canonical manifest:
        // a re-apply, never a different release wearing the same sequence.
        if current.digest == candidate.digest {
            return Plan::decided(Classification::NoOp, &current, &candidate, new_seq);
        }
        return Plan::refusal(
            "the same bundle_seq identifies a different canonical manifest",
            Some(&current),
            Some(&candidate),
        );
    }

    let old = &current.value;
    let new = &candidate.value;
    let old_components = components_by_id(old);
    let new_components = components_by_id(new);
    let old_content = content_by_id(old);
    let new_content = content_by_id(new);
    let changed_components_ids = changed_ids(&old_components, &new_components);
    let changed_content_ids = changed_ids(&old_content, &new_content);
    let host_payload_changed = old.host != new.host;
    let host_changed = host_payload_changed || old.compatibility != new.compatibility;

    let changed_shared_content: Vec<String> = changed_content_ids
        .iter()
        .filter(|id| old_content.contains_key(id.as_str()) && new_content.contains_key(id.as_str()))
        .cloned()
        .collect();

    // A compatibility edit is metadata, not an explicit host payload delta. It
    // must never smuggle a structural transition past the host requirement.
    if !host_payload_changed {
        if old_components.keys().ne(new_components.keys()) {
            return Plan::refusal(
                "component membership changed without an explicit host delta",
                Some(&current),
                Some(&candidate),
            );
        }
        let component_digest_only = changed_components_ids.iter().all(|id| {
            match (
                old_components.get(id.as_str()),
                new_components.get(id.as_str()),
            ) {
                (Some(old), Some(new)) => old.differs_only_by_digest(new),
                _ => false,
            }
        });
        if !component_digest_only {
            return Plan::refusal(
                "component contract changed without an explicit host delta",
                Some(&current),
                Some(&candidate),
            );
        }
        let content_digest_only = changed_shared_content.iter().all(|id| {
            match (old_content.get(id.as_str()), new_content.get(id.as_str())) {
                (Some((old_media, old)), Some((new_media, new))) => {
                    old_media == new_media && old.differs_only_by_digest(new)
                }
                _ => false,
            }
        });
        if !content_digest_only {
            return Plan::refusal(
                "content contract changed without an explicit host delta",
                Some(&current),
                Some(&candidate),
            );
        }
    }

    let mut transition: Vec<&Payload> = Vec::new();
    if host_changed && host_payload_changed {
        transition.push(&old.host);
        transition.push(&new.host);
    }
    transition.extend(changed_payloads(
        &old_components,
        &new_components,
        &changed_components_ids,
        |payload| payload,
    ));
    transition.extend(changed_payloads(
        &old_content,
        &new_content,
        &changed_content_ids,
        |(_, payload)| payload,
    ));

    if host_changed {
        return Plan {
            classification: Classification::Host,
            current_manifest_digest: Some(current.digest.clone()),
            candidate_manifest_digest: Some(candidate.digest.clone()),
            bundle_seq: Some(new_seq),
            changed_components: changed_components_ids,
            changed_content: changed_content_ids,
            restart_scope: union_restart_scope(&transition),
            reboot_required: transition.iter().any(|payload| payload.reboot_required),
            refusal_reason: None,
        };
    }

    if !changed_components_ids.is_empty() || !changed_content_ids.is_empty() {
        return Plan {
            classification: Classification::ComponentContent,
            current_manifest_digest: Some(current.digest.clone()),
            candidate_manifest_digest: Some(candidate.digest.clone()),
            bundle_seq: Some(new_seq),
            changed_components: changed_components_ids,
            changed_content: changed_content_ids,
            restart_scope: union_restart_scope(&transition),
            reboot_required: transition.iter().any(|payload| payload.reboot_required),
            refusal_reason: None,
        };
    }

    // Evidence and bundle_seq are signed facts, but do not select an engine.
    Plan::decided(Classification::NoOp, &current, &candidate, new_seq)
}

#[cfg(test)]
#[path = "release_manifest_tests.rs"]
mod tests;
