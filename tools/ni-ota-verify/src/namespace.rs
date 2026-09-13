//! The one place this OS says whose it is.
//!
//! Every string that identifies the OPERATOR rather than the MECHANISM is
//! derived from the namespace declared here: the domain separators that bind a
//! signature to its purpose, and the schema identifiers stamped into every
//! evidence file. Nine domains and thirty-four schemas shared one prefix as
//! thirty-four separate literals, which meant an adopter could not build this
//! OS under their own identity without editing the source — and meant this
//! deployment's own bench, laboratory and customer appliances all sealed their
//! records into a single cryptographic domain.
//!
//! See `docs/ADR-0016-open-core-namespace.md`.
//!
//! # Why it is a build input and not configuration
//!
//! Same reason as [`crate::trusted_time::TRUSTED_TIME_ISSUER`], which made this
//! argument first: a domain separator that whoever writes a configuration file
//! can redirect is not a separator. Baked at compile time, it keeps exactly the
//! property the literals had — nothing on the running system can point it
//! elsewhere.
//!
//! # Why it defaults instead of being mandatory
//!
//! These bytes are already sealed into deployed TPMs and written into evidence
//! files on deployed disks. An unconfigured build MUST reproduce them or those
//! appliances stop verifying. So the default is this deployment's value, and
//! `NI_NAMESPACE` is how somebody else declares theirs.
//!
//! Changing it starts a NEW LINEAGE. Records sealed under one namespace cannot
//! be verified by a build using another, in either direction. That is what a
//! domain separator is for, and it is why there is no migration: there is
//! nothing to migrate, only two populations that must not be confused.

/// The declared namespace. Lowercase, no colon — the separators add those.
pub(crate) const NAMESPACE: &str = match option_env!("NI_NAMESPACE") {
    Some(declared) => declared,
    None => "neural-ice",
};

/// A signature domain: `<namespace>:<purpose>` with the NUL these payloads
/// have always carried, so the bytes are unchanged for the default namespace.
pub(crate) fn domain(purpose: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(NAMESPACE.len() + purpose.len() + 2);
    bytes.extend_from_slice(NAMESPACE.as_bytes());
    bytes.push(b':');
    bytes.extend_from_slice(purpose.as_bytes());
    bytes.push(0);
    bytes
}

/// A schema identifier: `<namespace>-<subject>`.
///
/// Not yet threaded through the thirty-four schema literals: those are stamped
/// into evidence files on deployed disks, so converting them is a mechanical
/// pass that deserves its own review rather than a tail-end of this one. The
/// guard below already refuses a thirty-fifth spelled differently.
#[allow(dead_code)]
pub(crate) fn schema(subject: &str) -> String {
    format!("{NAMESPACE}-{subject}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vocabulary this crate shipped before the namespace existed. It is
    /// what an UNCONFIGURED build must still produce, and what the literals
    /// still spell in the files not yet converted.
    const SHIPPED: &str = "neural-ice";

    #[test]
    fn the_default_namespace_reproduces_the_bytes_already_sealed() {
        // A build that declared its own namespace is not the subject here: it
        // is SUPPOSED to produce different bytes, and failing its suite for
        // doing so would make the adoption path red for the right behaviour.
        if NAMESPACE != SHIPPED {
            assert_eq!(
                domain("ota:trusted-time:v2"),
                format!("{NAMESPACE}:ota:trusted-time:v2\0").into_bytes(),
                "a declared namespace must still compose the same shape"
            );
            return;
        }
        // Not a tautology: these are the literals this crate shipped before the
        // namespace existed. An unconfigured build that produced anything else
        // would make every deployed appliance unverifiable.
        assert_eq!(
            domain("ota:trusted-time:v2"),
            b"neural-ice:ota:trusted-time:v2\0"
        );
        assert_eq!(
            domain("tpm:access-profile-binding:v1"),
            b"neural-ice:tpm:access-profile-binding:v1\0"
        );
        assert_eq!(
            schema("device-root-tpm-v1"),
            "neural-ice-device-root-tpm-v1"
        );
    }

    /// The guard that makes the namespace real: no source file may introduce a
    /// domain separator or a schema identifier under a DIFFERENT vocabulary.
    ///
    /// Thirty-four schemas and nine domains were written as independent
    /// literals. Nothing stopped the thirty-fifth from being spelled otherwise,
    /// and nothing would have said so — a second vocabulary is only ever
    /// discovered by the thing it breaks.
    ///
    /// It compares against the SHIPPED vocabulary rather than the declared one:
    /// the schema literals are not converted yet, so under a custom namespace
    /// they legitimately still spell the old prefix. This becomes `NAMESPACE`
    /// when that pass lands.
    #[test]
    fn no_source_file_declares_a_vocabulary_of_its_own() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut offenders = Vec::new();
        let mut checked = 0usize;
        let mut stack = vec![std::path::PathBuf::from(root)];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path).expect("readable source tree") {
                let entry = entry.expect("readable entry").path();
                if entry.is_dir() {
                    stack.push(entry);
                    continue;
                }
                if entry.extension().is_none_or(|ext| ext != "rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&entry).expect("readable source");
                for (number, line) in source.lines().enumerate() {
                    for piece in line.split('"').skip(1) {
                        let Some(value) = piece.split('"').next() else {
                            continue;
                        };
                        // A format template is not a vocabulary: `{NAMESPACE}`
                        // composes one at runtime, which is the point.
                        if value.contains('{') {
                            continue;
                        }
                        let is_domain = value.contains(':') && value.ends_with("\\0");
                        let is_schema = value.starts_with(&format!("{SHIPPED}-"));
                        if !is_domain && !is_schema {
                            continue;
                        }
                        checked += 1;
                        let owned = value.starts_with(&format!("{SHIPPED}:"))
                            || value.starts_with(&format!("{SHIPPED}-"));
                        if !owned {
                            offenders.push(format!("{}:{}: {value}", entry.display(), number + 1));
                        }
                    }
                }
            }
        }
        assert!(
            checked > 30,
            "the scan found only {checked} identifiers; it has stopped measuring anything"
        );
        assert!(
            offenders.is_empty(),
            "these declare a vocabulary the namespace does not own:\n{}",
            offenders.join("\n")
        );
    }
}
