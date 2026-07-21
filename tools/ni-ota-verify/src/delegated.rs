//! ADR-0039 delegated OTA verifier.
//!
//! The first stacked slice compiles and tests the closed contract foundation;
//! the next slice consumes it from the device command and removes this narrow
//! temporary dead-code allowance.

#![allow(dead_code)]

pub(crate) mod contract;
