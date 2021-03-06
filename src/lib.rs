//! `RustySecrets` implements Shamir's secret sharing in Rust. It provides the possibility to sign shares.

#![deny(
    missing_docs,
    missing_debug_implementations, missing_copy_implementations,
    trivial_casts, trivial_numeric_casts,
    unsafe_code, unstable_features,
    unused_import_braces, unused_qualifications
)]

extern crate protobuf;
extern crate rustc_serialize as serialize;
extern crate rand;
extern crate merkle_sigs;
extern crate ring;
extern crate base64;

// base64_serde_type!(Base64Standard, STANDARD);

use base64::{encode_config, STANDARD};

extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

use ring::digest::{Algorithm, SHA512};
#[allow(non_upper_case_globals)]
static digest: &'static Algorithm = &SHA512;

mod custom_error;
mod gf256;
mod interpolation;
#[allow(unused_qualifications)]
mod secret;
#[allow(unused_qualifications)]
mod share_data;
mod share_format;
mod json_share_data;
mod validation;

pub use custom_error::RustyError;

pub mod sss;
pub mod wrapped_secrets;

#[cfg(test)]
mod tests;
