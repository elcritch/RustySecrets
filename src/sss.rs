//! SSS provides Shamir's secret sharing with raw data.

use custom_error::{RustyError, other_io_err};
use digest;
use interpolation::{encode, lagrange_interpolate};
use merkle_sigs::sign_data_vec;
use rand::{OsRng, Rng};
use share_format::format_share_for_signing;
use share_format::share_string_from;
use share_format::share_from_string_format;
use share_format::ParsedShare;
use std::io;
use std::iter::repeat;
use validation::process_and_validate_shares;

fn new_vec<T: Clone>(n: usize, x: T) -> Vec<T> {
    repeat(x).take(n).collect()
}

/// Type of encoding to use on returned strings.
///
#[derive(Debug, Copy, Clone)]
pub enum ShareFormatKind {
    /// Use `SharedData` Protobuf
    Protobuf,
    /// Use JSON encoding of ShareDataJson struct.
    Json,
}


/// Performs threshold k-out-of-n Shamir's secret sharing, returns Protobuf encoded strings.
///
/// # Examples
///
/// ```
/// use rusty_secrets::sss::generate_shares;
/// let secret = "These programs were never about terrorism: they’re about economic spying,
///               social control, and diplomatic manipulation. They’re about power.".to_string();
///
/// match generate_shares(7, 10, &secret.into_bytes(), true){
/// 	Ok(shares) => {
/// 		// Do something with the shares
/// 	},
/// 	Err(_) => {}// Deal with error}
/// }
/// ```
pub fn generate_shares(k: u8, n: u8, secret: &[u8], sign_shares: bool) -> io::Result<Vec<String>> {
    generate_shares_format(k, n, secret, sign_shares, ShareFormatKind::Protobuf)
}

/// Performs threshold k-out-of-n Shamir's secret sharing, returns as Protobuf or JSON encoded base64 strings.
///
/// # Examples
///
/// ```
/// use rusty_secrets::sss::generate_shares_format;
/// use rusty_secrets::sss::ShareFormatKind;
/// let secret = "These programs were never about terrorism: they’re about economic spying,
///               social control, and diplomatic manipulation. They’re about power.".to_string();
///
/// match generate_shares_format(7, 10, &secret.into_bytes(), true, ShareFormatKind::Json){
/// 	Ok(shares) => {
/// 		// Do something with the shares
/// 	},
/// 	Err(_) => {}// Deal with error}
/// }
/// ```
pub fn generate_shares_format(k: u8, n: u8, secret: &[u8], sign_shares: bool, share_format: ShareFormatKind) -> io::Result<Vec<String>> {
    if k > n {
        return Err(other_io_err("Threshold K can not be larger than N", None, None, None));
    }

    let shares = try!(secret_share(secret, k, n));

    let signatures = if sign_shares {
        let shares_to_sign = shares.iter()
            .enumerate()
            .map(|(i, x)| format_share_for_signing(k, (i + 1) as u8, x))
            .collect::<Vec<_>>();

        let sign = sign_data_vec(&shares_to_sign, digest)
            .unwrap()
            .into_iter()
            .map(Some)
            .collect::<Vec<_>>();

        Some(sign)
    } else {
        None
    };

    let mut result = Vec::with_capacity(n as usize);

    for ((index, share), signature_pair) in
        shares.into_iter()
            .enumerate()
            .zip(signatures.unwrap_or_else(|| vec![None; n as usize]).into_iter()) {
        let share_string = share_string_from(share, k, (index + 1) as u8, share_format, signature_pair);
        result.push(share_string);
    }

    Ok(result)
}

/// Create share from string
///
pub fn share_from_string(s: &str, index: u8, is_signed: bool, share_format: ShareFormatKind) ->  ParsedShare {
     share_from_string_format(s, index, is_signed, share_format)
}

fn secret_share(src: &[u8], k: u8, n: u8) -> Result<Vec<Vec<u8>>, RustyError> {
    let mut result = Vec::with_capacity(n as usize);
    for _ in 0..(n as usize) {
        result.push(new_vec(src.len(), 0u8));
    }
    let mut col_in = new_vec(k as usize, 0u8);
    let mut col_out = Vec::with_capacity(n as usize);
    let mut osrng = try!(OsRng::new());
    for (c, &s) in src.iter().enumerate() {
        col_in[0] = s;
        osrng.fill_bytes(&mut col_in[1..]);
        col_out.clear();
        try!(encode(&*col_in, n, &mut col_out));
        for (&y, share) in col_out.iter().zip(result.iter_mut()) {
            share[c] = y;
        }
    }
    Ok(result)
}


/// Recovers the secret from a k-out-of-n Shamir's secret sharing.
///
/// At least `k` distinct shares need to be provided to recover the share.
///
/// # Examples
///
/// ```
/// use rusty_secrets::sss::recover_secret;
/// let share1 = "2-1-Cha7s14Q/mSwWko0ittr+/Uf79RHQMIP".to_string();
/// let share2 = "2-4-ChaydsUJDypD9ZWxwvIICh/cmZvzusOF".to_string();
/// let shares = vec![share1, share2];
///
/// match recover_secret(shares, false) {
/// 	Ok(secret) => {
/// 		// Do something with the secret
/// 	},
/// 	Err(e) => {
/// 		// Deal with the error
/// 	}
/// }
/// ```
pub fn recover_secret(shares: Vec<String>, verify_signatures: bool) -> Result<Vec<u8>, RustyError> {
    recover_secret_format(shares, verify_signatures, ShareFormatKind::Protobuf)
}

/// Recovers the secret from a k-out-of-n Shamir's secret sharing in specified format.
///
pub fn recover_secret_format(shares: Vec<String>, verify_signatures: bool, share_format: ShareFormatKind) -> Result<Vec<u8>, RustyError> {
    let (k, shares) = try!(process_and_validate_shares(shares, verify_signatures, share_format));

    let slen = shares[0].1.len();
    let mut col_in = Vec::with_capacity(k as usize);
    let mut secret = Vec::with_capacity(slen);
    for byteindex in 0..slen {
        col_in.clear();
        for s in shares.iter().take(k as usize) {
            col_in.push((s.0, s.1[byteindex]));
        }
        secret.push(lagrange_interpolate(&*col_in));
    }

    Ok(secret)
}
