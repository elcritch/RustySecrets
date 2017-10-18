use custom_error::{RustyError, RustyErrorTypes};
use custom_error::pie2error;
use digest;
use merkle_sigs::{MerklePublicKey, Proof, PublicKey};
use protobuf;
use protobuf::{Message, RepeatedField};
use serialize;
use serialize::base64::{self, FromBase64, ToBase64};
use share_data::ShareData;
use std::error::Error;
use json_share_data::ShareDataJson;
use serde_json;
use sss::ShareFormatKind;
use base64::{encode, decode};
use std::str;

pub type ParsedShare = Result<(Vec<u8>, u8, u8, Option<(Vec<Vec<u8>>, Proof<MerklePublicKey>)>), RustyError>;

fn base64_config() -> serialize::base64::Config {
    base64::Config { pad: false, ..base64::STANDARD }
}

pub fn share_string_from(share: Vec<u8>, threshold: u8, share_num: u8, serde_kind: ShareFormatKind,
                         signature_pair: Option<(Vec<Vec<u8>>, Proof<MerklePublicKey>)>)
                         -> String {
    match serde_kind {
        ShareFormatKind::Protobuf =>
            profobuf_share_string_from(share, threshold, share_num, signature_pair),
        ShareFormatKind::Json =>
            json_share_string_from(share, threshold, share_num, signature_pair),
    }
}

pub fn profobuf_share_string_from(share: Vec<u8>, threshold: u8, share_num: u8,
                         signature_pair: Option<(Vec<Vec<u8>>, Proof<MerklePublicKey>)>)
                         -> String {
    let mut share_protobuf = ShareData::new();
    share_protobuf.set_shamir_data(share);

    if signature_pair.is_some() {
        let (signature, proof) = signature_pair.unwrap();
        share_protobuf.set_signature(RepeatedField::from_vec(signature));
        share_protobuf.set_proof(proof.write_to_bytes().unwrap());
    }

    let b64_share = share_protobuf.write_to_bytes().unwrap().to_base64(base64_config());
    format!("{}-{}-{}", threshold, share_num, b64_share)
}

pub fn json_share_string_from(share: Vec<u8>, threshold: u8, share_num: u8,
                         signature_pair: Option<(Vec<Vec<u8>>, Proof<MerklePublicKey>)>)
                         -> String {
    let mut share_json = ShareDataJson{
        shamir_data: encode(&share),
        signature: None,
        proof: None,
    };

    if signature_pair.is_some() {
        let (signature, proof) = signature_pair.unwrap();
        share_json.signature = Some( signature.iter().map(|v| encode(&v) ).collect() );
        share_json.proof = Some(encode(&proof.write_to_bytes().unwrap()));
    }

    let share_json_str = serde_json::to_string(&share_json).unwrap();

    // println!("json share format: struct: {:?}", share_json);

    // println!("json share format: json: {}", share_json_str);

    let b64_share = share_json_str.as_bytes().to_base64(base64_config());
    format!("{}-{}-{}", threshold, share_num, b64_share)
}

pub fn share_from_string(s: &str, index: u8, is_signed: bool) ->  ParsedShare {
     share_from_string_format(s, index, is_signed, ShareFormatKind::Protobuf)
}

pub fn share_from_string_format
    (s: &str,
     index: u8,
     is_signed: bool,
     share_format: ShareFormatKind)
     ->  ParsedShare {
    let parts: Vec<_> = s.trim().split('-').collect();

    if parts.len() != 3 {
        return Err(RustyError::with_type(RustyErrorTypes::ShareParsingError(index, format!("Expected 3 parts separated by a minus sign. Found {}.", s))));
    }
    let (k, n, p3) = {
        let mut iter = parts.into_iter();
        let k = try!(iter.next().unwrap().parse::<u8>().map_err(pie2error));
        let n = try!(iter.next().unwrap().parse::<u8>().map_err(pie2error));
        let p3 = iter.next().unwrap();
        (k, n, p3)
    };
    if k < 1 || n < 1 {
        return Err(RustyError::with_type(RustyErrorTypes::ShareParsingError(index, format!("Found illegal parameters K: {} N: {}.", k, n))));
    }

    let raw_data = try!(p3.from_base64().map_err(|_| {
        RustyError::with_type(RustyErrorTypes::ShareParsingError(index, "Base64 decoding of data block failed".to_owned()))
    }));

    match share_format {
        ShareFormatKind::Protobuf =>
            protobuf_share_from_string(raw_data, index, is_signed, k, n),
        ShareFormatKind::Json =>
            json_share_from_string(raw_data, index, is_signed, k, n),
    }
}

fn protobuf_share_from_string(raw_data: Vec<u8>, index: u8, is_signed: bool, k: u8, n: u8) -> ParsedShare {
    let protobuf_data = try!(protobuf::parse_from_bytes::<ShareData>(raw_data.as_slice())
        .map_err(|e| RustyError::with_type(RustyErrorTypes::ShareParsingError(index, format!("Protobuf decoding of data block failed with error: {} .", e.description())))));

    let share = Vec::from(protobuf_data.get_shamir_data());

    if is_signed {
        let p_result = Proof::parse_from_bytes(protobuf_data.get_proof(), digest);

        let p_opt = p_result.unwrap();
        let p = p_opt.unwrap();

        let proof = Proof {
            algorithm: digest,
            lemma: p.lemma,
            root_hash: p.root_hash,
            value: MerklePublicKey::new(PublicKey::from_vec(p.value, digest).unwrap()),
        };

        let signature = protobuf_data.get_signature();

        Ok((share, k, n, Some((Vec::from(signature), proof))))
    } else {
        Ok((share, k, n, None))
    }
}

fn json_share_from_string(raw_data: Vec<u8>, index: u8, is_signed: bool, k: u8, n: u8) -> ParsedShare {
    let json_data: ShareDataJson = serde_json::from_str(str::from_utf8(&raw_data).unwrap()).unwrap();

    // println!("json_share_from_string: {:?}", json_data);

    let share: Vec<u8> = decode(&json_data.shamir_data).unwrap();

    if is_signed {
        let p_bytes: Vec<u8> = decode(&json_data.proof.unwrap()).unwrap();
        let p_result = Proof::parse_from_bytes(&p_bytes, digest);

        let p_opt = p_result.unwrap();
        let p = p_opt.unwrap();

        let proof = Proof {
            algorithm: digest,
            lemma: p.lemma,
            root_hash: p.root_hash,
            value: MerklePublicKey::new(PublicKey::from_vec(p.value, digest).unwrap()),
        };

        let signature: Vec<Vec<u8>> = json_data.signature.unwrap().iter().map(|s| decode(&s).unwrap()).collect();

        Ok((share, k, n, Some((signature, proof))))
    } else {
        Ok((share, k, n, None))
    }
}

pub fn format_share_for_signing(k: u8, i: u8, data: &[u8]) -> Vec<u8> {
    format!("{}-{}-{}", k, i, data.to_base64(base64_config())).into_bytes()
}
