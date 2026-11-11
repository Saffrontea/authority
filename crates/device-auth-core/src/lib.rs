//! Stable preimages and encodings for device proof-of-possession.

use thiserror::Error;

const ENROLLMENT_DOMAIN: &[u8] = b"AUTHORITY-DEVICE-ENROLLMENT-V1\0";
const AUTHENTICATION_DOMAIN: &[u8] = b"AUTHORITY-DEVICE-AUTHENTICATION-V1\0";
const SESSION_REQUEST_DOMAIN: &[u8] = b"AUTHORITY-DEVICE-SESSION-REQUEST-V1\0";
const NODE_ENROLLMENT_DOMAIN: &[u8] = b"AUTHORITY-NODE-ENROLLMENT-V1\0";

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DeviceProofError {
    #[error("value is not canonical unpadded base64url")]
    InvalidBase64Url,
    #[error("device public key must contain 32 bytes")]
    InvalidPublicKey,
    #[error("device signature must contain 64 bytes")]
    InvalidSignature,
}

#[must_use]
pub fn enrollment_preimage(
    user_id: &str,
    device_public_key: &str,
    wireguard_public_key: &str,
) -> Vec<u8> {
    preimage(
        ENROLLMENT_DOMAIN,
        &[user_id, device_public_key, wireguard_public_key],
    )
}

#[must_use]
pub fn authentication_preimage(challenge_id: &str, device_challenge: &str) -> Vec<u8> {
    preimage(AUTHENTICATION_DOMAIN, &[challenge_id, device_challenge])
}

#[must_use]
pub fn node_enrollment_preimage(node_id: &str, public_key: &str) -> Vec<u8> {
    preimage(NODE_ENROLLMENT_DOMAIN, &[node_id, public_key])
}

#[must_use]
pub fn session_request_preimage(
    session_token: &str,
    action: &str,
    bindings: &[String],
    timestamp: &str,
    nonce: &str,
) -> Vec<u8> {
    let mut values = Vec::with_capacity(bindings.len() + 4);
    values.push(session_token);
    values.push(action);
    values.extend(bindings.iter().map(String::as_str));
    values.push(timestamp);
    values.push(nonce);
    preimage(SESSION_REQUEST_DOMAIN, &values)
}

/// Decodes and validates an Ed25519 raw public key.
///
/// # Errors
///
/// Returns [`DeviceProofError`] for malformed encoding or the wrong length.
pub fn decode_public_key(value: &str) -> Result<[u8; 32], DeviceProofError> {
    decode_fixed(value).ok_or(DeviceProofError::InvalidPublicKey)
}

/// Decodes and validates an Ed25519 signature.
///
/// # Errors
///
/// Returns [`DeviceProofError`] for malformed encoding or the wrong length.
pub fn decode_signature(value: &str) -> Result<[u8; 64], DeviceProofError> {
    decode_fixed(value).ok_or(DeviceProofError::InvalidSignature)
}

#[must_use]
pub fn encode_base64url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(first >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                ALPHABET[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        }
        if chunk.len() > 2 {
            output.push(char::from(ALPHABET[usize::from(third & 0x3f)]));
        }
    }
    output
}

fn preimage(domain: &[u8], values: &[&str]) -> Vec<u8> {
    let mut output = Vec::with_capacity(256);
    output.extend_from_slice(domain);
    for value in values {
        let length = u32::try_from(value.len()).expect("device proof field fits in u32");
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(value.as_bytes());
    }
    output
}

fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    let decoded = decode_base64url(value)?;
    decoded.try_into().ok()
}

fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 4 == 1 || value.contains('=') {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    for chunk in value.as_bytes().chunks(4) {
        let a = decode_character(chunk[0])?;
        let b = decode_character(chunk[1])?;
        output.push((a << 2) | (b >> 4));
        if chunk.len() > 2 {
            let c = decode_character(chunk[2])?;
            output.push((b << 4) | (c >> 2));
            if chunk.len() > 3 {
                let d = decode_character(chunk[3])?;
                output.push((c << 6) | d);
            }
        }
    }
    (encode_base64url(&output) == value).then_some(output)
}

fn decode_character(value: u8) -> Option<u8> {
    match value {
        b'A'..=b'Z' => Some(value - b'A'),
        b'a'..=b'z' => Some(value - b'a' + 26),
        b'0'..=b'9' => Some(value - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trips_device_material() {
        let public_key = [7_u8; 32];
        let signature = [9_u8; 64];
        assert_eq!(
            decode_public_key(&encode_base64url(&public_key)),
            Ok(public_key)
        );
        assert_eq!(
            decode_signature(&encode_base64url(&signature)),
            Ok(signature)
        );
    }

    #[test]
    fn enrollment_and_authentication_domains_are_distinct() {
        assert_ne!(
            enrollment_preimage("user", "key", "wg"),
            authentication_preimage("user", "key")
        );
        assert_ne!(
            authentication_preimage("challenge", "device"),
            session_request_preimage(
                "token",
                "ssh.issue",
                &["binding".to_owned()],
                "100",
                "nonce",
            )
        );
    }
}
