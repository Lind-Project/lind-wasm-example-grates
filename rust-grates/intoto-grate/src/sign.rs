//! The signer: an ECDSA P-256 key made when the grate starts, and DSSE
//! envelopes signed with it.
//!
//! Formats follow in-toto / securesystemslib, so that the usual tools can
//! check the envelopes: the public key is an `ecdsa` / `ecdsa-sha2-nistp256`
//! key with a PEM SubjectPublicKeyInfo, its keyid is the SHA-256 of the key
//! object's canonical JSON, and a signature is the DER-encoded ECDSA
//! signature over SHA-256 of the DSSE pre-authentication encoding (PAE).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{EncodePublicKey, LineEnding};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub const KEYTYPE: &str = "ecdsa";
pub const SCHEME: &str = "ecdsa-sha2-nistp256";

pub struct Signer {
    key: SigningKey,
    public_pem: String,
    keyid: String,
}

impl Signer {
    /// A signer for a fresh key, made from `fill`, which must fill a buffer
    /// with random bytes (the grate passes `getrandom`).
    pub fn generate(mut fill: impl FnMut(&mut [u8]) -> Result<(), String>) -> Result<Self, String> {
        // A random 32-byte string is a valid scalar unless it is zero or not
        // below the group order; that is rare enough to just draw again.
        for _ in 0..16 {
            let mut bytes = [0u8; 32];
            fill(&mut bytes)?;
            if let Ok(key) = SigningKey::from_slice(&bytes) {
                return Self::from_key(key);
            }
        }
        Err("could not draw a valid P-256 key".to_string())
    }

    pub fn from_key(key: SigningKey) -> Result<Self, String> {
        let public_pem = key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| format!("cannot encode the public key: {}", e))?;
        let keyid = hex(&Sha256::digest(
            canonical_json(&key_object(&public_pem)).as_bytes(),
        ));
        Ok(Signer {
            key,
            public_pem,
            keyid,
        })
    }

    pub fn keyid(&self) -> &str {
        &self.keyid
    }

    /// The public key as in-toto expects it, with its keyid.
    pub fn public_key_json(&self) -> Value {
        let mut key = key_object(&self.public_pem);
        key["keyid"] = json!(self.keyid);
        key
    }

    /// A DSSE envelope over `payload`.
    pub fn envelope(&self, payload_type: &str, payload: &[u8]) -> Value {
        let signature: Signature = self.key.sign(&pae(payload_type, payload));
        json!({
            "payloadType": payload_type,
            "payload": BASE64.encode(payload),
            "signatures": [{
                "keyid": self.keyid,
                "sig": BASE64.encode(signature.to_der().as_bytes()),
            }],
        })
    }
}

/// The key object whose canonical JSON the keyid hashes (securesystemslib).
fn key_object(public_pem: &str) -> Value {
    json!({
        "keytype": KEYTYPE,
        "scheme": SCHEME,
        "keyid_hash_algorithms": ["sha256", "sha512"],
        "keyval": { "public": public_pem },
    })
}

/// DSSE pre-authentication encoding.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

/// securesystemslib canonical JSON: sorted keys, no whitespace, and strings
/// with only `\` and `"` escaped (other characters, newlines included, are
/// written as they are).
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                if c == '\\' || c == '"' {
                    out.push('\\');
                }
                out.push(c);
            }
            out.push('"');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(&Value::String((*key).clone()), out);
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::{DerSignature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    fn signer() -> Signer {
        let mut n = 0u8;
        Signer::generate(|buf| {
            for b in buf.iter_mut() {
                n = n.wrapping_add(37);
                *b = n;
            }
            Ok(())
        })
        .unwrap()
    }

    #[test]
    fn pae_matches_the_dsse_spec() {
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[test]
    fn canonical_json_sorts_keys_and_escapes_only_quote_and_backslash() {
        let v = json!({"b": [1, true, null], "a": "x\"y\\z\nw"});
        assert_eq!(
            canonical_json(&v),
            "{\"a\":\"x\\\"y\\\\z\nw\",\"b\":[1,true,null]}"
        );
    }

    #[test]
    fn envelopes_verify_with_the_published_key() {
        let s = signer();
        let key = s.public_key_json();
        assert_eq!(key["keytype"], KEYTYPE);
        assert_eq!(key["scheme"], SCHEME);
        assert_eq!(key["keyid"], s.keyid());
        // The keyid is the hash of the key object without the keyid itself.
        let mut object = key.clone();
        object.as_object_mut().unwrap().remove("keyid");
        assert_eq!(
            hex(&Sha256::digest(canonical_json(&object).as_bytes())),
            s.keyid()
        );

        let env = s.envelope("application/vnd.in-toto+json", b"{\"a\":1}");
        let payload = BASE64.decode(env["payload"].as_str().unwrap()).unwrap();
        assert_eq!(payload, b"{\"a\":1}");
        assert_eq!(env["signatures"][0]["keyid"], s.keyid());

        let pem = key["keyval"]["public"].as_str().unwrap();
        let verifying = VerifyingKey::from_public_key_pem(pem).unwrap();
        let der = BASE64
            .decode(env["signatures"][0]["sig"].as_str().unwrap())
            .unwrap();
        let sig = DerSignature::try_from(der.as_slice()).unwrap();
        let pae = pae("application/vnd.in-toto+json", &payload);
        verifying.verify(&pae, &sig).unwrap();
        assert!(verifying.verify(b"something else", &sig).is_err());
    }
}
