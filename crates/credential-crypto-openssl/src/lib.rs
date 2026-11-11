//! In-process OpenSSL adapter for Ed25519 signing and verification.

use std::{fs, path::Path};

use authority_issuer_core::{AuthorizationSigner, AuthorizationVerifier, CryptoError};
use openssl::{
    pkey::{Id, PKey, Private, Public},
    sign::{Signer, Verifier},
};

/// Verifies an Ed25519 signature using a raw 32-byte device public key.
///
/// # Errors
///
/// Returns an error when OpenSSL cannot construct or use the key.
pub fn verify_device_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<bool, CryptoError> {
    let key = PKey::public_key_from_raw_bytes(public_key, Id::ED25519).map_err(crypto_error)?;
    let mut verifier = Verifier::new_without_digest(&key).map_err(crypto_error)?;
    verifier
        .verify_oneshot(signature, message)
        .map_err(crypto_error)
}

pub struct OpenSslEd25519Signer {
    key_id: String,
    private_key: PKey<Private>,
}

pub struct OpenSslEd25519Verifier {
    key_id: String,
    public_key: PKey<Public>,
}

impl OpenSslEd25519Signer {
    /// Generates a new in-memory Ed25519 private key.
    ///
    /// # Errors
    ///
    /// Returns an error when OpenSSL cannot generate the key.
    pub fn generate(key_id: impl Into<String>) -> Result<Self, CryptoError> {
        Ok(Self {
            key_id: key_id.into(),
            private_key: PKey::generate_ed25519().map_err(crypto_error)?,
        })
    }

    /// Loads an unencrypted PEM private key into memory.
    ///
    /// # Errors
    ///
    /// Returns an error when the PEM cannot be decoded or is not an Ed25519 key.
    pub fn from_pem(key_id: impl Into<String>, pem: &[u8]) -> Result<Self, CryptoError> {
        let private_key = PKey::private_key_from_pem(pem).map_err(crypto_error)?;
        ensure_ed25519(private_key.id())?;
        Ok(Self {
            key_id: key_id.into(),
            private_key,
        })
    }

    /// Reads an unencrypted PEM private key once, during adapter construction.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, the PEM cannot be decoded,
    /// or the key is not Ed25519.
    pub fn from_pem_file(
        key_id: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> Result<Self, CryptoError> {
        let pem = fs::read(path).map_err(crypto_error)?;
        Self::from_pem(key_id, &pem)
    }

    /// Encodes the private key as unencrypted PKCS#8 PEM.
    ///
    /// # Errors
    ///
    /// Returns an error when OpenSSL cannot encode the key.
    pub fn private_key_to_pem(&self) -> Result<Vec<u8>, CryptoError> {
        self.private_key
            .private_key_to_pem_pkcs8()
            .map_err(crypto_error)
    }

    /// Encodes the corresponding public key as PEM `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    ///
    /// Returns an error when OpenSSL cannot encode the key.
    pub fn public_key_to_pem(&self) -> Result<Vec<u8>, CryptoError> {
        self.private_key.public_key_to_pem().map_err(crypto_error)
    }
}

impl OpenSslEd25519Verifier {
    /// Loads a PEM `SubjectPublicKeyInfo` public key into memory.
    ///
    /// # Errors
    ///
    /// Returns an error when the PEM cannot be decoded or is not an Ed25519 key.
    pub fn from_pem(key_id: impl Into<String>, pem: &[u8]) -> Result<Self, CryptoError> {
        let public_key = PKey::public_key_from_pem(pem).map_err(crypto_error)?;
        ensure_ed25519(public_key.id())?;
        Ok(Self {
            key_id: key_id.into(),
            public_key,
        })
    }

    /// Reads a PEM public key once, during adapter construction.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, the PEM cannot be decoded,
    /// or the key is not Ed25519.
    pub fn from_pem_file(
        key_id: impl Into<String>,
        path: impl AsRef<Path>,
    ) -> Result<Self, CryptoError> {
        let pem = fs::read(path).map_err(crypto_error)?;
        Self::from_pem(key_id, &pem)
    }
}

impl AuthorizationSigner for OpenSslEd25519Signer {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut signer = Signer::new_without_digest(&self.private_key).map_err(crypto_error)?;
        signer.sign_oneshot_to_vec(message).map_err(crypto_error)
    }
}

impl AuthorizationVerifier for OpenSslEd25519Verifier {
    fn verify(&self, key_id: &str, message: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        if key_id != self.key_id {
            return Ok(false);
        }
        let mut verifier = Verifier::new_without_digest(&self.public_key).map_err(crypto_error)?;
        verifier
            .verify_oneshot(signature, message)
            .map_err(crypto_error)
    }
}

fn ensure_ed25519(id: Id) -> Result<(), CryptoError> {
    if id == Id::ED25519 {
        Ok(())
    } else {
        Err(CryptoError {
            message: "expected an Ed25519 key".to_owned(),
        })
    }
}

fn crypto_error(error: impl std::fmt::Display) -> CryptoError {
    CryptoError {
        message: error.to_string(),
    }
}
