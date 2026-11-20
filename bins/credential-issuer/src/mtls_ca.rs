use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    },
};

pub struct MtlsCa {
    pub key: PKey<Private>,
    pub certificate: X509,
}

pub fn load_or_generate(
    key_path: &Path,
    cert_path: &Path,
) -> Result<MtlsCa, Box<dyn std::error::Error>> {
    if key_path.try_exists()? != cert_path.try_exists()? {
        return Err("mTLS CA key and certificate must both exist or both be absent".into());
    }
    if key_path.try_exists()? {
        let key = PKey::private_key_from_pem(&fs::read(key_path)?)?;
        let certificate = X509::from_pem(&fs::read(cert_path)?)?;
        if !certificate.public_key()?.public_eq(&key) {
            return Err("mTLS CA key does not match certificate".into());
        }
        return Ok(MtlsCa { key, certificate });
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", "Authority PoC mTLS CA")?;
    let name = name.build();
    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;
    let serial = Asn1Integer::from_bn(&serial)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&key)?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(3650)?.as_ref())?;
    builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;
    builder.append_extension(
        SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?,
    )?;
    builder.sign(&key, MessageDigest::sha256())?;
    let certificate = builder.build();
    let mut key_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(key_path)?;
    key_file.write_all(&key.private_key_to_pem_pkcs8()?)?;
    key_file.sync_all()?;
    let mut cert_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(cert_path)?;
    cert_file.write_all(&certificate.to_pem()?)?;
    cert_file.sync_all()?;
    Ok(MtlsCa { key, certificate })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn partial_ca_state_is_rejected_without_touching_existing_material() {
        for key_exists in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let key = directory.path().join("ca.key");
            let certificate = directory.path().join("ca.pem");
            let existing = if key_exists { &key } else { &certificate };
            fs::write(existing, b"must not be overwritten").unwrap();
            assert!(load_or_generate(&key, &certificate).is_err());
            assert_eq!(fs::read(existing).unwrap(), b"must not be overwritten");
            assert_eq!(key.exists(), key_exists);
            assert_eq!(certificate.exists(), !key_exists);
        }
    }

    #[test]
    fn generated_key_is_private_and_restart_preserves_the_ca() {
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("ca.key");
        let certificate = directory.path().join("ca.pem");
        let generated = load_or_generate(&key, &certificate).unwrap();
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let original = fs::read(&key).unwrap();
        let loaded = load_or_generate(&key, &certificate).unwrap();
        assert_eq!(fs::read(&key).unwrap(), original);
        assert_eq!(
            generated.certificate.to_der().unwrap(),
            loaded.certificate.to_der().unwrap()
        );
    }
}
