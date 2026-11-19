use std::{fs, os::unix::fs::PermissionsExt, path::Path};

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
    if key_path.exists() && cert_path.exists() {
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
    fs::write(key_path, key.private_key_to_pem_pkcs8()?)?;
    fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
    fs::write(cert_path, certificate.to_pem()?)?;
    Ok(MtlsCa { key, certificate })
}
