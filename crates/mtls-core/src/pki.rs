//! Standard X.509 CRL and RFC 6960 OCSP from the shared certificate ledger.
use crate::database::{AuthorityDb, begin};
use der::{
    Decode, Encode,
    asn1::{BitString, ObjectIdentifier},
};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::{MessageDigest, hash},
    pkey::{Id, PKeyRef, Private},
    sign::Signer,
    x509::{
        X509, X509CrlBuilder, X509Ref, X509RevokedBuilder,
        extension::{AuthorityKeyIdentifier, CrlNumber},
    },
};
use sqlx::Row;
use std::{
    collections::HashMap,
    time::{Duration, UNIX_EPOCH},
};
use x509_ocsp::{
    BasicOcspResponse, CertStatus, OcspGeneralizedTime, OcspRequest, OcspResponse, ResponderId,
    ResponseData, RevokedInfo, SingleResponse,
};
type Error = Box<dyn std::error::Error + Send + Sync>;
pub const STATUS_VALIDITY_SECONDS: i64 = 30;

fn time(seconds: i64) -> Result<OcspGeneralizedTime, Error> {
    Ok((UNIX_EPOCH + Duration::from_secs(u64::try_from(seconds)?)).try_into()?)
}

/// # Errors
/// Produces a CA-signed CRL with a globally serialized number, or fails closed.
pub async fn crl(
    db: &AuthorityDb,
    ca_id: &str,
    ca: &X509Ref,
    key: &PKeyRef<Private>,
) -> Result<Vec<u8>, Error> {
    let mut tx = begin(db.pool()).await?;
    let number:i64=sqlx::query_scalar("INSERT INTO issuer.crl_counters(ca_id,number) VALUES($1,1) ON CONFLICT(ca_id) DO UPDATE SET number=issuer.crl_counters.number+1 RETURNING number").bind(ca_id).fetch_one(&mut *tx).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await?;
    let rows=sqlx::query("SELECT serial,revoked_at FROM issuer.certificates WHERE ca_id=$1 AND revoked_at IS NOT NULL AND expires_at>$2 ORDER BY serial").bind(ca_id).bind(now).fetch_all(&mut *tx).await?;
    let mut crl = X509CrlBuilder::new()?;
    crl.set_issuer_name(ca.subject_name())?;
    crl.set_last_update(Asn1Time::from_unix(now)?.as_ref())?;
    crl.set_next_update(Asn1Time::from_unix(now + STATUS_VALIDITY_SECONDS)?.as_ref())?;
    let dummy = X509::builder()?;
    crl.append_extension(
        AuthorityKeyIdentifier::new()
            .issuer(true)
            .build(&dummy.x509v3_context(Some(ca), None))?,
    )?;
    crl.append_extension(CrlNumber::new(BigNum::from_dec_str(&number.to_string())?)?.build()?)?;
    for row in rows {
        let serial: i64 = row.try_get("serial")?;
        let revoked: i64 = row.try_get("revoked_at")?;
        let mut entry = X509RevokedBuilder::new()?;
        entry.set_serial_number(
            Asn1Integer::from_bn(BigNum::from_dec_str(&serial.to_string())?.as_ref())?.as_ref(),
        )?;
        entry.set_revocation_date(Asn1Time::from_unix(revoked)?.as_ref())?;
        crl.add_revoked(entry.build())?;
    }
    crl.sign(key, MessageDigest::sha256())?;
    let bytes = crl.build()?.to_der()?;
    tx.commit().await?;
    Ok(bytes)
}

/// # Errors
/// Verifies `CertID` issuer hashes and signs one shared-snapshot status response.
/// Invalid requests are returned as standard unsuccessful OCSP responses.
pub async fn ocsp(
    db: &AuthorityDb,
    ca_id: &str,
    ca: &X509Ref,
    key: &PKeyRef<Private>,
    request: &[u8],
) -> Result<Vec<u8>, Error> {
    let Ok(request) = OcspRequest::from_der(request) else {
        return Ok(OcspResponse::malformed_request().to_der()?);
    };
    if request.tbs_request.request_list.is_empty() || request.tbs_request.request_list.len() > 32 {
        return Ok(OcspResponse::malformed_request().to_der()?);
    }
    let mut extensions = Vec::new();
    for extension in request
        .tbs_request
        .request_extensions
        .as_deref()
        .unwrap_or_default()
    {
        if extension.extn_id.to_string() == "1.3.6.1.5.5.7.48.1.2" {
            let Some(nonce) = request.nonce() else {
                return Ok(OcspResponse::malformed_request().to_der()?);
            };
            if nonce.0.as_bytes().is_empty()
                || nonce.0.as_bytes().len() > 128
                || !extensions.is_empty()
            {
                return Ok(OcspResponse::malformed_request().to_der()?);
            }
            extensions.push(extension.clone());
        } else if extension.critical {
            return Ok(OcspResponse::malformed_request().to_der()?);
        }
    }
    let ca_typed = x509_cert::Certificate::from_der(&ca.to_der()?)?;
    let subject = ca_typed.tbs_certificate.subject.to_der()?;
    let public_key = ca_typed
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or("unaligned CA key")?;
    let mut serials = Vec::new();
    for entry in &request.tbs_request.request_list {
        if entry
            .single_request_extensions
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|e| e.critical)
        {
            return Ok(OcspResponse::malformed_request().to_der()?);
        }
        let id = &entry.req_cert;
        let digest = match id.hash_algorithm.oid.to_string().as_str() {
            "1.3.14.3.2.26" => MessageDigest::sha1(),
            "2.16.840.1.101.3.4.2.1" => MessageDigest::sha256(),
            _ => return Ok(OcspResponse::unauthorized().to_der()?),
        };
        let matches = hash(digest, &subject)?.as_ref() == id.issuer_name_hash.as_bytes()
            && hash(digest, public_key)?.as_ref() == id.issuer_key_hash.as_bytes();
        let serial = positive_serial(&id.serial_number)?;
        serials.push(if matches { serial } else { None });
    }
    let (now, statuses) = certificate_statuses(db, ca_id, &serials).await?;
    let mut responses = Vec::new();
    for (entry, serial) in request.tbs_request.request_list.into_iter().zip(serials) {
        let cert_status = match serial.and_then(|serial| statuses.get(&serial)) {
            Some(Some(revoked)) => CertStatus::revoked(RevokedInfo {
                revocation_time: time(*revoked)?,
                revocation_reason: None,
            }),
            Some(None) => CertStatus::good(),
            None => CertStatus::unknown(),
        };
        responses.push(SingleResponse {
            cert_id: entry.req_cert,
            cert_status,
            this_update: time(now)?,
            next_update: Some(time(now + STATUS_VALIDITY_SECONDS)?),
            single_extensions: None,
        });
    }
    let data = ResponseData {
        version: x509_ocsp::Version::default(),
        responder_id: ResponderId::ByName(ca_typed.tbs_certificate.subject.clone()),
        produced_at: time(now)?,
        responses,
        response_extensions: (!extensions.is_empty()).then_some(extensions),
    };
    sign_response(data, ca_typed, key)
}

async fn certificate_statuses(
    db: &AuthorityDb,
    ca_id: &str,
    serials: &[Option<i64>],
) -> Result<(i64, HashMap<i64, Option<i64>>), Error> {
    let mut tx = begin(db.pool()).await?;
    let now: i64 =
        sqlx::query_scalar("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await?;
    let ids: Vec<i64> = serials.iter().flatten().copied().collect();
    let rows = sqlx::query(
        "SELECT serial,revoked_at FROM issuer.certificates WHERE ca_id=$1 AND serial=ANY($2)",
    )
    .bind(ca_id)
    .bind(&ids)
    .fetch_all(&mut *tx)
    .await?;
    let statuses: HashMap<i64, Option<i64>> = rows
        .into_iter()
        .map(|row| Ok((row.try_get("serial")?, row.try_get("revoked_at")?)))
        .collect::<Result<_, sqlx::Error>>()?;
    tx.commit().await?;
    Ok((now, statuses))
}

fn sign_response(
    data: ResponseData,
    ca_typed: x509_cert::Certificate,
    key: &PKeyRef<Private>,
) -> Result<Vec<u8>, Error> {
    let algorithm = match key.id() {
        Id::EC => "1.2.840.10045.4.3.2",
        Id::RSA => "1.2.840.113549.1.1.11",
        _ => return Err("unsupported OCSP CA key".into()),
    };
    let mut signer = Signer::new(MessageDigest::sha256(), key)?;
    signer.update(&data.to_der()?)?;
    let signature = signer.sign_to_vec()?;
    let basic = BasicOcspResponse {
        tbs_response_data: data,
        signature_algorithm: spki::AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new(algorithm)?,
            parameters: if key.id() == Id::RSA {
                Some(der::asn1::Any::from_der(&[5, 0])?)
            } else {
                None
            },
        },
        signature: BitString::from_bytes(&signature)?,
        certs: Some(vec![ca_typed]),
    };
    Ok(OcspResponse::successful(basic)?.to_der()?)
}

/// # Errors
/// Encodes standard CRL distribution point and OCSP AIA extensions as DER.
pub fn certificate_extensions(
    origin: &str,
    ca_id: &str,
) -> Result<Vec<openssl::x509::X509Extension>, Error> {
    use x509_cert::ext::pkix::{
        AccessDescription, AuthorityInfoAccessSyntax, CrlDistributionPoints,
        crl::dp::DistributionPoint,
        name::{DistributionPointName, GeneralName},
    };
    let base = format!("{}/v1/pki/{ca_id}", origin.trim_end_matches('/'));
    let crl = CrlDistributionPoints(vec![DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(vec![
            GeneralName::UniformResourceIdentifier(der::asn1::Ia5String::new(&format!(
                "{base}/crl"
            ))?),
        ])),
        reasons: None,
        crl_issuer: None,
    }]);
    let aia = AuthorityInfoAccessSyntax(vec![AccessDescription {
        access_method: ObjectIdentifier::new("1.3.6.1.5.5.7.48.1")?,
        access_location: GeneralName::UniformResourceIdentifier(der::asn1::Ia5String::new(
            &format!("{base}/ocsp"),
        )?),
    }]);
    [
        ("2.5.29.31", crl.to_der()?),
        ("1.3.6.1.5.5.7.1.1", aia.to_der()?),
    ]
    .into_iter()
    .map(|(oid, der)| {
        Ok(openssl::x509::X509Extension::new_from_der(
            openssl::asn1::Asn1Object::from_str(oid)?.as_ref(),
            false,
            openssl::asn1::Asn1OctetString::new_from_bytes(&der)?.as_ref(),
        )?)
    })
    .collect()
}

fn positive_serial(serial: &x509_cert::serial_number::SerialNumber) -> Result<Option<i64>, Error> {
    // Decode the signed INTEGER; interpreting its raw bytes as an unsigned
    // BigNum could alias a negative request serial to an issued positive one.
    Ok(i64::from_der(&serial.to_der()?)
        .ok()
        .filter(|value| *value > 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::serial_number::SerialNumber;

    #[test]
    fn ocsp_serials_do_not_alias_negative_or_oversized_integers() {
        assert_eq!(positive_serial(&SerialNumber::from(1u64)).unwrap(), Some(1));
        assert_eq!(positive_serial(&SerialNumber::from(0u64)).unwrap(), None);
        assert_eq!(
            positive_serial(&SerialNumber::from(u64::MAX)).unwrap(),
            None
        );
        let negative = SerialNumber::from_der(&[0x02, 0x01, 0xff]).unwrap();
        assert_eq!(positive_serial(&negative).unwrap(), None);
    }
}
