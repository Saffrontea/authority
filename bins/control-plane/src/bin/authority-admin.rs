//! `PoC` management uses the already trusted control-plane signing root.
use authority_contracts_model::administration::{IdentityRevocationCommandV1, IdentitySelector};
use authority_credential_crypto_openssl::OpenSslEd25519Signer;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if !(5..=6).contains(&args.len()) {
        return Err(
            "usage: authority-admin ORIGIN DOMAIN_UUID subject|device ID_UUID [REASON]".into(),
        );
    }
    let domain = args[2].parse::<uuid::Uuid>()?.to_string();
    let id = args[4].parse::<uuid::Uuid>()?.to_string();
    let selector = match args[3].as_str() {
        "subject" => IdentitySelector::Subject {
            subject_user_id: id,
        },
        "device" => IdentitySelector::Device { device_id: id },
        _ => return Err("unknown identity selector".into()),
    };
    let key = std::env::var("AUTHORITY_SIGNING_KEY_FILE")?;
    let signer = OpenSslEd25519Signer::from_pem(
        std::env::var("AUTHORITY_SIGNING_KEY_ID").unwrap_or_else(|_| "control-plane-key-1".into()),
        &std::fs::read(key)?,
    )?;
    let nonce = if let Ok(nonce) = std::env::var("AUTHORITY_OPERATION_NONCE") {
        nonce
    } else {
        let mut bytes = [0_u8; 32];
        openssl::rand::rand_bytes(&mut bytes)?;
        authority_device_auth_core::encode_base64url(&bytes)
    };
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let command = IdentityRevocationCommandV1 {
            version: 1,
            domain_id: domain.clone(),
            selector: selector.clone(),
            nonce: nonce.clone(),
            reason: args.get(5).cloned().unwrap_or_else(|| "compromised".into()),
            issued_at: now,
            expires_at: now + 30,
        };
        let envelope = authority_issuer_core::fence::sign_command(command, &signer)?;
        let response = client
            .post(format!(
                "{}/v1/identity-revocations",
                args[1].trim_end_matches('/')
            ))
            .json(&envelope)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(format!(
                "revocation command rejected: {} {}",
                response.status(),
                response.text().await?
            )
            .into());
        }
        let value: serde_json::Value = response.json().await?;
        if value["completed"] == true {
            println!("{}", serde_json::to_string(&value)?);
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            println!("{}", serde_json::to_string(&value)?);
            return Err("revocation committed; delivery remains pending (reuse AUTHORITY_OPERATION_NONCE to query)".into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
