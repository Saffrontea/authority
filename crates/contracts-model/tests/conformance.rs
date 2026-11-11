use std::{fs, path::Path};

use authority_contracts_model::{
    AccessAuthorizationBundleV1, IssuanceAuthorizationV1, NetworkAccessGrantV1,
    SignedIssuanceAuthorizationV1, SignedNetworkAccessGrantV1,
};

#[test]
fn valid_vectors_conform_and_have_stable_preimages() {
    for path in vectors("valid") {
        let bytes = fs::read(&path).expect("read valid vector");
        let contract: IssuanceAuthorizationV1 =
            serde_json::from_slice(&bytes).expect("deserialize valid vector");
        contract.validate().expect("validate valid vector");
        let first = contract.signing_preimage().expect("build preimage");
        let second = contract.signing_preimage().expect("rebuild preimage");
        assert_eq!(first, second, "unstable preimage for {}", path.display());

        let golden_path = path.with_extension("preimage.hex");
        let golden = fs::read_to_string(&golden_path).expect("read golden signing preimage");
        assert_eq!(
            encode_hex(&first),
            golden.trim(),
            "signing preimage changed for {}",
            path.display()
        );
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[test]
fn invalid_vectors_are_rejected() {
    for path in vectors("invalid") {
        let bytes = fs::read(&path).expect("read invalid vector");
        let rejected = serde_json::from_slice::<IssuanceAuthorizationV1>(&bytes)
            .map_or(true, |contract| contract.validate().is_err());
        assert!(rejected, "invalid vector was accepted: {}", path.display());
    }
}

#[test]
fn signed_envelope_vectors_conform() {
    for path in envelope_vectors("valid") {
        let bytes = fs::read(&path).expect("read valid envelope vector");
        let contract: SignedIssuanceAuthorizationV1 =
            serde_json::from_slice(&bytes).expect("deserialize valid envelope vector");
        contract.validate().expect("validate envelope vector");
    }

    for path in envelope_vectors("invalid") {
        let bytes = fs::read(&path).expect("read invalid envelope vector");
        let rejected = serde_json::from_slice::<SignedIssuanceAuthorizationV1>(&bytes)
            .map_or(true, |contract| contract.validate().is_err());
        assert!(
            rejected,
            "invalid envelope vector was accepted: {}",
            path.display()
        );
    }
}

#[test]
fn network_grant_vectors_conform() {
    for path in contract_vectors("network-access-grant-v1", "valid") {
        let bytes = fs::read(&path).expect("read valid network grant");
        let grant: NetworkAccessGrantV1 =
            serde_json::from_slice(&bytes).expect("deserialize valid network grant");
        grant.validate().expect("validate network grant");
        let preimage = grant.signing_preimage().expect("build network preimage");
        let golden =
            fs::read_to_string(path.with_extension("preimage.hex")).expect("read network preimage");
        assert_eq!(encode_hex(&preimage), golden.trim());
    }
    for path in contract_vectors("network-access-grant-v1", "invalid") {
        let bytes = fs::read(&path).expect("read invalid network grant");
        let rejected = serde_json::from_slice::<NetworkAccessGrantV1>(&bytes)
            .map_or(true, |grant| grant.validate().is_err());
        assert!(
            rejected,
            "invalid network grant accepted: {}",
            path.display()
        );
    }
}

#[test]
fn signed_network_grant_vectors_conform() {
    for path in contract_vectors("signed-network-access-grant-v1", "valid") {
        let bytes = fs::read(&path).expect("read signed network grant");
        let grant: SignedNetworkAccessGrantV1 =
            serde_json::from_slice(&bytes).expect("deserialize signed network grant");
        grant.validate().expect("validate signed network grant");
    }
    for path in contract_vectors("signed-network-access-grant-v1", "invalid") {
        let bytes = fs::read(&path).expect("read invalid signed network grant");
        let rejected = serde_json::from_slice::<SignedNetworkAccessGrantV1>(&bytes)
            .map_or(true, |grant| grant.validate().is_err());
        assert!(
            rejected,
            "invalid signed network grant accepted: {}",
            path.display()
        );
    }
}

#[test]
fn access_authorization_bundle_vectors_conform() {
    for path in contract_vectors("access-authorization-bundle-v1", "valid") {
        let bytes = fs::read(&path).expect("read access authorization bundle");
        let bundle: AccessAuthorizationBundleV1 =
            serde_json::from_slice(&bytes).expect("deserialize access authorization bundle");
        bundle
            .validate()
            .expect("validate access authorization bundle");
    }
    for path in contract_vectors("access-authorization-bundle-v1", "invalid") {
        let bytes = fs::read(&path).expect("read invalid access authorization bundle");
        let rejected = serde_json::from_slice::<AccessAuthorizationBundleV1>(&bytes)
            .map_or(true, |bundle| bundle.validate().is_err());
        assert!(
            rejected,
            "invalid access authorization bundle accepted: {}",
            path.display()
        );
    }
}

fn contract_vectors(contract: &str, kind: &str) -> Vec<std::path::PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test-vectors")
        .join(contract)
        .join(kind);
    let mut paths: Vec<_> = fs::read_dir(directory)
        .expect("read contract vector directory")
        .map(|entry| entry.expect("read vector entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "contract vector set must not be empty");
    paths
}

fn vectors(kind: &str) -> Vec<std::path::PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test-vectors/issuance-authorization-v1")
        .join(kind);
    let mut paths: Vec<_> = fs::read_dir(directory)
        .expect("read vector directory")
        .map(|entry| entry.expect("read vector entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "contract vector set must not be empty");
    paths
}

fn envelope_vectors(kind: &str) -> Vec<std::path::PathBuf> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/test-vectors/signed-issuance-authorization-v1")
        .join(kind);
    let mut paths: Vec<_> = fs::read_dir(directory)
        .expect("read envelope vector directory")
        .map(|entry| entry.expect("read vector entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "envelope vector set must not be empty");
    paths
}
