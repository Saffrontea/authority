use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::{Html, IntoResponse, Response},
};

use crate::state::AppState;

const CSP_SCRIPT_HASH: &str = "nR1BxaPVh+wefo9yHIs6ghPqaxKUTp1oPzNXi9241Jw=";

pub async fn index(State(state): State<AppState>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&format!(
            "default-src 'none'; script-src 'sha256-{CSP_SCRIPT_HASH}'; style-src 'unsafe-inline'; connect-src 'self' http://localhost:* http://127.0.0.1:* {} ws://localhost:* ws://127.0.0.1:*; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
            state.network_agent_origin(),
        ))
        .expect("static CSP header is valid"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static(
            "publickey-credentials-create=(self), publickey-credentials-get=(self)",
        ),
    );
    (headers, Html(include_str!("../static/index.html"))).into_response()
}

#[cfg(test)]
mod tests {
    use openssl::{base64::encode_block, sha::sha256};

    use super::CSP_SCRIPT_HASH;

    #[test]
    fn inline_script_matches_the_csp_hash() {
        let html = include_str!("../static/index.html");
        let script = html
            .split_once("<script>")
            .and_then(|(_, tail)| tail.split_once("</script>"))
            .map(|(script, _)| script)
            .expect("one inline script");
        assert_eq!(encode_block(&sha256(script.as_bytes())), CSP_SCRIPT_HASH);
    }
}
