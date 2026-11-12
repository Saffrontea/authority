use axum::{
    http::{HeaderMap, HeaderValue, header},
    response::{Html, IntoResponse, Response},
};

const CSP_SCRIPT_HASH: &str = "NS8ldf9B3olgiQH7UOtljzxBIu+QnfvoNz9mkXTN1SY=";

pub async fn index() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&format!(
            "default-src 'none'; script-src 'sha256-{CSP_SCRIPT_HASH}'; style-src 'unsafe-inline'; connect-src 'self' http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:*; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
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
    use openssl::sha::sha256;

    use super::CSP_SCRIPT_HASH;

    #[test]
    fn inline_script_matches_the_csp_hash() {
        let html = include_str!("../static/index.html");
        let script = html
            .split_once("<script>")
            .and_then(|(_, tail)| tail.split_once("</script>"))
            .map(|(script, _)| script)
            .expect("one inline script");
        assert_eq!(encode_base64(&sha256(script.as_bytes())), CSP_SCRIPT_HASH);
    }

    fn encode_base64(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);
            output.push(char::from(ALPHABET[usize::from(chunk[0] >> 2)]));
            output.push(char::from(
                ALPHABET[usize::from(((chunk[0] & 3) << 4) | (second >> 4))],
            ));
            output.push(if chunk.len() > 1 {
                char::from(ALPHABET[usize::from(((second & 15) << 2) | (third >> 6))])
            } else {
                '='
            });
            output.push(if chunk.len() > 2 {
                char::from(ALPHABET[usize::from(third & 63)])
            } else {
                '='
            });
        }
        output
    }
}
