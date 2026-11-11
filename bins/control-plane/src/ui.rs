use axum::{
    http::{HeaderMap, HeaderValue, header},
    response::{Html, IntoResponse, Response},
};

pub async fn index() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'sha256-+xTKpxMfYii8vp0AbMvqxQLwTPjd+i2RrgfFjugSEQI='; style-src 'unsafe-inline'; connect-src 'self' http://localhost:* http://127.0.0.1:* http://10.0.3.110:3003; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        ),
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
