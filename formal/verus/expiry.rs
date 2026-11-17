use vstd::prelude::*;

verus! {
pub const MIN_TTL_SECONDS: i64 = /* MIN_TTL */;
pub const MAX_TTL_SECONDS: i64 = /* MAX_TTL */;

pub open spec fn valid_ttl_spec(seconds: i64) -> bool {
    MIN_TTL_SECONDS <= seconds <= MAX_TTL_SECONDS
}
#[verifier::when_used_as_spec(valid_ttl_spec)]
pub fn valid_ttl_seconds(seconds: i64) -> (result: bool)
    ensures result == valid_ttl_spec(seconds),
{
    /* PRODUCTION_VALID_TTL */
}

pub open spec fn expiry_spec(issued_at: i64, ttl_seconds: i64) -> Option<i64> {
    if valid_ttl_spec(ttl_seconds)
        && i64::MIN as int <= issued_at as int + ttl_seconds as int <= i64::MAX as int {
        Some((issued_at as int + ttl_seconds as int) as i64)
    } else { None }
}

#[verifier::when_used_as_spec(expiry_spec)]
pub fn projection_expiry(issued_at: i64, ttl_seconds: i64) -> (result: Option<i64>)
    ensures result == expiry_spec(issued_at, ttl_seconds),
{
    /* PRODUCTION_EXPIRY */
}

pub open spec fn lifetime_spec(not_before: i64, expires_at: i64) -> Option<i64> {
    if MIN_TTL_SECONDS <= expires_at as int - not_before as int <= MAX_TTL_SECONDS {
        Some((expires_at as int - not_before as int) as i64)
    } else { None }
}

#[verifier::when_used_as_spec(lifetime_spec)]
pub fn lifetime_seconds(not_before: i64, expires_at: i64) -> (result: Option<i64>)
    ensures result == lifetime_spec(not_before, expires_at),
{
    /* PRODUCTION_LIFETIME */
}

pub proof fn addition_and_subtraction_agree(issued_at: i64, ttl_seconds: i64, projected_end: i64)
    requires expiry_spec(issued_at, ttl_seconds) == Some(projected_end),
    ensures lifetime_spec(issued_at, projected_end) == Some(ttl_seconds),
{}

pub proof fn expiry_round_trip(issued_at: i64, authorized_end: i64)
    requires MIN_TTL_SECONDS <= authorized_end as int - issued_at as int <= MAX_TTL_SECONDS,
    ensures expiry_spec(issued_at, (authorized_end as int - issued_at as int) as i64) == Some(authorized_end),
{}

pub proof fn expiry_no_widening(issued_at: i64, ttl_seconds: i64, authorized_end: i64, projected_end: i64)
    requires expiry_spec(issued_at, ttl_seconds) == Some(projected_end),
        issued_at as int + ttl_seconds as int <= authorized_end as int,
    ensures projected_end <= authorized_end,
{}

} // verus!
