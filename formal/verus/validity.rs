use vstd::prelude::*;

verus! {

// Both declarations marked below are generated from production source by the
// checker. This file cannot be checked meaningfully without source injection.
/* PRODUCTION_VALIDITY_STRUCT */

pub open spec fn interval_contains(a: Validity, b: Validity) -> bool {
    0 <= b.not_before as int
        && (a.not_before as int) < (a.expires_at as int)
        && (b.not_before as int) < (b.expires_at as int)
        && a.not_before as int <= b.not_before as int
        && b.expires_at as int <= a.expires_at as int
}

impl Validity {
    pub fn contains(self, other: Self) -> (result: bool)
        ensures
            result == interval_contains(self, other),
            result ==> other.expires_at as int - other.not_before as int
                <= self.expires_at as int - self.not_before as int,
    {
        /* PRODUCTION_VALIDITY_BODY */
    }
}

pub proof fn interval_transitive(a: Validity, b: Validity, c: Validity)
    requires interval_contains(a, b), interval_contains(b, c),
    ensures interval_contains(a, c),
{}

pub proof fn nonempty_and_nonnegative_request(a: Validity, b: Validity)
    requires interval_contains(a, b),
    ensures b.not_before >= 0, b.not_before < b.expires_at,
{}

pub proof fn expired_or_widened_interval_rejected(a: Validity, b: Validity)
    requires b.expires_at <= b.not_before
        || b.not_before < 0
        || b.not_before < a.not_before
        || b.expires_at > a.expires_at,
    ensures !interval_contains(a, b),
{}

} // verus!
