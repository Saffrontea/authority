use authority_policy_core::{
    Effect, PolicyRef,
    ability_policy::PermissionError,
    resources::{Interval, IntervalSet, Region, RegionRule, ResourceError, authorize, uncovered},
};
use proptest::prelude::*;
use uuid::Uuid;

fn set(points: &[bool]) -> IntervalSet {
    IntervalSet::new(
        points
            .iter()
            .enumerate()
            .filter_map(|(i, p)| {
                p.then_some(Interval {
                    start: i as u64,
                    end: i as u64 + 1,
                })
            })
            .collect(),
    )
    .unwrap()
}

fn range(start: u64, end: u64) -> IntervalSet {
    IntervalSet::new(vec![Interval { start, end }]).unwrap()
}

proptest! {
    #[test]
    fn interval_operations_match_independent_point_sets(
        a in prop::collection::vec(any::<bool>(), 32),
        b in prop::collection::vec(any::<bool>(), 32),
        c in prop::collection::vec(any::<bool>(), 32),
    ) {
        let (left,right,third) = (set(&a),set(&b),set(&c));
        let union = left.union(&right).unwrap();
        let intersection = left.intersection(&right).unwrap();
        let difference = left.difference(&right).unwrap();
        for i in 0..32 {
            prop_assert_eq!(union.contains_point(i as u64), a[i] || b[i]);
            prop_assert_eq!(intersection.contains_point(i as u64), a[i] && b[i]);
            prop_assert_eq!(difference.contains_point(i as u64), a[i] && !b[i]);
        }
        prop_assert_eq!(left.is_subset(&right), (0..32).all(|i| !a[i] || b[i]));
        prop_assert_eq!(left.union(&right).unwrap().union(&third).unwrap(), left.union(&right.union(&third).unwrap()).unwrap());
        prop_assert_eq!(left.intersection(&right.union(&third).unwrap()).unwrap(), left.intersection(&right).unwrap().union(&left.intersection(&third).unwrap()).unwrap());
        prop_assert_eq!(difference.union(&intersection).unwrap(), left);
    }

    #[test]
    fn product_difference_matches_independent_grid(
        a in prop::collection::vec(any::<bool>(), 8),
        b in prop::collection::vec(any::<bool>(), 8),
        c in prop::collection::vec(any::<bool>(), 8),
        d in prop::collection::vec(any::<bool>(), 8),
    ) {
        let left = Region([set(&a),set(&b)]);
        let right = Region([set(&c),set(&d)]);
        let pieces = left.difference(&right).unwrap();
        for x in 0..8 { for y in 0..8 {
            let count = pieces.iter().filter(|r| r.0[0].contains_point(x as u64) && r.0[1].contains_point(y as u64)).count();
            prop_assert_eq!(count, usize::from(a[x] && b[y] && !(c[x] && d[y])));
        }}
    }

    #[test]
    fn symbolic_precedence_matches_independent_grid(
        specs in prop::collection::vec((0_u8..8,1_u8..9,0_u8..8,1_u8..9,-2_i32..3,any::<bool>()),0..15),
    ) {
        let rules: Vec<_> = specs.into_iter().enumerate().map(|(i,(a,b,c,d,priority,deny))| RegionRule {
            policy: PolicyRef { policy_id: Uuid::from_u128(i as u128+1), revision: 100-i64::try_from(i).unwrap() },
            priority,
            effect: if deny { Effect::Deny } else { Effect::Allow },
            region: Region([range(u64::from(a.min(b)),u64::from(a.max(b))+1),range(u64::from(c.min(d)),u64::from(c.max(d))+1)]),
        }).collect();
        let expected = (0..8).all(|x| (0..8).all(|y| {
            rules.iter().filter(|r| r.region.0[0].contains_point(x) && r.region.0[1].contains_point(y))
                .max_by_key(|r| (r.priority,r.effect == Effect::Deny,r.policy.policy_id))
                .is_some_and(|r| r.effect == Effect::Allow)
        }));
        let result = authorize(&Region([range(0,8),range(0,8)]),&rules,4096);
        prop_assert_eq!(result.is_ok(),expected);
    }
}

#[test]
fn large_resources_remain_symbolic_and_wire_is_canonical() {
    let subnet = IntervalSet::cidr("10.0.0.0".parse().unwrap(), 8).unwrap();
    let ports = IntervalSet::ports(1024, 65535).unwrap();
    assert_eq!(subnet.intervals().len(), 1);
    assert_eq!(ports.intervals().len(), 1);
    assert_eq!(
        IntervalSet::cidr("0.0.0.0".parse().unwrap(), 0)
            .unwrap()
            .intervals()[0]
            .end,
        1_u64 << 32
    );
    assert!(IntervalSet::cidr("10.0.0.1".parse().unwrap(), 8).is_err());
    let requested = Region([subnet.clone(), subnet, ports]);
    assert!(
        uncovered(&requested, std::slice::from_ref(&requested), 1)
            .unwrap()
            .is_empty()
    );
    assert!(serde_json::to_string(&requested.0[0]).unwrap().len() < 100);
    for invalid in [
        r#"[{"start":1,"end":2},{"start":2,"end":3}]"#,
        r#"[{"start":2,"end":3},{"start":1,"end":2}]"#,
        r#"[{"start":1,"end":1}]"#,
        r#"[{"start":1,"end":2,"ignored":true}]"#,
    ] {
        assert!(serde_json::from_str::<IntervalSet>(invalid).is_err());
    }
}

#[test]
fn mixed_axis_holes_and_budget_exhaustion_never_authorize() {
    let requested = Region([range(0, 10), range(0, 10)]);
    let hole = Region([range(3, 7), range(3, 7)]);
    assert_eq!(
        uncovered(&requested, std::slice::from_ref(&hole), 1),
        Err(ResourceError::Budget)
    );
    let pieces = uncovered(&requested, std::slice::from_ref(&hole), 4).unwrap();
    assert_eq!(pieces.len(), 2);
    let allow = RegionRule {
        policy: PolicyRef {
            policy_id: Uuid::from_u128(1),
            revision: 99,
        },
        priority: 0,
        effect: Effect::Allow,
        region: requested.clone(),
    };
    let deny = RegionRule {
        policy: PolicyRef {
            policy_id: Uuid::from_u128(2),
            revision: 1,
        },
        priority: 0,
        effect: Effect::Deny,
        region: hole,
    };
    assert_eq!(
        authorize(&requested, &[allow.clone(), deny.clone()], 4),
        Err(PermissionError::ExplicitDeny(deny.policy))
    );
    assert_eq!(
        authorize(&requested, &[allow, deny], 1),
        Err(PermissionError::PartitionBudget)
    );
    assert_eq!(uncovered(&requested, &[], 0), Err(ResourceError::Budget));
}
