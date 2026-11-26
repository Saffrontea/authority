//! An independent non-network resource: queue namespaces x actions.
use authority_planning_core::authority::{self, Domain, Error, Product, Rule, Space};
use std::collections::BTreeSet;
#[derive(Clone, Debug, PartialEq, Eq)]
struct Names(BTreeSet<u8>);
impl Domain for Names {
    type Error = ();
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    fn intersection(&self, other: &Self) -> Result<Self, ()> {
        Ok(Self(self.0.intersection(&other.0).copied().collect()))
    }
    fn difference(&self, other: &Self) -> Result<Self, ()> {
        Ok(Self(self.0.difference(&other.0).copied().collect()))
    }
    fn complexity(&self) -> usize {
        self.0.len()
    }
}
fn product(names: &[u8], actions: &[u8]) -> Product<Names> {
    Product(vec![
        Names(names.iter().copied().collect()),
        Names(actions.iter().copied().collect()),
    ])
}
#[test]
fn queue_deny_wins_and_split_authorities_cover() {
    let requested = product(&[1, 2], &[3, 4]);
    let allow = Rule {
        identity: "queues",
        space: requested.clone(),
        priority: 0,
        deny: false,
        order: 20,
        provenance: 99,
    };
    let deny = Rule {
        identity: "queues",
        space: product(&[2], &[4]),
        priority: 0,
        deny: true,
        order: 1,
        provenance: 1,
    };
    assert_eq!(
        authority::authorize(&"queues", &requested, &[allow.clone(), deny], 64),
        Err(Error::Denied(1))
    );
    assert_eq!(
        authority::authorize(&"queues", &requested, &[allow], 64),
        Ok(BTreeSet::from([99]))
    );
    assert_eq!(
        authority::covered(
            &[("queues", requested)],
            &[
                ("queues", product(&[1], &[3, 4])),
                ("queues", product(&[2], &[3, 4]))
            ],
            64
        ),
        Ok(true)
    );
    assert_eq!(
        authority::covered(
            &[("queues", product(&[1], &[3]))],
            &[("other", product(&[1], &[3]))],
            64
        ),
        Ok(false)
    );
}
proptest::proptest! {
    #[test]
    fn product_difference_matches_independent_point_oracle(a in proptest::collection::btree_set(0u8..8,0..8),b in proptest::collection::btree_set(0u8..8,0..8),c in proptest::collection::btree_set(0u8..8,0..8),d in proptest::collection::btree_set(0u8..8,0..8)) {
        let left = Product(vec![Names(a.clone()),Names(b.clone())]);
        let right = Product(vec![Names(c.clone()),Names(d.clone())]);
        let pieces = left.difference(&right).unwrap();
        for x in 0..8 { for y in 0..8 {
            let count = pieces.iter().filter(|p|p.0[0].0.contains(&x)&&p.0[1].0.contains(&y)).count();
            proptest::prop_assert_eq!(count,usize::from(a.contains(&x)&&b.contains(&y)&&!(c.contains(&x)&&d.contains(&y))));
        }}
    }
}
