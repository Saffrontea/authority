use authority_planning_core::{PlanningError, minimal_indices_checked};

#[test]
fn comparison_budget_discards_previously_found_minima() {
    let items = [1_u8, 2, 3];
    let result = minimal_indices_checked(&items, |a, b| {
        if *a == 3 && *b == 1 {
            Err(PlanningError::SearchLimit)
        } else {
            Ok(a <= b)
        }
    });
    assert_eq!(result, Err(PlanningError::SearchLimit));
}
