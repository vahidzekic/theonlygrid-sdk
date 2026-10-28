use super::*;

const P: CoretimeParams = CoretimeParams { cores: 30, on_demand_cores: 6, launch_price: 1_000, od_min_price: 10 };

#[test]
fn params_need_on_demand_and_bulk_cores() {
    assert!(P.is_well_formed());
    assert_eq!(P.bulk(), 24);
    assert!(!CoretimeParams { on_demand_cores: 0, ..P }.is_well_formed());
    assert!(!CoretimeParams { on_demand_cores: 30, ..P }.is_well_formed());
    assert!(!CoretimeParams { od_min_price: 0, ..P }.is_well_formed());
    assert_eq!(
        CoretimeStatus::genesis(&P),
        CoretimeStatus { period: 0, price: 1_000, next_price: 1_000, od_price: 10 }
    );
}

#[test]
fn prices_follow_the_formulas() {
    // u = 90% leaves the price; full sales +20%; none −30% (clamped); never below 1.
    assert_eq!(adjust(1_000, 9, 10), 1_000);
    assert_eq!(adjust(1_000, 10, 10), 1_200);
    assert_eq!(adjust(1_000, 0, 10), 700);
    assert_eq!(adjust(1, 0, 10), 1);
    assert_eq!(renewal(1_000, 900), 945);
    assert_eq!(renewal(1_000, 990), 1_000);
    // era_length 10: W = 70; open price falls from 2x to 1x over the second week.
    assert_eq!(open_price(1_000, 1_070, 1_000, 10), 2_000);
    assert_eq!(open_price(1_000, 1_105, 1_000, 10), 1_500);
    assert_eq!(open_price(1_000, 1_500, 1_000, 10), 1_000);
    // T = 3: no inclusions decay by 7/8 to the floor; 3 inclusions keep the price.
    assert_eq!(next_od_price(800, 0, &P), 700);
    assert_eq!(next_od_price(800, 3, &P), 800);
    assert_eq!(next_od_price(10, 0, &P), 10);
    assert_eq!(split(1_000), (300, 200, 500));
    assert_eq!((period_length(10), period_of(560, 10), period_of(559, 10)), (280, 2, 1));
}
