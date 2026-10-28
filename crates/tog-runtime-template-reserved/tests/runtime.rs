//! The runtime on an in-memory chain (`tog test`): jobs on a scripted Hub reservation.

use tog_runtime_core::{AccountId, ChainId, DispatchError, ModuleError, Origin};
use tog_runtime_modules::{compute, sudo};
use tog_runtime_template_reserved::reserved_compute::{self, fits, Error, Event, CLAIM_WINDOW, MAX_RESERVATION_BYTES};
use tog_runtime_template_reserved::{GenesisConfig, Template, RESERVED_COMPUTE, SUDO};
use tog_runtime_test::TestChain;
use tog_types::job::JobSpec;
use tog_types::reservation::{Beneficiary, Reservation, ReservationOutcome, ReservationSlice, ReservationStatus};
use tog_types::state::{items, Booking, GpuBooking};
use tog_types::testing::sample_spec;

const ALICE: AccountId = [2; 20];
/// The sudo key.
const ROOT: AccountId = [8; 20];
/// The chain.
const CHAIN: ChainId = ChainId(5);
/// The reservation's id on the Hub.
const ID: u64 = 3;

fn chain() -> TestChain<Template> {
    TestChain::new(CHAIN, |author| {
        let config = GenesisConfig {
            balances: vec![(ALICE, 10u128.pow(21)), (ROOT, 10u128.pow(21))],
            authorities: vec![author],
            root_key: Some(ROOT),
        };
        borsh::to_vec(&config).unwrap()
    })
}

/// A slice that `sample_spec()`'s job fills exactly.
fn slice() -> ReservationSlice {
    let hw = sample_spec().hw;
    ReservationSlice {
        gpu: hw.gpu,
        cpu_cores: hw.cpu_cores,
        cpu_isa_level: hw.cpu_isa_level,
        ram_bytes: hw.ram_bytes,
        scratch_bytes: hw.scratch_bytes,
        min_isolation: sample_spec().min_isolation,
    }
}

fn active() -> ReservationStatus {
    let used = Booking { cores: 0, ram_bytes: 0, scratch_bytes: 0, gpus: GpuBooking::None };
    ReservationStatus::Active { worker: [9; 20], start: 1, end: 10_000, gpus: vec![0], bond: 1, used, misses: 0 }
}

/// A reservation for `beneficiary` in worker set `set`, in `status`.
fn reservation(beneficiary: Beneficiary, set: ChainId, status: ReservationStatus) -> Reservation {
    Reservation {
        payer: [7; 20],
        beneficiary,
        worker_set: set,
        slice: slice(),
        duration_blocks: 1_800,
        price_per_block: 10u128.pow(15),
        requested_at: 1,
        match_deadline: 100,
        status,
    }
}

/// The Hub now holds `r` as reservation [`ID`], or none.
fn hub(c: &mut TestChain<Template>, r: Option<&Reservation>) {
    c.set_hub(&items::reservation(ID), r.map(|r| borsh::to_vec(r).unwrap()));
}

fn ours(status: ReservationStatus) -> Reservation {
    reservation(Beneficiary::Chain(CHAIN), CHAIN, status)
}

fn err(e: Error) -> Result<tog_runtime_core::Weight, DispatchError> {
    Err(e.into_dispatch(RESERVED_COMPUTE))
}

fn bind(c: &mut TestChain<Template>, origin: Origin) -> Result<tog_runtime_core::Weight, DispatchError> {
    c.dispatch(origin, reserved_compute::Call::Bind { id: ID }.into_call(RESERVED_COMPUTE)).result
}

/// Governance binds reservation [`ID`] in a block.
fn sudo_bind(c: &mut TestChain<Template>) {
    let bind = reserved_compute::Call::Bind { id: ID }.into_call(RESERVED_COMPUTE);
    c.submit(ROOT, (SUDO, sudo::CALL, borsh::to_vec(&bind).unwrap()));
    c.block();
    let sudid: Vec<sudo::Event> = c.events_of("sudo");
    assert!(matches!(sudid[..], [sudo::Event::Sudid(Ok(()))]), "{sudid:?}");
}

/// `run(spec)` on a budget Alice pays.
fn run(mut spec: JobSpec) -> tog_runtime_modules::executive::Call {
    spec.fee.max_budget = 300;
    reserved_compute::Call::Run { spec, fee: 10u128.pow(16), timeout: None }.into_call(RESERVED_COMPUTE)
}

#[test]
fn only_a_reservation_for_this_chain_is_bound() {
    let mut c = chain();
    assert_eq!(bind(&mut c, Origin::Root), err(Error::NoReservation));
    hub(&mut c, Some(&ours(ReservationStatus::Requested { excluded: vec![] })));
    assert_eq!(bind(&mut c, Origin::Signed(ALICE)), err(Error::BadOrigin));

    // Another chain's, an account's, another worker set's, an ended one, one too large to read.
    let other: AccountId = [4; 20];
    for (r, e) in [
        (reservation(Beneficiary::Chain(ChainId(6)), ChainId(6), active()), Error::NotOurs),
        (reservation(Beneficiary::Account(other), CHAIN, active()), Error::NotOurs),
        (reservation(Beneficiary::Chain(CHAIN), ChainId::HUB, active()), Error::NotOurs),
        (ours(ReservationStatus::Ended { outcome: ReservationOutcome::Completed, at: 5 }), Error::Ended),
        (
            ours(ReservationStatus::Requested { excluded: vec![[1; 20]; MAX_RESERVATION_BYTES / 20] }),
            Error::ReservationTooLarge,
        ),
    ] {
        hub(&mut c, Some(&r));
        assert_eq!(bind(&mut c, Origin::Root), err(e), "{r:?}");
    }
    assert_eq!(reserved_compute::bound(c.state()).unwrap(), None);

    // Still waiting for a worker, it is bound.
    hub(&mut c, Some(&ours(ReservationStatus::Requested { excluded: vec![] })));
    let d = c.dispatch(Origin::Root, reserved_compute::Call::Bind { id: ID }.into_call(RESERVED_COMPUTE));
    assert!(d.result.is_ok(), "{d:?}");
    assert_eq!(reserved_compute::bound(c.state()).unwrap(), Some(ID));

    // Unbound by Root alone, once.
    let unbind = reserved_compute::Call::Unbind {}.into_call(RESERVED_COMPUTE);
    assert_eq!(c.dispatch(Origin::Signed(ALICE), unbind.clone()).result, err(Error::BadOrigin));
    assert!(c.dispatch(Origin::Root, unbind.clone()).result.is_ok());
    assert_eq!(reserved_compute::bound(c.state()).unwrap(), None);
    assert_eq!(c.dispatch(Origin::Root, unbind).result, err(Error::Unbound));
}

#[test]
fn a_job_runs_only_on_the_active_reservation_and_within_its_slice() {
    let mut c = chain();
    let try_run = |c: &mut TestChain<Template>, spec| c.dispatch(Origin::Signed(ALICE), run(spec)).result;
    assert_eq!(try_run(&mut c, sample_spec()), err(Error::Unbound));
    hub(&mut c, Some(&ours(ReservationStatus::Requested { excluded: vec![] })));
    sudo_bind(&mut c);
    assert_eq!(try_run(&mut c, sample_spec()), err(Error::NotActive));

    // Accepted: a job that fits goes out in this chain's worker set, claimable for a window.
    hub(&mut c, Some(&ours(active())));
    let mut spec = sample_spec();
    spec.worker_set = ChainId::HUB;
    c.submit(ALICE, run(spec.clone()));
    c.block();
    assert!(c.outcomes()[0].is_ok(), "{:?}", c.outcomes());
    let request = c.take_compute_requests().remove(0);
    assert_eq!(request.spec.worker_set, CHAIN);
    let relay = request.spec.fee.claim_deadline_height - CLAIM_WINDOW;
    assert!((1..10).contains(&relay), "relay parent {relay}");
    let events: Vec<Event> = c.events_of("reserved_compute");
    assert_eq!(events, [Event::Submitted { job_id: request.job_id, reservation: ID }]);
    let requested: Vec<compute::Event> = c.events_of("compute");
    assert!(
        matches!(requested[..], [compute::Event::Requested { job_id, payer: ALICE, .. }] if job_id == request.job_id)
    );

    // A job larger than the slice is refused.
    let mut large = sample_spec();
    large.hw.cpu_cores += 1;
    assert_eq!(try_run(&mut c, large), err(Error::TooLarge));

    // Ended, or pruned from the Hub: no job runs.
    hub(&mut c, Some(&ours(ReservationStatus::Ended { outcome: ReservationOutcome::Completed, at: 5 })));
    assert_eq!(try_run(&mut c, sample_spec()), err(Error::NotActive));
    hub(&mut c, None);
    assert_eq!(try_run(&mut c, sample_spec()), err(Error::NotActive));
}

#[test]
fn a_slice_fits_no_more_than_it_has() {
    let s = slice();
    let hw = sample_spec().hw;
    assert!(fits(&s, &hw));
    let mut cpu = hw.clone();
    cpu.gpu = None;
    assert!(fits(&s, &cpu), "a CPU job fits a GPU slice");
    assert!(!fits(&ReservationSlice { gpu: None, ..s.clone() }, &hw), "a GPU job on a CPU slice");
    let mut more = hw.clone();
    more.gpu.as_mut().unwrap().count += 1;
    assert!(!fits(&s, &more));
    for grow in [
        |h: &mut tog_types::job::HardwareRequirements| h.ram_bytes += 1,
        |h: &mut tog_types::job::HardwareRequirements| h.scratch_bytes += 1,
        |h: &mut tog_types::job::HardwareRequirements| h.cpu_cores += 1,
    ] {
        let mut h = hw.clone();
        grow(&mut h);
        assert!(!fits(&s, &h), "{h:?}");
    }
}

#[test]
fn another_chain_s_note_reaches_remark() {
    use tog_runtime_modules::remark;
    let mut c = chain();
    let by = tog_runtime_test::CgmpOrigin::Account { chain: ChainId(3), account: [9; 20] };
    let mut call = vec![remark::REMARK];
    call.extend(borsh::to_vec(&(b"hi".to_vec(),)).unwrap());
    let weight_limit = tog_runtime_template_reserved::weights::REMARK_REMARK;
    let payload = tog_runtime_test::CgmpPayload::Call { module: remark::CGMP_NAME, call, weight_limit };
    c.send(ChainId(3), by.clone(), payload, u64::MAX, 0);
    c.block();
    let noted = remark::Event::Remarked { source: ChainId(3), by, data: b"hi".to_vec() };
    assert_eq!(c.events_of::<remark::Event>("remark"), vec![noted]);
}
