//! Property tests over the consensus objects that arrive as bytes: transactions, state values
//! read from the Hub (deals, challenges, records), and the frames of the conf-key, AppChain and
//! erasure protocols. Whatever the bytes, decoding returns a value or an error and never panics;
//! what decodes encodes back to the same bytes, so no object has two encodings.

use borsh::{BorshDeserialize, BorshSerialize};
use proptest::collection::vec;
use proptest::prelude::*;
use tog_types::{appchain, availability, channel, enclave, endpoint, erasure, hub_key, por, state, storage, worker};
use tog_types::{SignedTx, TxBody};

fn config(cases: u32) -> ProptestConfig {
    ProptestConfig { cases, failure_persistence: None, ..ProptestConfig::default() }
}

/// Bytes whose first byte is an enum variant in `0..types`.
fn tagged(types: u8, len: usize) -> impl Strategy<Value = Vec<u8>> {
    (0..types, vec(any::<u8>(), 0..len)).prop_map(|(t, body)| [vec![t], body].concat())
}

/// `T` from `bytes` is the one value whose encoding is `bytes`.
fn canonical<T: BorshDeserialize + BorshSerialize + PartialEq + std::fmt::Debug>(
    bytes: &[u8],
) -> Result<(), TestCaseError> {
    if let Ok(v) = borsh::from_slice::<T>(bytes) {
        prop_assert_eq!(borsh::to_vec(&v).unwrap(), bytes, "{:?}", v);
    }
    Ok(())
}

proptest! {
    #![proptest_config(config(2048))]

    #[test]
    fn transactions(bytes in tagged(64, 400)) {
        canonical::<TxBody>(&bytes)?;
        canonical::<SignedTx>(&bytes)?;
    }

    #[test]
    fn storage_state(bytes in vec(any::<u8>(), 0..400)) {
        canonical::<storage::StorageDeal>(&bytes)?;
        canonical::<storage::HolderSlot>(&bytes)?;
        canonical::<por::RetrievabilityChallenge>(&bytes)?;
        canonical::<por::ChallengeResponse>(&bytes)?;
        canonical::<state::StateProof>(&bytes)?;
    }

    #[test]
    fn records_and_vouchers(bytes in vec(any::<u8>(), 0..400)) {
        canonical::<channel::SignedVoucher>(&bytes)?;
        canonical::<endpoint::EndpointRecord>(&bytes)?;
        canonical::<hub_key::IbeCiphertext>(&bytes)?;
        if let Ok(r) = worker::WorkerRecord::decode(&bytes) {
            prop_assert_eq!(&borsh::to_vec(&r).unwrap(), &bytes);
        }
        if let Some(a) = availability::Availability::decode(&bytes) {
            prop_assert_eq!(availability::Availability::decode(&borsh::to_vec(&a).unwrap()), Some(a));
        }
        let _ = enclave::decode_enclaves(&bytes);
    }

    #[test]
    fn conf_key_messages(bytes in vec(any::<u8>(), 0..600)) {
        if let Some(m) = enclave::ConfKeyRequest::decode(&bytes) {
            prop_assert_eq!(enclave::ConfKeyRequest::decode(&borsh::to_vec(&m).unwrap()), Some(m));
        }
        if let Some(m) = enclave::DeliverConfKey::decode(&bytes) {
            prop_assert_eq!(enclave::DeliverConfKey::decode(&borsh::to_vec(&m).unwrap()), Some(m));
        }
        if let Some(m) = enclave::ShareRequest::decode_frame(&bytes) {
            prop_assert_eq!(enclave::ShareRequest::decode_frame(&m.encode_frame()), Some(m));
        }
        if let Some(m) = enclave::ConfShare::decode_frame(&bytes) {
            prop_assert_eq!(enclave::ConfShare::decode_frame(&m.encode_frame()), Some(m));
        }
    }

    #[test]
    fn appchain_frames(bytes in tagged(8, 600)) {
        if let Some(m) = appchain::Collation::decode_frame(&bytes) {
            prop_assert_eq!(appchain::Collation::decode_frame(&m.encode_frame()), Some(m));
        }
        if let Some(m) = appchain::CollateResponse::decode_frame(&bytes) {
            prop_assert_eq!(appchain::CollateResponse::decode_frame(&m.encode_frame()), Some(m));
        }
        if let Some(m) = appchain::PovRequest::decode_frame(&bytes) {
            prop_assert_eq!(appchain::PovRequest::decode_frame(&m.encode_frame()), Some(m));
        }
        if let Some(m) = appchain::PovResponse::decode_frame(&bytes) {
            prop_assert_eq!(appchain::PovResponse::decode_frame(&m.encode_frame()), Some(m));
        }
    }

    #[test]
    fn erasure_frames(bytes in tagged(8, 600)) {
        if let Some(m) = erasure::ChunkRequest::decode_frame(&bytes) {
            prop_assert_eq!(erasure::ChunkRequest::decode_frame(&m.encode_frame()), Some(m));
        }
        if let Some(m) = erasure::ChunkResponse::decode_frame(&bytes) {
            prop_assert_eq!(erasure::ChunkResponse::decode_frame(&m.encode_frame()), Some(m));
        }
    }

    /// Valid objects with a few bytes changed reach the checks deep inside them.
    #[test]
    fn damaged_jobs_and_records(flips in vec((any::<usize>(), 1u8..), 1..6), cut in any::<prop::sample::Index>()) {
        let job = borsh::to_vec(&TxBody::SubmitJob(Box::new(tog_types::testing::sample_job()))).unwrap();
        let record = borsh::to_vec(&tog_types::testing::sample_worker(3, &[(90, 550), (80, 535)])).unwrap();
        for valid in [&job, &record] {
            let damaged = mutated(valid, &flips);
            canonical::<TxBody>(&damaged)?;
            let _ = worker::WorkerRecord::decode(&damaged);
            canonical::<worker::WorkerRecord>(&damaged)?;
        }
        // Cut short, neither decodes.
        prop_assert!(borsh::from_slice::<TxBody>(&job[..cut.index(job.len())]).is_err());
        prop_assert!(worker::WorkerRecord::decode(&record[..cut.index(record.len())]).is_err());
    }

    /// A length prefix of any size costs no allocation of that size: borsh grows vectors as
    /// their elements decode.
    #[test]
    fn huge_length_prefixes_fail_short(len in any::<u32>(), body in vec(any::<u8>(), 0..64)) {
        let bytes = [&len.to_le_bytes()[..], &body].concat();
        let _ = borsh::from_slice::<Vec<storage::HolderSlot>>(&bytes);
        let _ = borsh::from_slice::<Vec<Vec<u8>>>(&bytes);
        let _ = borsh::from_slice::<state::StateProof>(&[&[1u8][..], &[0; 64], &bytes].concat());
    }
}

/// `bytes` with each `(position, mask)` xor-ed in, positions taken modulo the length.
fn mutated(bytes: &[u8], flips: &[(usize, u8)]) -> Vec<u8> {
    let mut b = bytes.to_vec();
    for &(i, m) in flips {
        let n = b.len();
        b[i % n] ^= m;
    }
    b
}
