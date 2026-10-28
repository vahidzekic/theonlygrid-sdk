//! A worker's advisory free capacity, gossiped on `/tog/grid/1/availability` (TOG-SPEC-0006 §2.4,
//! TOG-SPEC-0001 §4.2 step 1).

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::hash::{tagged_hash, Domain};
use tog_primitives::Hash32;

use crate::state::Occupancy;
use crate::tx::Signature;
use crate::worker::{HwSignature, WorkerId};

/// Largest message.
pub const AVAILABILITY_MAX: usize = 4 * 1024;
/// Least time between two messages of one worker; a sooner one is ignored.
pub const AVAILABILITY_INTERVAL_SECS: u64 = 30;
/// MIG memory eighths of one GPU.
const EIGHTHS: u8 = 8;

/// Everything but the signature: what the worker key signs.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AvailabilityBody {
    /// Worker.
    pub worker: WorkerId,
    /// Hub height of the occupancy view the message reflects.
    pub height: u64,
    /// Bit `i` set: GPU `i` (order of `HwSignature.gpus`) is free for a whole-GPU booking.
    pub free_gpus: u64,
    /// Per GPU, free MIG eighths `0..=8`; empty when no GPU has MIG mode on.
    pub free_eighths: Vec<u8>,
    /// Free cores.
    pub free_cores: u32,
    /// Free RAM.
    pub free_ram_bytes: u64,
    /// Free scratch.
    pub free_scratch_bytes: u64,
}

/// The gossiped message; Borsh is the body's fields, then `sig`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Availability {
    /// Body.
    pub body: AvailabilityBody,
    /// Variant 0 (Ed25519), by the worker key, over [`AvailabilityBody::digest`].
    pub sig: Signature,
}

impl AvailabilityBody {
    /// What a worker with hardware `hw` and Hub occupancy `occ` at `height` has free. A GPU is free
    /// whole only with nothing booked on it; MIG eighths are listed per GPU when any GPU is
    /// MIG-capable, `0` for one that is not or is booked whole.
    pub fn free(worker: WorkerId, height: u64, hw: &HwSignature, occ: &Occupancy) -> Self {
        let mut free_gpus = 0u64;
        for (i, _) in hw.gpus.iter().enumerate().take(64) {
            let i8 = i as u8;
            if !occ.whole_gpus.contains(&i8) && !occ.mig.contains_key(&i8) {
                free_gpus |= 1 << i;
            }
        }
        let free_eighths = if hw.gpus.iter().any(|g| g.mig_capable) {
            hw.gpus
                .iter()
                .enumerate()
                .map(|(i, g)| match (g.mig_capable, occ.whole_gpus.contains(&(i as u8))) {
                    (true, false) => EIGHTHS.saturating_sub(occ.mig.get(&(i as u8)).map_or(0, |m| m.eighths)),
                    _ => 0,
                })
                .collect()
        } else {
            vec![]
        };
        Self {
            worker,
            height,
            free_gpus,
            free_eighths,
            free_cores: u32::from(hw.cpu_cores).saturating_sub(occ.cores),
            free_ram_bytes: hw.ram_bytes.saturating_sub(occ.ram_bytes),
            free_scratch_bytes: hw.scratch_bytes.saturating_sub(occ.scratch_bytes),
        }
    }

    /// `H("TOG/v1/availability" ‖ borsh(body))`.
    pub fn digest(&self) -> Hash32 {
        tagged_hash(Domain::Availability, &[&borsh::to_vec(self).expect("in-memory borsh cannot fail")])
    }
}

impl Availability {
    /// The stateless check every peer makes before forwarding: exact decoding within
    /// [`AVAILABILITY_MAX`], a variant-0 signature, and its key's address is `worker`.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > AVAILABILITY_MAX {
            return None;
        }
        let msg: Self = borsh::from_slice(bytes).ok()?;
        if !matches!(msg.sig, Signature::Ed25519 { .. }) {
            return None;
        }
        (msg.sig.verify(&msg.body.digest()).ok()? == msg.body.worker).then_some(msg)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::state::MigUse;
    use crate::testing::sample_worker;

    fn sample_hw() -> HwSignature {
        sample_worker(1, &[(8, 0), (8, 0)]).hw
    }

    fn signed(key: &SigningKey, body: AvailabilityBody) -> Vec<u8> {
        let sig =
            Signature::Ed25519 { public_key: key.verifying_key().to_bytes(), sig: key.sign(&body.digest()).to_bytes() };
        borsh::to_vec(&Availability { body, sig }).unwrap()
    }

    #[test]
    fn free_capacity_is_hardware_minus_bookings() {
        let mut hw = sample_hw();
        hw.gpus = vec![hw.gpus[0].clone(); 3];
        hw.gpus[1].mig_capable = true;
        hw.gpus[2].mig_capable = true;
        let occ = Occupancy {
            cores: 2,
            ram_bytes: 1 << 30,
            scratch_bytes: 1,
            whole_gpus: BTreeSet::from([0]),
            mig: BTreeMap::from([(2, MigUse { eighths: 3, jobs: 1 })]),
        };
        let b = AvailabilityBody::free([1; 20], 9, &hw, &occ);
        assert_eq!(b.free_gpus, 0b010);
        assert_eq!(b.free_eighths, vec![0, 8, 5]);
        assert_eq!(b.free_cores, u32::from(hw.cpu_cores) - 2);
        assert_eq!(b.free_ram_bytes, hw.ram_bytes - (1 << 30));
        // Without MIG-capable GPUs the list is empty.
        hw.gpus.iter_mut().for_each(|g| g.mig_capable = false);
        assert!(AvailabilityBody::free([1; 20], 9, &hw, &Occupancy::default()).free_eighths.is_empty());
    }

    #[test]
    fn only_the_workers_own_key_passes() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let me = tog_primitives::ed25519_address(&key.verifying_key().to_bytes());
        let body = AvailabilityBody::free(me, 1, &sample_hw(), &Occupancy::default());
        let ok = signed(&key, body.clone());
        assert_eq!(Availability::decode(&ok).unwrap().body, body);
        // Signed by another key, trailing bytes, or too large.
        assert!(Availability::decode(&signed(&SigningKey::from_bytes(&[4; 32]), body.clone())).is_none());
        assert!(Availability::decode(&[ok.clone(), vec![0]].concat()).is_none());
        let big = AvailabilityBody { free_eighths: vec![0; AVAILABILITY_MAX], ..body };
        assert!(Availability::decode(&signed(&key, big)).is_none());
    }
}
