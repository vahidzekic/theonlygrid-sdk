//! Objects of the Hub threshold key EK (TOG-SPEC-0009): IBE ciphertexts, encrypted
//! user-lane transactions, checkpoint key escrow and job resume points.
//! `EncryptedTx` and `KeyEscrowTx` are `TxBody` variants 10 and 11.

#[cfg(not(feature = "std"))]
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_primitives::segment::{segment_genesis, segment_link};
use tog_primitives::{tagged_hash, Address, Amount, Domain, Hash32};

use crate::checkpoint::CheckpointCommitment;
use crate::job::EscrowRef;

/// Keys released through vote extensions besides the beacon and mempool (TOG-SPEC-0009 §3.3).
pub const MAX_ESCROW_RELEASES: usize = 4;

/// Escrowed keys that may fail their commitment before a lost job restarts from segment 0
/// (TOG-SPEC-0009 §5.4 rule 2).
pub const RESUME_TRIES: u8 = 3;

/// `L_escrow` in blocks (TOG-SPEC-0009 §5.2 rule 3): how long a segmented job's claim lasts past
/// its last escrow, or past the claim before the first: `max_segment_wall_time_secs / 2 s × 2 +
/// T_place(checkpoint_max_bytes)` on network `network_id`, `T_place` over the `r` slots of the
/// job's `ChallengeWindow` checkpoint deal (TOG-SPEC-0004 §4.4). Saturates.
pub fn l_escrow(max_segment_wall_time_secs: u64, checkpoint_max_bytes: u64, network_id: u32) -> u64 {
    use crate::storage::{t_place_slots, CHALLENGE_WINDOW_REPLICAS};
    let place = t_place_slots(checkpoint_max_bytes, u64::from(CHALLENGE_WINDOW_REPLICAS), network_id);
    max_segment_wall_time_secs.saturating_add(place)
}

/// Keys by epoch: the current one, and the previous one while it has live ciphertexts
/// (TOG-SPEC-0009 §2.4).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KeyEpoch {
    /// Epoch; a fresh DKG increments it, resharing keeps it.
    pub ek_epoch: u32,
    /// `EK`.
    pub ek: [u8; 48],
    /// `EK_i` by validator index, derived from the transcript.
    pub share_keys: Vec<[u8; 48]>,
    /// `t` for the set holding the shares.
    pub threshold: u16,
}

/// Something only `t` validators together can sign (TOG-SPEC-0009 §1.3): the key for identity
/// `id` is the threshold BLS signature on it. Borsh index = position; `threshold_key.release_queue`
/// holds these.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
pub enum Identity {
    /// 0: beacon of height `h` (`TOG/v1/beacon`).
    Beacon(u64),
    /// 1: decryption key of the encrypted transactions of height `h` (`TOG/v1/mempool`).
    Mempool(u64),
    /// 2: escrowed checkpoint key `k_n` of a job (`TOG/v1/key-escrow`).
    KeyEscrow {
        /// Job.
        job_id: Hash32,
        /// Segment.
        segment: u32,
    },
    /// 3: `K_conf` of a confidential job under the Hub broker, by its escrow (`TOG/v1/conf-key`,
    /// TOG-SPEC-0010 §4.2). Its shares go only to enclaves, off-chain.
    ConfKey(EscrowRef),
}

impl Identity {
    /// The domain whose tag is the hash-to-curve DST.
    pub fn domain(&self) -> Domain {
        match self {
            Identity::Beacon(_) => Domain::Beacon,
            Identity::Mempool(_) => Domain::Mempool,
            Identity::KeyEscrow { .. } => Domain::KeyEscrow,
            Identity::ConfKey(_) => Domain::ConfKey,
        }
    }

    /// The tag, used as the hash-to-curve DST.
    pub fn tag(&self) -> &'static str {
        self.domain().tag()
    }

    /// The fixed-width fields after the tag, integers little-endian.
    pub fn fields(&self) -> Vec<u8> {
        match self {
            Identity::Beacon(h) | Identity::Mempool(h) => h.to_le_bytes().to_vec(),
            Identity::KeyEscrow { job_id, segment } => [&job_id[..], &segment.to_le_bytes()].concat(),
            Identity::ConfKey(escrow) => escrow.0.to_vec(),
        }
    }

    /// `Q_id = hash_to_G2(fields, DST = tag)` (RFC 9380, `BLS12381G2_XMD:SHA-256_SSWU_RO_`).
    pub fn point(&self) -> bls12_381::G2Affine {
        crate::ibe::identity_point(self.domain(), &self.fields())
    }
}

/// Fujisaki–Okamoto IBE ciphertext under EK (TOG-SPEC-0009 §1.2). 116 bytes in Borsh.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct IbeCiphertext {
    /// Which EK; 0 until the first rotation.
    pub ek_epoch: u32,
    /// `r · g1`.
    pub u: [u8; 48],
    /// `σ ⊕ H("TOG/v1/ibe-mask" ‖ e(EK, Q_id)^r)`.
    pub v: [u8; 32],
    /// `m ⊕ H("TOG/v1/ibe-msg" ‖ σ)`.
    pub w: [u8; 32],
}

/// Allowed padded sizes of `EncryptedTx.body` plaintext (TOG-SPEC-0009 §4.1).
pub const ENCRYPTED_BODY_SIZES: [usize; 3] = [256, 1024, 4096];

/// Encrypted user-lane transaction (TOG-SPEC-0009 §4.1), `TxBody` variant 10.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EncryptedTx {
    /// Replay domain of the Hub.
    pub chain_id: u64,
    /// Pays gas whatever happens to the inner transaction.
    pub payer: Address,
    /// Payer nonce.
    pub nonce: u64,
    /// Must be included exactly at this height.
    pub target_height: u64,
    /// Covers the inner transaction.
    pub gas_limit: u64,
    /// Fee cap.
    pub max_fee_per_gas: Amount,
    /// Body key under identity (`TOG/v1/mempool`, `target_height`).
    pub key: IbeCiphertext,
    /// ChaCha20-Poly1305 of the padded `borsh(SignedTx)`.
    pub body: Vec<u8>,
}

/// Poly1305 tag length.
const AEAD_TAG: usize = 16;

impl EncryptedTx {
    /// The ciphertext length must be one of the padded sizes plus the AEAD tag.
    pub fn has_valid_body_size(&self) -> bool {
        ENCRYPTED_BODY_SIZES.iter().any(|&s| self.body.len() == s + AEAD_TAG)
    }
}

/// Blocks an `EncryptedTx` waits in `threshold_key.encrypted[h]` for its key: the item is deleted
/// at the end of block `h + ENCRYPTED_WAIT` (TOG-SPEC-0009 §4.2 rule 4).
pub const ENCRYPTED_WAIT: u64 = 600;

/// `ReleasedKeys` for `h` is valid from block `h + RELEASE_AFTER` (TOG-SPEC-0009 §4.2 rule 3).
pub const RELEASE_AFTER: u64 = 2;

/// Why an `EncryptedTx` body yields no inner transaction (TOG-SPEC-0009 §4.2 rules 1–2); the
/// payer's fee stays charged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    /// `body.len()` is not 272, 1 040 or 4 112: invalid at inclusion.
    #[error("body is not a padded size plus the tag")]
    Size,
    /// The AEAD tag doesn't verify under the body key.
    #[error("body does not decrypt")]
    Aead,
    /// The plaintext doesn't start with a Borsh `SignedTx`.
    #[error("plaintext is not a transaction")]
    Decode,
    /// A byte after the transaction is not 0, or the padding goes past the smallest size that
    /// fits the transaction.
    #[error("padding is not zero bytes up to the smallest size that fits")]
    Padding,
    /// The inner transaction is not a user-lane variant, or is itself `SubmitEncrypted`.
    #[error("inner transaction is not a plain user-lane transaction")]
    Lane,
}

fn aead(body_key: &[u8; 32]) -> chacha20poly1305::ChaCha20Poly1305 {
    use chacha20poly1305::KeyInit;
    chacha20poly1305::ChaCha20Poly1305::new(body_key.into())
}

impl EncryptedTx {
    /// `aad = H("TOG/v1/enc-tx" ‖ borsh((chain_id, payer, nonce, target_height, key)))`: the
    /// envelope's own fields, so a body copied into another envelope fails to open (TOG-SPEC-0009
    /// §4.2 rule 1).
    pub fn aad(&self) -> Hash32 {
        let fields = (self.chain_id, self.payer, self.nonce, self.target_height, &self.key);
        tagged_hash(Domain::EncTx, &[&borsh::to_vec(&fields).expect("in-memory borsh cannot fail")])
    }

    /// The digest the inner transaction's key signs (TOG-SPEC-0009 §4.2 rule 5):
    /// `H("TOG/v1/enc-inner" ‖ borsh((chain_id, payer, nonce, target_height)) ‖ borsh(body))`, over
    /// this envelope's fields, never the plaintext `H("TOG/v1/tx" ‖ borsh(body))`. The inner
    /// transaction then runs only from this envelope, and nobody who reads it once the mempool key
    /// is out can replay it in the plaintext lane, in another envelope or at another height.
    pub fn inner_signing_hash(&self, body: &crate::tx::TxBody) -> Hash32 {
        let fields = (self.chain_id, self.payer, self.nonce, self.target_height);
        let fields = borsh::to_vec(&fields).expect("in-memory borsh cannot fail");
        tagged_hash(Domain::EncInner, &[&fields, &borsh::to_vec(body).expect("in-memory borsh cannot fail")])
    }

    /// Verifies `inner`'s signature over [`EncryptedTx::inner_signing_hash`] and returns its signer.
    /// An EIP-712 signature covers a transaction digest, never this one, so it is rejected.
    pub fn inner_signer(&self, inner: &crate::tx::SignedTx) -> Result<Address, crate::signing::SignatureError> {
        if matches!(inner.sig, crate::tx::Signature::Secp256k1Eip712(_)) {
            return Err(crate::signing::SignatureError::Invalid);
        }
        inner.sig.verify(&self.inner_signing_hash(&inner.body))
    }

    /// Signs `body` with an Ed25519 key as the inner transaction of this envelope, over
    /// [`EncryptedTx::inner_signing_hash`]. Seal it with [`EncryptedTx::seal_body`] after the
    /// envelope's fields are final.
    pub fn sign_inner_ed25519(&self, body: crate::tx::TxBody, key: &ed25519_dalek::SigningKey) -> crate::tx::SignedTx {
        use ed25519_dalek::Signer;
        let sig = key.sign(&self.inner_signing_hash(&body)).to_bytes();
        crate::tx::SignedTx {
            body,
            sig: crate::tx::Signature::Ed25519 { public_key: key.verifying_key().to_bytes(), sig },
        }
    }

    /// Seals `inner` into `self.body` (TOG-SPEC-0009 §4.2 rule 1): `borsh(inner)` and zero bytes up
    /// to the smallest of [`ENCRYPTED_BODY_SIZES`] that fits it, ChaCha20-Poly1305 under
    /// `body_key` (fresh per transaction), nonce 12 zero bytes, AAD [`EncryptedTx::aad`]. Fails,
    /// leaving `self` as it was, if `inner` is longer than 4 096 bytes.
    pub fn seal_body(&mut self, body_key: &[u8; 32], inner: &crate::tx::SignedTx) -> Result<(), OpenError> {
        use chacha20poly1305::aead::{Aead, Payload};
        let mut plain = borsh::to_vec(inner).expect("in-memory borsh cannot fail");
        let size = ENCRYPTED_BODY_SIZES.into_iter().find(|&s| plain.len() <= s).ok_or(OpenError::Size)?;
        plain.resize(size, 0);
        let aad = self.aad();
        let payload = Payload { msg: plain.as_slice(), aad: &aad };
        self.body = aead(body_key).encrypt(&[0u8; 12].into(), payload).map_err(|_| OpenError::Aead)?;
        Ok(())
    }

    /// The inner transaction (TOG-SPEC-0009 §4.2 rules 1–2): the body decrypted under `body_key`
    /// with AAD [`EncryptedTx::aad`], read as one Borsh `SignedTx` followed only by zero bytes,
    /// up to the smallest of [`ENCRYPTED_BODY_SIZES`] that fits it, and a user-lane variant other
    /// than `SubmitEncrypted`. Its signature is the caller's to check, with [`EncryptedTx::inner_signer`].
    pub fn open_body(&self, body_key: &[u8; 32]) -> Result<crate::tx::SignedTx, OpenError> {
        use chacha20poly1305::aead::{Aead, Payload};
        if !self.has_valid_body_size() {
            return Err(OpenError::Size);
        }
        let aad = self.aad();
        let payload = Payload { msg: self.body.as_slice(), aad: &aad };
        let plain = aead(body_key).decrypt(&[0u8; 12].into(), payload).map_err(|_| OpenError::Aead)?;
        let mut rest = plain.as_slice();
        let inner = <crate::tx::SignedTx as BorshDeserialize>::deserialize(&mut rest).map_err(|_| OpenError::Decode)?;
        let used = plain.len() - rest.len();
        let smallest = ENCRYPTED_BODY_SIZES.into_iter().find(|&s| used <= s);
        if rest.iter().any(|&b| b != 0) || smallest != Some(plain.len()) {
            return Err(OpenError::Padding);
        }
        if inner.body.lane() != crate::tx::Lane::User || matches!(inner.body, crate::tx::TxBody::SubmitEncrypted(_)) {
            return Err(OpenError::Lane);
        }
        Ok(inner)
    }
}

/// Escrow of `k_n` after each segment of a segmented job (TOG-SPEC-0009 §5.2),
/// `TxBody` variant 11.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KeyEscrowTx {
    /// Job.
    pub job_id: Hash32,
    /// `n`; the segment after the last escrow, 0 first.
    pub segment: u32,
    /// `S_n`.
    pub segment_hash: Hash32,
    /// `H("TOG/v1/metrics" ‖ metrics_n)`.
    pub metrics_hash: Hash32,
    /// Checkpoint commitment with `sketch = None`.
    pub checkpoint: CheckpointCommitment,
    /// Metered WUs of segments `0..=n`, cumulative.
    pub work_units: u64,
    /// `k_n` to identity (`TOG/v1/key-escrow`, `job_id`, `n`).
    pub escrowed_key: IbeCiphertext,
}

/// The last escrow the Hub has recorded for a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EscrowHead {
    /// Segment of the last escrow.
    pub segment: u32,
    /// `S_segment`.
    pub segment_hash: Hash32,
    /// Cumulative work units at that escrow.
    pub work_units: u64,
}

/// Why an escrow is rejected.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EscrowError {
    /// Not the next segment.
    #[error("expected segment {expected}, got {got}")]
    OutOfOrder {
        /// Next segment the Hub accepts.
        expected: u32,
        /// Segment in the transaction.
        got: u32,
    },
    /// `checkpoint.segment` differs from `segment`, or carries a sketch.
    #[error("checkpoint commitment does not belong to this escrow")]
    BadCheckpoint,
    /// `segment_hash` does not extend the chain.
    #[error("segment hash does not extend the chain")]
    BadSegmentHash,
    /// Work units went down.
    #[error("cumulative work units decreased")]
    WorkUnitsDecreased,
}

impl KeyEscrowTx {
    /// Rule 2 of TOG-SPEC-0009 §5.2: check this escrow against the previous one
    /// (`None` before the first). Returns the new head.
    ///
    /// `work_units` count only the signing claim's segments (rule 6). For the first escrow of a
    /// resumed claim, pass the old claim's head with `work_units: 0`, so there is no lower bound.
    pub fn check_next(&self, prev: Option<&EscrowHead>) -> Result<EscrowHead, EscrowError> {
        let (expected, prev_hash, prev_wu) = match prev {
            None => (Some(0), segment_genesis(&self.job_id), 0),
            Some(p) => (p.segment.checked_add(1), p.segment_hash, p.work_units),
        };
        // No segment follows u32::MAX.
        if expected != Some(self.segment) {
            return Err(EscrowError::OutOfOrder { expected: expected.unwrap_or(u32::MAX), got: self.segment });
        }
        if self.checkpoint.segment != self.segment || self.checkpoint.sketch.is_some() {
            return Err(EscrowError::BadCheckpoint);
        }
        let link = segment_link(&prev_hash, self.segment, &self.checkpoint.plaintext_root, &self.metrics_hash);
        if link != self.segment_hash {
            return Err(EscrowError::BadSegmentHash);
        }
        if self.work_units < prev_wu {
            return Err(EscrowError::WorkUnitsDecreased);
        }
        Ok(EscrowHead { segment: self.segment, segment_hash: self.segment_hash, work_units: self.work_units })
    }
}

/// `compute_market.key_escrows[(job_id, segment)]` value (TOG-SPEC-0002 §7.2), kept until the job
/// is pruned.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EscrowedSegment {
    /// Executor whose claim escrowed it.
    pub worker: crate::worker::WorkerId,
    /// Inclusion height.
    pub at: u64,
    /// The escrow.
    pub escrow: KeyEscrowTx,
    /// `R` of the claim that escrowed it ([`crate::metering::Lease::rate`]), for `wall_n`
    /// (TOG-SPEC-0003 §4.6).
    pub rate: u64,
}

/// Why a resumed executor's commit can't be built.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ResumedCommitError {
    /// The escrows are not `0..=m` in order, or don't chain to `ResumePoint.segment_hash`.
    #[error("escrowed segments do not chain to the resume point")]
    Escrows,
    /// The executor's own checkpoints don't start at `m + 1` and continue without gaps.
    #[error("own checkpoints do not follow the resume point")]
    Own,
}

/// `ResultCommitTx.checkpoints` of a resumed claim (TOG-SPEC-0009 §5.4 "Building the commit"): the
/// escrowed commitments of `0..=m`, read from `key_escrows` in segment order with `sketch = None`,
/// then the executor's own `m + 1..`.
pub fn resumed_checkpoints(
    job_id: &Hash32,
    resume: &ResumePoint,
    escrowed: &[EscrowedSegment],
    own: Vec<CheckpointCommitment>,
) -> Result<Vec<CheckpointCommitment>, ResumedCommitError> {
    let mut head: Option<EscrowHead> = None;
    for e in escrowed {
        // Work units restart with each claim, so only the chain is checked here.
        let prev = head.map(|h| EscrowHead { work_units: 0, ..h });
        if e.escrow.job_id != *job_id {
            return Err(ResumedCommitError::Escrows);
        }
        head = Some(e.escrow.check_next(prev.as_ref()).map_err(|_| ResumedCommitError::Escrows)?);
    }
    match head {
        Some(h) if h.segment == resume.segment && h.segment_hash == resume.segment_hash => {}
        _ => return Err(ResumedCommitError::Escrows),
    }
    let next = resume.segment.checked_add(1).ok_or(ResumedCommitError::Own)?;
    if own.len() > (u32::MAX - resume.segment) as usize || own.iter().zip(next..).any(|(c, n)| c.segment != n) {
        return Err(ResumedCommitError::Own);
    }
    let mut out: Vec<CheckpointCommitment> =
        escrowed.iter().map(|e| CheckpointCommitment { sketch: None, ..e.escrow.checkpoint.clone() }).collect();
    out.extend(own);
    Ok(out)
}

/// What tog-executor streams to togd after sealing segment `n` (TOG-SPEC-0001 §5.1). It has
/// exactly the fields of [`KeyEscrowTx`] in the same order, so togd submits it unchanged.
pub type SegmentSealed = KeyEscrowTx;

/// The Hub key the executor encrypts checkpoint keys to (TOG-SPEC-0001 §5.1). The IBE
/// encryption runs in tog-executor, because `k_n` never leaves it before V4/V6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EscrowTarget {
    /// Epoch of `ek`.
    pub ek_epoch: u32,
    /// EK, BLS12-381 G1 compressed (TOG-SPEC-0009 §1.2).
    pub ek: [u8; 48],
}

/// Where a reassigned job continues (TOG-SPEC-0009 §5.4): the new executor starts at
/// segment `segment + 1` from `ckpt_segment`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ResumePoint {
    /// `m`.
    pub segment: u32,
    /// `S_m`.
    pub segment_hash: Hash32,
    /// `k_m`, public on the Hub.
    pub key: [u8; 32],
    /// The old executor's commitment of segment `m`: the encrypted payload to fetch and the
    /// `plaintext_root` to check after decryption.
    pub checkpoint: CheckpointCommitment,
}

/// Keys combined by the proposer, other than the beacon (TOG-SPEC-0009 §6): system lane
/// ([`crate::consensus::SystemItem::ReleasedKeys`]), at most one per block.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReleasedKeys {
    /// Identity and its key `d_id`.
    pub keys: Vec<(Identity, [u8; 96])>,
}

impl ReleasedKeys {
    /// True if every key verifies against `EK`: `e(g1, d_id) = e(EK, Q_id)`.
    pub fn verify(&self, ek: &[u8; 48]) -> bool {
        use bls12_381::{pairing, G1Affine, G2Affine};
        let Some(ek) = Option::<G1Affine>::from(G1Affine::from_compressed(ek)).filter(|p| !bool::from(p.is_identity()))
        else {
            return false;
        };
        self.keys.iter().all(|(id, d)| {
            Option::<G2Affine>::from(G2Affine::from_compressed(d))
                .is_some_and(|d| pairing(&G1Affine::generator(), &d) == pairing(&ek, &id.point()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tog_primitives::segment::{metrics_hash, SegmentChain};

    const JOB: Hash32 = [3; 32];

    #[test]
    fn identities_hash_as_the_ibe_points() {
        let id = Identity::KeyEscrow { job_id: JOB, segment: 2 };
        assert_eq!(id.point(), crate::ibe::key_escrow_point(&JOB, 2));
        assert_eq!(Identity::Mempool(9).point(), crate::ibe::mempool_point(9));
        assert_eq!(Identity::ConfKey(EscrowRef([5; 32])).fields(), vec![5; 32]);
        assert_eq!(Identity::ConfKey(EscrowRef([5; 32])).tag(), "TOG/v1/conf-key");
        // Borsh index = position.
        let first = |i: &Identity| borsh::to_vec(i).unwrap()[0];
        assert_eq!(
            [Identity::Beacon(1), Identity::Mempool(1), id, Identity::ConfKey(EscrowRef([0; 32]))].map(|i| first(&i)),
            [0, 1, 2, 3]
        );
    }

    fn ct() -> IbeCiphertext {
        IbeCiphertext { ek_epoch: 0, u: [0; 48], v: [0; 32], w: [0; 32] }
    }

    fn escrow(n: u32, chain: &mut SegmentChain, wu: u64) -> KeyEscrowTx {
        let root = [n as u8 + 10; 32];
        let metrics = format!("loss={n}");
        let segment_hash = chain.push(n, &root, metrics.as_bytes()).unwrap();
        KeyEscrowTx {
            job_id: JOB,
            segment: n,
            segment_hash,
            metrics_hash: metrics_hash(metrics.as_bytes()),
            checkpoint: CheckpointCommitment {
                segment: n,
                plaintext_root: root,
                ciphertext_root: [0; 32],
                key_commitment: [0; 32],
                size: 0,
                metrics_hash: [0; 32],
                sketch: None,
                checker: None,
            },
            work_units: wu,
            escrowed_key: ct(),
        }
    }

    #[test]
    fn ibe_ciphertext_is_116_bytes() {
        assert_eq!(borsh::to_vec(&ct()).unwrap().len(), 116);
    }

    #[test]
    fn escrow_chain_matches_segment_chain() {
        let mut chain = SegmentChain::genesis(&JOB);
        let e0 = escrow(0, &mut chain, 10);
        let e1 = escrow(1, &mut chain, 25);
        let h0 = e0.check_next(None).unwrap();
        let h1 = e1.check_next(Some(&h0)).unwrap();
        assert_eq!(h1.segment_hash, chain.head());
    }

    #[test]
    fn escrow_rejections() {
        let mut chain = SegmentChain::genesis(&JOB);
        let e0 = escrow(0, &mut chain, 10);
        let h0 = e0.check_next(None).unwrap();

        assert_eq!(e0.check_next(Some(&h0)), Err(EscrowError::OutOfOrder { expected: 1, got: 0 }));

        let mut e1 = escrow(1, &mut chain, 25);
        let mut bad = e1.clone();
        bad.segment_hash[0] ^= 1;
        assert_eq!(bad.check_next(Some(&h0)), Err(EscrowError::BadSegmentHash));

        let mut bad = e1.clone();
        bad.checkpoint.segment = 5;
        assert_eq!(bad.check_next(Some(&h0)), Err(EscrowError::BadCheckpoint));

        e1.work_units = 5;
        assert_eq!(e1.check_next(Some(&h0)), Err(EscrowError::WorkUnitsDecreased));
    }

    #[test]
    fn resumed_commit_joins_escrows_and_own_segments() {
        let mut chain = SegmentChain::genesis(&JOB);
        // Two earlier claims escrowed 0..=2; work units restart with each claim.
        let escrowed: Vec<EscrowedSegment> = [(0, 10), (1, 20), (2, 5)]
            .into_iter()
            .map(|(n, wu)| EscrowedSegment {
                worker: [n as u8; 20],
                at: u64::from(n),
                escrow: escrow(n, &mut chain, wu),
                rate: 8_000,
            })
            .collect();
        let last = &escrowed[2].escrow;
        let resume = ResumePoint {
            segment: 2,
            segment_hash: last.segment_hash,
            key: [0; 32],
            checkpoint: last.checkpoint.clone(),
        };
        let own = vec![escrow(3, &mut chain, 1).checkpoint, escrow(4, &mut chain, 2).checkpoint];
        let all = resumed_checkpoints(&JOB, &resume, &escrowed, own.clone()).unwrap();
        assert_eq!(all.iter().map(|c| c.segment).collect::<Vec<_>>(), vec![0, 1, 2, 3, 4]);

        let skipped = vec![own[1].clone()];
        assert_eq!(resumed_checkpoints(&JOB, &resume, &escrowed, skipped), Err(ResumedCommitError::Own));
        assert_eq!(resumed_checkpoints(&JOB, &resume, &escrowed[..2], own.clone()), Err(ResumedCommitError::Escrows));
        let mut gap = escrowed.clone();
        gap.remove(1);
        assert_eq!(resumed_checkpoints(&JOB, &resume, &gap, own.clone()), Err(ResumedCommitError::Escrows));
        let elsewhere = ResumePoint { segment_hash: [0; 32], ..resume };
        assert_eq!(resumed_checkpoints(&JOB, &elsewhere, &escrowed, own), Err(ResumedCommitError::Escrows));
    }

    #[test]
    fn body_sizes() {
        let mut tx = EncryptedTx {
            chain_id: 1 << 32,
            payer: [0; 20],
            nonce: 0,
            target_height: 10,
            gas_limit: 1,
            max_fee_per_gas: 1,
            key: ct(),
            body: vec![0; 256 + 16],
        };
        assert!(tx.has_valid_body_size());
        tx.body.push(0);
        assert!(!tx.has_valid_body_size());
    }

    #[test]
    fn the_inner_signature_is_bound_to_its_envelope() {
        // TOG-SPEC-0009 §4.2 rule 5.
        use crate::tx::{SignedTx, TransferTx, TxBody};
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let from = tog_primitives::ed25519_address(&key.verifying_key().to_bytes());
        let transfer = TxBody::Transfer(TransferTx { chain_id: 1, from, to: [2; 20], amount: 5, nonce: 0 });
        let envelope = EncryptedTx {
            chain_id: 1,
            payer: [3; 20],
            nonce: 4,
            target_height: 10,
            gas_limit: 1,
            max_fee_per_gas: 1,
            key: ct(),
            body: vec![],
        };
        let inner = envelope.sign_inner_ed25519(transfer.clone(), &key);
        assert_eq!(envelope.inner_signer(&inner), Ok(from));
        // Not valid in the plaintext lane, and a plaintext signature isn't valid inside.
        assert!(inner.signer(1) != Ok(from));
        assert!(envelope.inner_signer(&SignedTx::sign_ed25519(transfer, &key)) != Ok(from));
        // Any other envelope: payer, nonce, height or chain.
        for other in [
            EncryptedTx { payer: [5; 20], ..envelope.clone() },
            EncryptedTx { nonce: 5, ..envelope.clone() },
            EncryptedTx { target_height: 11, ..envelope.clone() },
            EncryptedTx { chain_id: 2, ..envelope.clone() },
        ] {
            assert!(other.inner_signer(&inner) != Ok(from));
        }
        // secp256k1 over the envelope's digest, and the same bytes tagged EIP-712 refused.
        let secp = k256::ecdsa::SigningKey::from_slice(&[8; 32]).unwrap();
        let (sig, recid) = secp.sign_prehash_recoverable(&envelope.inner_signing_hash(&inner.body)).unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = recid.to_byte();
        let raw = SignedTx { body: inner.body.clone(), sig: crate::tx::Signature::Secp256k1(bytes) };
        assert!(envelope.inner_signer(&raw).is_ok());
        let tagged = SignedTx { sig: crate::tx::Signature::Secp256k1Eip712(bytes), ..raw };
        assert_eq!(envelope.inner_signer(&tagged), Err(crate::signing::SignatureError::Invalid));
        // Gas, fee and body key aren't signed: the payer may raise what it pays and seal it once.
        let raised =
            EncryptedTx { gas_limit: 9, max_fee_per_gas: 9, key: IbeCiphertext { ek_epoch: 1, ..ct() }, ..envelope };
        assert_eq!(raised.inner_signer(&inner), Ok(from));
        // The digest is the spec's.
        let fields = borsh::to_vec(&(1u64, [3u8; 20], 4u64, 10u64)).unwrap();
        let body = borsh::to_vec(&inner.body).unwrap();
        assert_eq!(raised.inner_signing_hash(&inner.body), tagged_hash(Domain::EncInner, &[&fields, &body]));
    }

    #[test]
    fn bodies_are_padded_sealed_and_opened_per_the_v1_rules() {
        use crate::tx::{SignedTx, TransferTx, TxBody};
        use chacha20poly1305::aead::{Aead, Payload};
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let transfer = TxBody::Transfer(TransferTx { chain_id: 1, from: [1; 20], to: [2; 20], amount: 5, nonce: 0 });
        let inner = SignedTx::sign_ed25519(transfer, &signer);
        let key = [9; 32];
        let envelope = EncryptedTx {
            chain_id: 1,
            payer: [3; 20],
            nonce: 4,
            target_height: 10,
            gas_limit: 1,
            max_fee_per_gas: 1,
            key: ct(),
            body: vec![],
        };
        let mut tx = envelope.clone();
        tx.seal_body(&key, &inner).unwrap();
        assert_eq!(tx.body.len(), 256 + AEAD_TAG);
        assert_eq!(tx.open_body(&key), Ok(inner.clone()));
        assert_eq!(tx.open_body(&[8; 32]), Err(OpenError::Aead));
        let short = EncryptedTx { body: tx.body[1..].to_vec(), ..tx.clone() };
        assert_eq!(short.open_body(&key), Err(OpenError::Size));

        // The body is bound to its envelope: copied into another payer's, or with any other
        // envelope field changed, it doesn't open.
        for other in [
            EncryptedTx { payer: [5; 20], ..tx.clone() },
            EncryptedTx { nonce: 5, ..tx.clone() },
            EncryptedTx { target_height: 11, ..tx.clone() },
            EncryptedTx { chain_id: 2, ..tx.clone() },
            EncryptedTx { key: IbeCiphertext { ek_epoch: 1, ..ct() }, ..tx.clone() },
        ] {
            assert_eq!(other.open_body(&key), Err(OpenError::Aead));
        }
        // Gas and fee are not in the AAD: the payer may only raise what it pays.
        assert_eq!(EncryptedTx { gas_limit: 9, ..tx.clone() }.open_body(&key), Ok(inner.clone()));

        // A non-zero byte in the padding, or a plaintext that isn't a transaction.
        let sealed = |plain: &[u8]| {
            let aad = envelope.aad();
            let body = aead(&key).encrypt(&[0u8; 12].into(), Payload { msg: plain, aad: &aad }).unwrap();
            EncryptedTx { body, ..envelope.clone() }
        };
        let mut plain = borsh::to_vec(&inner).unwrap();
        plain.resize(256, 0);
        plain[255] = 1;
        assert_eq!(sealed(&plain).open_body(&key), Err(OpenError::Padding));
        assert_eq!(sealed(&[0xff; 1024]).open_body(&key), Err(OpenError::Decode));
        // Zero bytes up to the smallest size that fits, not a larger one: 256 here, so the same
        // transaction padded to 1 024 bytes is refused.
        plain[255] = 0;
        assert_eq!(sealed(&plain).open_body(&key), Ok(inner.clone()));
        plain.resize(1024, 0);
        assert_eq!(sealed(&plain).open_body(&key), Err(OpenError::Padding));

        // Compute-lane and nested encrypted transactions are skipped.
        let claim = TxBody::ClaimJob(crate::tx::ClaimTx { job_id: JOB, bond: 1 });
        let mut tx = envelope.clone();
        tx.seal_body(&key, &SignedTx::sign_ed25519(claim, &signer)).unwrap();
        assert_eq!(tx.open_body(&key), Err(OpenError::Lane));
        let nested = EncryptedTx { body: vec![0; 256 + AEAD_TAG], ..envelope.clone() };
        let nested = SignedTx::sign_ed25519(TxBody::SubmitEncrypted(Box::new(nested)), &signer);
        let mut tx = envelope.clone();
        tx.seal_body(&key, &nested).unwrap();
        assert_eq!(tx.body.len(), 1024 + AEAD_TAG);
        assert_eq!(tx.open_body(&key), Err(OpenError::Lane));
        // Longer than 4 096 bytes can't be encrypted.
        let big = EncryptedTx { body: vec![0; 5000], ..envelope.clone() };
        let mut tx = envelope.clone();
        let big = SignedTx::sign_ed25519(TxBody::SubmitEncrypted(Box::new(big)), &signer);
        assert_eq!(tx.seal_body(&key, &big), Err(OpenError::Size));
        assert!(tx.body.is_empty());
    }
}
