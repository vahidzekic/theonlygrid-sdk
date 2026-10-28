//! `cgmp`: both ends of CGMP channels (TOG-SPEC-0007 §3.4 "Inbox proofs", 0000 §7.2, 0002 §4.7).
//!
//! **Inbound.** For each source chain the module keeps `(next_nonce, queue_head)`: the next channel
//! nonce to process and the queue head after the last processed message. Messages are taken in
//! nonce order, and each folds into `queue_head`. One inbox proof per source and block, on the
//! source's last message, ties them to the channel the Hub holds: the `msg_hash`es of every later
//! message up to the channel's `last_nonce`, which folded from the new `queue_head` must give the
//! channel's `head` in Hub state (§3.4 "Inbox proofs"). [`InboxRun`] tracks one block's inbox and
//! enforces that rule and `max_lag` with [`MIN_DRAIN`].
//!
//! The channel itself (`cgmp.channels[(source, dest)]` in Hub state, 0002 §7.2) is read by the
//! caller through `hub_read_proof` at `tog_types::state::items::cgmp_channel`; the fold and the lag
//! rule are [`CgmpChannel::check_inbox`] and [`CgmpChannel::within_lag`].
//!
//! **Outbound.** [`send`] gives a message the next nonce of its channel and appends it to the
//! queue in [`OUTBOX`], whose [`outbox_root`] goes in the header; the caller pushes the returned
//! message with `tog_runtime_io::cgmp::outbox_push`.
//!
//! **$TOG.** The $TOG on a chain is backed by its sovereign account on the Hub (0002 §4.7), so a
//! `TransferTog` from the Hub mints ([`receive_tog`]) and one to the Hub burns, together with the
//! message fee the Hub takes from the sovereign account ([`send_tog`]).

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use tog_runtime_core::dispatch::{ensure_signed, DispatchError};
use tog_runtime_core::env::Env as HostEnv;
use tog_runtime_core::Origin;
use tog_runtime_core::{
    AccountId, Amount, ChainId, Hash32, HubHeight, Storage, StorageError, StorageMap, StorageValue,
};
use tog_types::cgmp::{
    next_head, AppchainsCall, CgmpChannel, CgmpError, CgmpMessage, CgmpOrigin, CgmpPayload, OutboxChannel, Weight,
    APPCHAINS_MODULE, CGMP_VERSION, HEAD_0, MAX_CALL_LEN,
};
use tog_types::eligibility::WorkerSetRules;
use tog_types::job::ModuleId;
use tog_types::state::items::{cgmp_channel, cgmp_inbound, cgmp_refused};

pub use tog_types::cgmp::{min_hub_fee, CGMP_BASE_FEE, CGMP_BYTE_FEE, MAX_BACKLOG, MAX_IN_CHANNELS, MAX_OUT_CHANNELS};

use crate::executive::{Context, Scoped};
use crate::{balances, storage_deposit};

/// Per-source progress through a channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Inbound {
    /// The next channel nonce to process.
    pub next_nonce: u64,
    /// The queue head after the last processed message (`[0; 32]` before the first).
    pub queue_head: Hash32,
}

impl Default for Inbound {
    fn default() -> Self {
        // Channel nonces start at 0 (0000 §7.2).
        Inbound { next_nonce: 0, queue_head: HEAD_0 }
    }
}

/// `cgmp.inbound: ChainId → Inbound`, this chain's progress per source.
pub const INBOUND: StorageMap<ChainId, Inbound> = StorageMap::new("cgmp", "inbound");

/// Why an inbox message or a block's lag was refused. Any of them fails the block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InboxError {
    /// The message's `channel_nonce` isn't the source's `next_nonce`.
    Nonce,
    /// The proof doesn't reach the channel's `last_nonce`.
    ProofLength,
    /// The fold doesn't give the channel's head.
    ProofHead,
    /// A source's last message in the block carries no proof.
    MissingProof,
    /// The block left more than `max_lag` messages of a channel unprocessed and took fewer than
    /// [`MIN_DRAIN`] from it.
    Lag,
    /// Stored state doesn't decode.
    Storage,
}

impl From<StorageError> for InboxError {
    fn from(_: StorageError) -> Self {
        InboxError::Storage
    }
}

pub use tog_runtime_core::block::MIN_DRAIN;

/// This chain's progress for `source`.
pub fn inbound(s: &mut impl Storage, source: ChainId) -> Result<Inbound, StorageError> {
    INBOUND.get_or_default(s, &source)
}

/// What the caller does with an accepted message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    /// Run its handler.
    Execute,
    /// It expired at the relay parent (`h > timeout_height`): it is consumed but has no effect on
    /// this chain; unless it is an `Ack`, the caller answers it with [`timeout_ack`] (§3.4).
    Expired,
}

/// Take `m` as the source's next message, folding it into `queue_head`; with `proof`, also check
/// that the channel's later messages (up to its `last_nonce` in `channel`) fold to its head. `h` is
/// the relay parent's height. Nothing changes on error.
pub fn accept(
    s: &mut impl Storage,
    m: &CgmpMessage,
    proof: Option<&[Hash32]>,
    channel: &CgmpChannel,
    h: HubHeight,
) -> Result<Delivery, InboxError> {
    let mut st = inbound(s, m.source)?;
    if m.channel_nonce != st.next_nonce {
        return Err(InboxError::Nonce);
    }
    let head = next_head(&st.queue_head, &m.hash());
    if let Some(later) = proof {
        let reach = u64::try_from(later.len()).ok().and_then(|n| m.channel_nonce.checked_add(n));
        if channel.last_nonce.is_none() || reach != channel.last_nonce {
            return Err(InboxError::ProofLength);
        }
        channel
            .check_inbox(st.next_nonce, &st.queue_head, m.channel_nonce, &m.hash(), later)
            .ok_or(InboxError::ProofHead)?;
    }
    st.queue_head = head;
    st.next_nonce = m.channel_nonce.checked_add(1).ok_or(InboxError::Nonce)?;
    INBOUND.insert(s, &m.source, &st)?;
    Ok(if h > m.timeout_height { Delivery::Expired } else { Delivery::Execute })
}

/// One block's inbox: per source, how many messages it took and whether the last carried a proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InboxRun {
    taken: Vec<(ChainId, u64, bool)>,
}

impl InboxRun {
    /// [`accept`] the block's next entry.
    pub fn accept(
        &mut self,
        s: &mut impl Storage,
        m: &CgmpMessage,
        proof: Option<&[Hash32]>,
        channel: &CgmpChannel,
        h: HubHeight,
    ) -> Result<Delivery, InboxError> {
        let d = accept(s, m, proof, channel, h)?;
        match self.taken.binary_search_by_key(&m.source, |e| e.0) {
            Ok(i) => {
                self.taken[i].1 += 1;
                self.taken[i].2 = proof.is_some();
            }
            Err(i) => self.taken.insert(i, (m.source, 1, proof.is_some())),
        }
        Ok(d)
    }

    /// Check `m`, read after the block's entries and not taken, as the next message of its source
    /// in the channel `channel`: its nonce, and its proof against the channel's head (which also
    /// covers the source's messages before it). Nothing changes but the run's record that the
    /// source's last message is proven. A block's peek (§3.4 "max_lag (exact)").
    pub fn peek(
        &mut self,
        s: &mut impl Storage,
        m: &CgmpMessage,
        proof: Option<&[Hash32]>,
        channel: &CgmpChannel,
    ) -> Result<(), InboxError> {
        let st = inbound(s, m.source)?;
        if m.channel_nonce != st.next_nonce {
            return Err(InboxError::Nonce);
        }
        let later = proof.ok_or(InboxError::MissingProof)?;
        let reach = u64::try_from(later.len()).ok().and_then(|n| m.channel_nonce.checked_add(n));
        if channel.last_nonce.is_none() || reach != channel.last_nonce {
            return Err(InboxError::ProofLength);
        }
        channel
            .check_inbox(st.next_nonce, &st.queue_head, m.channel_nonce, &m.hash(), later)
            .ok_or(InboxError::ProofHead)?;
        if let Ok(i) = self.taken.binary_search_by_key(&m.source, |e| e.0) {
            self.taken[i].2 = true;
        }
        Ok(())
    }

    /// Messages taken from `source` in this block.
    pub fn taken(&self, source: ChainId) -> u64 {
        self.taken.binary_search_by_key(&source, |e| e.0).map_or(0, |i| self.taken[i].1)
    }

    /// End of the block: every source's last message carried a proof (or its [`InboxRun::peek`]
    /// did), and every channel to this chain (`inbound`: each source of `cgmp.inbound[dest]` at the
    /// relay parent with its channel) is within `max_lag` or drained by at least [`MIN_DRAIN`],
    /// unless the block stopped at a peek (`peeked`). Returns `ValidationResult.inbox`:
    /// `(source, next_nonce)` of each source the block took messages from, ascending.
    pub fn finish(
        &self,
        s: &mut impl Storage,
        inbound_channels: &[(ChainId, CgmpChannel)],
        peeked: bool,
    ) -> Result<Vec<(ChainId, u64)>, InboxError> {
        if self.taken.iter().any(|(_, _, proved)| !proved) {
            return Err(InboxError::MissingProof);
        }
        for (source, channel) in inbound_channels.iter().filter(|_| !peeked) {
            let next = inbound(s, *source)?.next_nonce;
            if !channel.within_lag(next) && self.taken(*source) < MIN_DRAIN {
                return Err(InboxError::Lag);
            }
        }
        self.taken.iter().map(|(source, _, _)| Ok((*source, inbound(s, *source)?.next_nonce))).collect()
    }
}

/// Whether one more message to `dest` keeps this chain's channel to it within [`MAX_BACKLOG`]:
/// `delivered` is the channel's `next_nonce` at the relay parent (0 while the Hub has none). The
/// Hub's own channel isn't capped here (0002 §4.7).
pub fn fits_backlog(s: &mut impl Storage, dest: ChainId, delivered: u64) -> Result<bool, SendError> {
    if dest == ChainId::HUB {
        return Ok(true);
    }
    let next = next_nonce(s, dest)?;
    Ok(next.saturating_add(1).saturating_sub(delivered) <= MAX_BACKLOG)
}

/// `cgmp.owed_acks: ChainId → Vec<u64>`, the `of_nonce`s of the `Timeout` `Ack`s owed to a source
/// that didn't fit under [`MAX_BACKLOG`], oldest first, at most [`MAX_PENDING_CALLS`] (§3.4
/// "Timeout Acks under the cap"); absent when empty.
pub const OWED_ACKS: StorageMap<ChainId, Vec<u64>> = StorageMap::new("cgmp", "owed_acks");
/// `cgmp.owed_sources`: the sources with an [`OWED_ACKS`] entry, ascending.
pub const OWED_SOURCES: StorageValue<Vec<ChainId>> = StorageValue::new("cgmp", "owed_sources");

/// The sources this chain owes `Timeout` `Ack`s, ascending.
pub fn owed_sources(s: &mut impl Storage) -> Result<Vec<ChainId>, StorageError> {
    OWED_SOURCES.get_or_default(s)
}

fn ack_to(chain: ChainId, source: ChainId, of_nonce: u64) -> Outgoing {
    Outgoing {
        dest: source,
        timeout_height: HubHeight::MAX,
        fee: 0,
        origin: CgmpOrigin::Chain(chain),
        payload: CgmpPayload::Ack { of_nonce, result: Err(CgmpError::Timeout) },
    }
}

/// The `Ack { of_nonce, Err(Timeout) }` a destination sends for an expired message from another
/// AppChain (§3.4), on which the source refunds: `fee = 0`, `timeout_height = u64::MAX`, origin
/// `Chain(chain)`. `None` for an `Ack`, which is never answered, and for one that has to wait:
/// when the channel back to the source, whose `next_nonce` at the relay parent is `delivered`,
/// would exceed [`MAX_BACKLOG`] with it, or Acks already wait for that source, it goes to the back
/// of [`OWED_ACKS`], or is dropped when that queue is full. Hub messages never expire.
pub fn timeout_ack(
    s: &mut impl Storage,
    chain: ChainId,
    m: &CgmpMessage,
    delivered: u64,
) -> Result<Option<CgmpMessage>, SendError> {
    if matches!(m.payload, CgmpPayload::Ack { .. }) {
        return Ok(None);
    }
    let mut owed = OWED_ACKS.get_or_default(s, &m.source)?;
    if owed.is_empty() && fits_backlog(s, m.source, delivered)? {
        return send(s, chain, ack_to(chain, m.source, m.channel_nonce)).map(Some);
    }
    if owed.len() < MAX_PENDING_CALLS as usize {
        owed.push(m.channel_nonce);
        OWED_ACKS.insert(s, &m.source, &owed)?;
        let mut sources = owed_sources(s)?;
        if let Err(i) = sources.binary_search(&m.source) {
            sources.insert(i, m.source);
            OWED_SOURCES.put(s, &sources)?;
        }
    }
    Ok(None)
}

/// At the start of a block's inbox: send the owed `Timeout` `Ack`s, oldest first, while each
/// source's channel stays within [`MAX_BACKLOG`]. `delivered` holds, for each of
/// [`owed_sources`], the `next_nonce` at the relay parent of this chain's channel to it. Returns
/// the messages for `outbox_push`, in order.
pub fn send_owed_acks(
    s: &mut impl Storage,
    chain: ChainId,
    delivered: &[(ChainId, u64)],
) -> Result<Vec<CgmpMessage>, SendError> {
    let mut sent = Vec::new();
    let mut sources = owed_sources(s)?;
    for &(source, d) in delivered {
        let mut owed = OWED_ACKS.get_or_default(s, &source)?;
        let mut taken = 0;
        while taken < owed.len() && fits_backlog(s, source, d)? {
            sent.push(send(s, chain, ack_to(chain, source, owed[taken]))?);
            taken += 1;
        }
        if taken == owed.len() {
            OWED_ACKS.remove(s, &source);
            sources.retain(|c| *c != source);
        } else if taken > 0 {
            owed.drain(..taken);
            OWED_ACKS.insert(s, &source, &owed)?;
        }
    }
    OWED_SOURCES.put(s, &sources)?;
    Ok(sent)
}

/// `cgmp.outbox`: this chain's outgoing channels, ascending by `dest`; one entry per destination
/// it has ever sent to. The host checks each block's pushes against it.
pub use tog_runtime_core::block::OUTBOX;

/// A message to send, before its channel gives it a nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    /// Receiving chain.
    pub dest: ChainId,
    /// Hub height after which it is refunded, not delivered.
    pub timeout_height: HubHeight,
    /// What the sender pays; the caller has already charged it.
    pub fee: Amount,
    /// Who sends it.
    pub origin: CgmpOrigin,
    /// What it carries.
    pub payload: CgmpPayload,
}

/// Why a message couldn't be sent. Nothing changes on error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    /// A message to this chain itself.
    ToSelf,
    /// The channel's nonce space is spent.
    Nonce,
    /// The sender can't pay the amount and fee.
    Balance(balances::Error),
    /// [`MAX_PENDING_TRANSFERS`] transfers wait for their `Ack`.
    TooManyTransfers,
    /// The send would open a channel beyond [`MAX_OUT_CHANNELS`].
    TooManyChannels,
    /// The destination already has [`MAX_IN_CHANNELS`] AppChain sources, so the Hub wouldn't
    /// create this channel.
    DestinationFull,
    /// The destination's manager refuses this chain (`cgmp.refused`), so the Hub would ignore the
    /// message.
    Refused,
    /// [`MAX_PENDING_CALLS`] messages to AppChains wait to be pruned or timed out.
    TooManyPendingCalls,
    /// [`MAX_PENDING_CALLS_PER_SENDER`] of the sender's messages to AppChains wait to be pruned or
    /// timed out.
    TooManyPendingCallsFromSender,
    /// The channel to the destination would hold more than [`MAX_BACKLOG`] unprocessed messages.
    Backlog,
    /// A call to the Hub, which [`send_call`] doesn't handle.
    ToHub,
    /// A message to the Hub with less than [`min_hub_fee`], which the Hub would refuse.
    FeeBelowHubMinimum {
        /// The least fee the Hub takes for this message.
        min: Amount,
    },
    /// Only `Root` may send a call to the Hub with origin `Chain` (§4.6).
    BadOrigin,
    /// Stored state doesn't decode.
    Storage,
}

impl From<StorageError> for SendError {
    fn from(_: StorageError) -> Self {
        SendError::Storage
    }
}

impl From<balances::Error> for SendError {
    fn from(e: balances::Error) -> Self {
        SendError::Balance(e)
    }
}

/// Every outgoing channel, ascending by `dest`.
pub fn outbox(s: &mut impl Storage) -> Result<Vec<OutboxChannel>, StorageError> {
    OUTBOX.get_or_default(s)
}

/// The header's `outbox_root` over [`outbox`] (0000 §7.2).
pub fn outbox_root(s: &mut impl Storage) -> Result<Hash32, StorageError> {
    Ok(tog_types::cgmp::outbox_root(&outbox(s)?))
}

/// The SDK's `timeout_height` of a message: the relay parent's height plus this, unless the caller
/// gives one (§4.6).
pub const DEFAULT_TIMEOUT: HubHeight = 600;

/// `timeout_height` for a message sent at relay parent `h`: `timeout`, or [`DEFAULT_TIMEOUT`] after
/// `h`.
pub fn timeout_height(h: HubHeight, timeout: Option<HubHeight>) -> HubHeight {
    timeout.unwrap_or_else(|| h.saturating_add(DEFAULT_TIMEOUT))
}

/// Append `out` from `chain` to its channel: the first message to a destination has nonce 0, each
/// later one the last plus one; a new channel only below [`MAX_OUT_CHANNELS`]. Returns the message
/// for `outbox_push`.
pub fn send(s: &mut impl Storage, chain: ChainId, out: Outgoing) -> Result<CgmpMessage, SendError> {
    if out.dest == chain {
        return Err(SendError::ToSelf);
    }
    let mut channels = outbox(s)?;
    let (i, nonce) = match channels.binary_search_by_key(&out.dest, |c| c.dest) {
        Ok(i) => (i, channels[i].last_nonce.checked_add(1).ok_or(SendError::Nonce)?),
        Err(_) if channels.len() >= MAX_OUT_CHANNELS => return Err(SendError::TooManyChannels),
        Err(i) => {
            channels.insert(i, OutboxChannel { dest: out.dest, head: HEAD_0, last_nonce: 0 });
            (i, 0)
        }
    };
    let m = CgmpMessage {
        version: CGMP_VERSION,
        source: chain,
        dest: out.dest,
        channel_nonce: nonce,
        timeout_height: out.timeout_height,
        fee: out.fee,
        origin: out.origin,
        payload: out.payload,
    };
    let c = &mut channels[i];
    c.head = next_head(&c.head, &m.hash());
    c.last_nonce = nonce;
    OUTBOX.put(s, &channels)?;
    Ok(m)
}

/// The next nonce of this chain's channel to `dest`: 0 before the first message.
pub fn next_nonce(s: &mut impl Storage, dest: ChainId) -> Result<u64, SendError> {
    let channels = outbox(s)?;
    match channels.binary_search_by_key(&dest, |c| c.dest) {
        Ok(i) => channels[i].last_nonce.checked_add(1).ok_or(SendError::Nonce),
        Err(_) => Ok(0),
    }
}

/// `cgmp.to_hub: u64 → ToHub`, the messages to the Hub that took $TOG out of this chain and have
/// no `Ack` yet, by channel nonce. The Hub acks every such message (0002 §4.7), so the map stays
/// as small as the channel's backlog.
pub const TO_HUB: StorageMap<u64, ToHub> = StorageMap::new("cgmp", "to_hub");

/// `MaxPendingTransfers`: outgoing `TransferTog`s without an `Ack` at most (0007 §7.1).
pub const MAX_PENDING_TRANSFERS: u32 = 1_024;

/// Bytes of a [`TO_HUB`] record, for its storage deposit (§5).
pub const TO_HUB_BYTES: u64 = 20 + 1 + 16 + 16;

/// `cgmp.pending_transfers`: the `TransferTog`s in [`TO_HUB`].
pub const PENDING_TRANSFERS: StorageValue<u32> = StorageValue::new("cgmp", "pending_transfers");

/// What a message to the Hub carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Kind {
    /// A `TransferTog`.
    Transfer,
    /// A `ComputeRequest`.
    Compute,
    /// A `Call` to a Hub module.
    Call,
}

/// What a message to the Hub took out of this chain, minted back if the Hub refuses it
/// (0007 §7.1 "Refunds on the source").
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ToHub {
    /// Who paid.
    pub account: AccountId,
    /// What the message carries.
    pub kind: Kind,
    /// What the payload moves: a `TransferTog`'s amount, a `ComputeRequest`'s `max_budget`.
    pub amount: Amount,
    /// The message fee.
    pub fee: Amount,
}

/// The least fee for a message to the Hub with `origin` and `payload` ([`min_hub_fee`]): a
/// message's encoded length doesn't depend on its nonce, timeout or fee, so the caller can compute
/// it before sending.
pub fn hub_fee(chain: ChainId, origin: &CgmpOrigin, payload: &CgmpPayload) -> Amount {
    min_hub_fee(&CgmpMessage {
        version: CGMP_VERSION,
        source: chain,
        dest: ChainId::HUB,
        channel_nonce: 0,
        timeout_height: 0,
        fee: 0,
        origin: origin.clone(),
        payload: payload.clone(),
    })
}

/// Send `payload` to the Hub on behalf of `from`, who pays `amount` (what the payload moves) and
/// `fee`, at least [`hub_fee`]: both leave this chain's issuance, since the Hub pays them out of the
/// sovereign account. The message stays in [`TO_HUB`] until the Hub acks it ([`receive_ack`]), and
/// `from` holds its storage deposit at `per_byte` (§5) until then.
#[allow(clippy::too_many_arguments)]
pub fn send_paid(
    s: &mut impl Storage,
    chain: ChainId,
    from: &AccountId,
    amount: Amount,
    fee: Amount,
    timeout_height: HubHeight,
    payload: CgmpPayload,
    per_byte: Amount,
) -> Result<CgmpMessage, SendError> {
    let origin = CgmpOrigin::Account { chain, account: *from };
    send_to_hub(s, chain, origin, from, amount, fee, timeout_height, payload, per_byte)
}

#[allow(clippy::too_many_arguments)]
fn send_to_hub(
    s: &mut impl Storage,
    chain: ChainId,
    origin: CgmpOrigin,
    from: &AccountId,
    amount: Amount,
    fee: Amount,
    timeout_height: HubHeight,
    payload: CgmpPayload,
    per_byte: Amount,
) -> Result<CgmpMessage, SendError> {
    let min = hub_fee(chain, &origin, &payload);
    if fee < min {
        return Err(SendError::FeeBelowHubMinimum { min });
    }
    let kind = match payload {
        CgmpPayload::ComputeRequest { .. } => Kind::Compute,
        CgmpPayload::Call { .. } => Kind::Call,
        _ => Kind::Transfer,
    };
    let transfers = PENDING_TRANSFERS.get_or_default(s)?;
    if kind == Kind::Transfer && transfers >= MAX_PENDING_TRANSFERS {
        return Err(SendError::TooManyTransfers);
    }
    let total = amount.checked_add(fee).ok_or(SendError::Balance(balances::Error::Overflow))?;
    // The record's deposit (R-6), under the nonce the message gets.
    let record = TO_HUB.key(&next_nonce(s, ChainId::HUB)?);
    storage_deposit::charge(s, &record, from, TO_HUB_BYTES, per_byte).map_err(deposit_error)?;
    // Withdraw first so no message goes out unpaid; if the send fails, put the balance back.
    if let Err(e) = balances::withdraw(s, from, total) {
        storage_deposit::release(s, &record).map_err(deposit_error)?;
        return Err(e.into());
    }
    let out = Outgoing { dest: ChainId::HUB, timeout_height, fee, origin, payload };
    let sent = send(s, chain, out).and_then(|m| {
        debug_assert_eq!(TO_HUB.key(&m.channel_nonce), record);
        TO_HUB.insert(s, &m.channel_nonce, &ToHub { account: *from, kind, amount, fee })?;
        if kind == Kind::Transfer {
            PENDING_TRANSFERS.put(s, &(transfers + 1))?;
        }
        Ok(m)
    });
    if sent.is_err() {
        balances::deposit(s, from, total)?;
        storage_deposit::release(s, &record).map_err(deposit_error)?;
    }
    sent
}

fn deposit_error(e: storage_deposit::Error) -> SendError {
    match e {
        storage_deposit::Error::InsufficientBalance => SendError::Balance(balances::Error::InsufficientBalance),
        storage_deposit::Error::Storage => SendError::Storage,
    }
}

/// The `SetWorkerSetRules` payload: a `Call` to the Hub's `appchains` module (0002 §4.7).
pub fn worker_set_rules_payload(rules: WorkerSetRules) -> CgmpPayload {
    CgmpPayload::Call {
        module: APPCHAINS_MODULE,
        call: borsh::to_vec(&AppchainsCall::SetWorkerSetRules(rules)).expect("in-memory borsh"),
        // The Hub ignores it.
        weight_limit: Default::default(),
    }
}

/// Replace this chain's `appchains.worker_set_rules` on the Hub: a `Call` with origin
/// `Chain(chain)`, which only `Root` may send (§4.6). `payer` pays `fee`, at least [`hub_fee`], and
/// gets it back if the Hub never takes the message (`Timeout`, `InsufficientFee`); the Hub keeps it
/// if it refuses the rules (`DispatchFailed`).
#[allow(clippy::too_many_arguments)]
pub fn set_worker_set_rules(
    s: &mut impl Storage,
    chain: ChainId,
    origin: &Origin,
    payer: &AccountId,
    rules: WorkerSetRules,
    fee: Amount,
    timeout_height: HubHeight,
    per_byte: Amount,
) -> Result<CgmpMessage, SendError> {
    if *origin != Origin::Root {
        return Err(SendError::BadOrigin);
    }
    let payload = worker_set_rules_payload(rules);
    send_to_hub(s, chain, CgmpOrigin::Chain(chain), payer, 0, fee, timeout_height, payload, per_byte)
}

/// Withdraw `amount` from `from` to `to` on the Hub, paying `fee` for the message ([`send_paid`]).
#[allow(clippy::too_many_arguments)]
pub fn send_tog(
    s: &mut impl Storage,
    chain: ChainId,
    from: &AccountId,
    to: AccountId,
    amount: Amount,
    fee: Amount,
    timeout_height: HubHeight,
    per_byte: Amount,
) -> Result<CgmpMessage, SendError> {
    send_paid(s, chain, from, amount, fee, timeout_height, CgmpPayload::TransferTog { to, amount }, per_byte)
}

/// What [`receive_ack`] did with an `Ack` from the Hub.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acked {
    /// The Hub took the message: what it moved stays on the Hub.
    Taken {
        /// The acked message's nonce.
        nonce: u64,
    },
    /// The Hub refused it, and `minted` went back to the payer: the amount, plus the fee when the Hub
    /// didn't take it (`Timeout`, `InsufficientFee`).
    Refunded {
        /// The acked message's nonce.
        nonce: u64,
        /// Why.
        error: CgmpError,
        /// What went back.
        minted: Amount,
    },
}

/// Settle an `Ack` from the Hub for a message in [`TO_HUB`], after [`accept`]. `None` when `m` isn't
/// a Hub `Ack` or acks nothing this chain paid for.
pub fn receive_ack(s: &mut impl Storage, m: &CgmpMessage) -> Result<Option<Acked>, balances::Error> {
    let CgmpPayload::Ack { of_nonce, result } = &m.payload else { return Ok(None) };
    if m.source != ChainId::HUB {
        return Ok(None);
    }
    let Some(p) = TO_HUB.take(s, of_nonce)? else { return Ok(None) };
    storage_deposit::release(s, &TO_HUB.key(of_nonce)).map_err(|e| match e {
        storage_deposit::Error::InsufficientBalance => balances::Error::InsufficientBalance,
        storage_deposit::Error::Storage => balances::Error::Storage,
    })?;
    if p.kind == Kind::Transfer {
        PENDING_TRANSFERS.mutate(s, |n| *n = n.saturating_sub(1))?;
    }
    Ok(Some(match result {
        Ok(()) => Acked::Taken { nonce: *of_nonce },
        Err(error) => {
            let fee_back = matches!(error, CgmpError::Timeout | CgmpError::InsufficientFee);
            let minted =
                if fee_back { p.amount.checked_add(p.fee).ok_or(balances::Error::Overflow)? } else { p.amount };
            balances::deposit(s, &p.account, minted)?;
            Acked::Refunded { nonce: *of_nonce, error: *error, minted }
        }
    }))
}

/// `MaxPendingCalls`: messages to other AppChains with a [`PENDING_CALLS`] record at most (§7.1).
pub const MAX_PENDING_CALLS: u32 = 1_024;
/// `MaxPendingCallsPerSender`: records in [`PENDING_CALLS`] one sender may have at once (§7.1), so
/// filling them all takes at least 64 accounts.
pub const MAX_PENDING_CALLS_PER_SENDER: u32 = 16;
/// `PendingCallDeposit`, the SDK default: 1 TOG (10¹⁸ atto-TOG), until its value is decided.
pub const DEFAULT_PENDING_CALL_DEPOSIT: Amount = 1_000_000_000_000_000_000;

/// What a [`PENDING_CALLS`] record reserves from its sender until it is deleted (§7.1): the
/// storage deposit `per_byte` of §5 for its bytes, plus a flat `per_call` (`PendingCallDeposit`),
/// both runtime parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallDeposits {
    /// `StorageDepositPerByte`.
    pub per_byte: Amount,
    /// `PendingCallDeposit`.
    pub per_call: Amount,
}

impl Default for CallDeposits {
    /// The SDK defaults.
    fn default() -> Self {
        CallDeposits { per_byte: storage_deposit::DEFAULT_PER_BYTE, per_call: DEFAULT_PENDING_CALL_DEPOSIT }
    }
}

impl CallDeposits {
    /// What one record reserves.
    pub fn for_record(&self) -> Option<Amount> {
        let len = borsh::object_length(&PendingCall::default()).ok()? as u64;
        storage_deposit::deposit_for(len, self.per_byte)?.checked_add(self.per_call)
    }
}

/// What a message to another AppChain took out of this chain: its fee, burned on sending and
/// minted back to `sender` on a `Timeout` `Ack` (§7.1 "Timeouts of messages to AppChains"), and
/// the deposit reserved from `sender` while the record exists.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct PendingCall {
    /// Who paid.
    pub sender: AccountId,
    /// The message fee.
    pub fee: Amount,
    /// The message's `timeout_height`, which bounds [`prune`].
    pub timeout_height: HubHeight,
    /// Reserved from `sender`, returned when the record is deleted.
    pub deposit: Amount,
}

/// `cgmp.pending_calls: (dest, channel_nonce) → PendingCall`.
pub const PENDING_CALLS: StorageMap<(ChainId, u64), PendingCall> = StorageMap::new("cgmp", "pending_calls");
/// `cgmp.pending_call_count`: entries of [`PENDING_CALLS`].
pub const PENDING_CALL_COUNT: StorageValue<u32> = StorageValue::new("cgmp", "pending_call_count");
/// `cgmp.pending_calls_of: sender → entries of [`PENDING_CALLS`] it paid for`, absent at 0.
pub const PENDING_CALLS_OF: StorageMap<AccountId, u32> = StorageMap::new("cgmp", "pending_calls_of");

/// Delete record `key` of [`PENDING_CALLS`], which holds `p`: the counts drop and the deposit
/// returns to its sender.
fn close_pending(s: &mut impl Storage, key: &(ChainId, u64), p: &PendingCall) -> Result<(), balances::Error> {
    PENDING_CALLS.remove(s, key);
    PENDING_CALL_COUNT.mutate(s, |n| *n = n.saturating_sub(1))?;
    match PENDING_CALLS_OF.get(s, &p.sender)?.unwrap_or(0) {
        0 | 1 => PENDING_CALLS_OF.remove(s, &p.sender),
        n => PENDING_CALLS_OF.insert(s, &p.sender, &(n - 1))?,
    }
    balances::unreserve(s, &p.sender, p.deposit)
}

/// Whether this chain may open a channel to `dest`: always if it already has one or `dest` is the
/// Hub; otherwise only while `dest_inbound` (`cgmp.inbound[dest]` at the relay parent) holds fewer
/// than [`MAX_IN_CHANNELS`] AppChain sources.
pub fn may_open(
    s: &mut impl Storage,
    chain: ChainId,
    dest: ChainId,
    dest_inbound: &[ChainId],
) -> Result<bool, StorageError> {
    if dest == ChainId::HUB || outbox(s)?.iter().any(|c| c.dest == dest) || dest_inbound.contains(&chain) {
        return Ok(true);
    }
    Ok(dest_inbound.iter().filter(|c| **c != ChainId::HUB).count() < MAX_IN_CHANNELS)
}

/// What a [`send_call`] reads of its destination in Hub state at the relay parent.
#[derive(Clone, Copy, Debug)]
pub struct AtDest<'a> {
    /// `cgmp.inbound[dest]`.
    pub inbound: &'a [ChainId],
    /// The `next_nonce` there of this chain's channel to `dest` (0 while it has none).
    pub delivered: u64,
    /// Whether `cgmp.refused[(chain, dest)]` is present.
    pub refused: bool,
}

/// Send `out` to another AppChain for `sender`, who pays `out.fee`: burned here, since the
/// destination doesn't credit it in v1 (§4.6), and recorded in [`PENDING_CALLS`] until it is
/// pruned or timed out, with `deposits` reserved from `sender` meanwhile (§7.1), at most
/// [`MAX_PENDING_CALLS_PER_SENDER`] records per sender. `at` is the destination at the relay
/// parent: the send fails rather than take the channel over [`MAX_BACKLOG`] (§3.4 "Backlog cap"),
/// or when `at.refused`: the Hub ignores a refused source's messages to that destination (§4.6
/// "Refused sources").
pub fn send_call(
    s: &mut impl Storage,
    chain: ChainId,
    sender: &AccountId,
    out: Outgoing,
    at: AtDest<'_>,
    deposits: CallDeposits,
) -> Result<CgmpMessage, SendError> {
    if out.dest == ChainId::HUB {
        return Err(SendError::ToHub);
    }
    if at.refused {
        return Err(SendError::Refused);
    }
    if !may_open(s, chain, out.dest, at.inbound)? {
        return Err(SendError::DestinationFull);
    }
    if !fits_backlog(s, out.dest, at.delivered)? {
        return Err(SendError::Backlog);
    }
    let count = PENDING_CALL_COUNT.get_or_default(s)?;
    if count >= MAX_PENDING_CALLS {
        return Err(SendError::TooManyPendingCalls);
    }
    let mine = PENDING_CALLS_OF.get(s, sender)?.unwrap_or(0);
    if mine >= MAX_PENDING_CALLS_PER_SENDER {
        return Err(SendError::TooManyPendingCallsFromSender);
    }
    let (fee, timeout_height) = (out.fee, out.timeout_height);
    let deposit = deposits.for_record().ok_or(SendError::Balance(balances::Error::Overflow))?;
    balances::reserve(s, sender, deposit)?;
    if let Err(e) = balances::withdraw(s, sender, fee) {
        balances::unreserve(s, sender, deposit)?;
        return Err(e.into());
    }
    let record = PendingCall { sender: *sender, fee, timeout_height, deposit };
    let sent = send(s, chain, out).and_then(|m| {
        PENDING_CALLS.insert(s, &(m.dest, m.channel_nonce), &record)?;
        PENDING_CALL_COUNT.put(s, &(count + 1))?;
        PENDING_CALLS_OF.insert(s, sender, &(mine + 1))?;
        Ok(m)
    });
    if sent.is_err() {
        balances::deposit(s, sender, fee)?;
        balances::unreserve(s, sender, deposit)?;
    }
    sent
}

/// Settle a `Timeout` `Ack` from another AppChain for a message in [`PENDING_CALLS`], after
/// [`accept`]: mint its fee back to the sender, delete the record and return its deposit. Returns the record; `None`
/// when `m` isn't such an `Ack` or acks nothing recorded. The caller passes the `Ack` on to the
/// sending module's `on_cgmp_message` hook.
pub fn receive_timeout(s: &mut impl Storage, m: &CgmpMessage) -> Result<Option<PendingCall>, balances::Error> {
    let CgmpPayload::Ack { of_nonce, result: Err(CgmpError::Timeout) } = &m.payload else { return Ok(None) };
    if m.source == ChainId::HUB {
        return Ok(None);
    }
    let key = (m.source, *of_nonce);
    let Some(p) = PENDING_CALLS.get(s, &key)? else { return Ok(None) };
    close_pending(s, &key, &p)?;
    balances::deposit(s, &p.sender, p.fee)?;
    Ok(Some(p))
}

/// `cgmp.prune(dest, nonce)`, callable by anyone: delete the record of a message that ran.
/// `channel` is `cgmp.channels[(this chain, dest)]` read at the relay parent of height `h`; the
/// message ran if the channel's `next_nonce` passed it by a height at most its `timeout_height`.
/// Returns whether a record was deleted; its deposit returns to its sender.
pub fn prune(
    s: &mut impl Storage,
    dest: ChainId,
    nonce: u64,
    channel: &CgmpChannel,
    h: HubHeight,
) -> Result<bool, balances::Error> {
    let Some(p) = PENDING_CALLS.get(s, &(dest, nonce))? else { return Ok(false) };
    if channel.next_nonce <= nonce || h > p.timeout_height {
        return Ok(false);
    }
    close_pending(s, &(dest, nonce), &p)?;
    Ok(true)
}

/// What [`receive_tog`] did with an accepted message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received {
    /// A `TransferTog` from the Hub, credited.
    Credited,
    /// Not a Hub `TransferTog`; the runtime handles it.
    NotTog,
}

/// Credit a `TransferTog` from the Hub to its recipient, after [`accept`]. The Hub has already
/// moved the amount into the sovereign account, so it is minted here. A `TransferTog` from any
/// other chain moves nothing: only the Hub holds the ledger.
pub fn receive_tog(s: &mut impl Storage, m: &CgmpMessage) -> Result<Received, balances::Error> {
    match &m.payload {
        CgmpPayload::TransferTog { to, amount } if m.source == ChainId::HUB => {
            balances::deposit(s, to, *amount)?;
            Ok(Received::Credited)
        }
        _ => Ok(Received::NotTog),
    }
}

/// A call of the `cgmp` module (§4.6, §7): `borsh(Call)` inside the runtime's call enum.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Call {
    /// 0: withdraw `amount` of the signer's $TOG to `to` on the Hub, paying `fee` for the message
    /// ([`send_tog`]); a refused or timed-out withdrawal is minted back at its `Ack`.
    Withdraw {
        /// The Hub account credited.
        to: AccountId,
        /// Amount in atto-TOG.
        amount: Amount,
        /// The message fee, at least [`hub_fee`].
        fee: Amount,
        /// Hub height after which it is refunded; `None` for the relay parent's plus
        /// [`DEFAULT_TIMEOUT`].
        timeout: Option<HubHeight>,
    },
    /// 1: send `call` to `module` on AppChain `dest` for the signer ([`send_call`]), with origin
    /// `Account { chain, signer }`; `fee` is burned and minted back only on a `Timeout` `Ack`.
    Send {
        /// The receiving AppChain.
        dest: ChainId,
        /// Its module.
        module: ModuleId,
        /// `borsh((call_index, args))` of that module, at most [`MAX_CALL_LEN`] bytes.
        call: Vec<u8>,
        /// Most weight the call may use there.
        weight_limit: Weight,
        /// The message fee.
        fee: Amount,
        /// Hub height after which it is timed out; `None` as for [`Call::Withdraw`].
        timeout: Option<HubHeight>,
    },
    /// 2: [`prune`] the record of the message `nonce` to `dest`; anyone may call it.
    Prune {
        /// The receiving AppChain.
        dest: ChainId,
        /// The message's `channel_nonce`.
        nonce: u64,
    },
}

/// The module's call index of `withdraw`.
pub const WITHDRAW: u8 = 0;
/// The module's call index of `send`.
pub const SEND: u8 = 1;
/// The module's call index of `prune`.
pub const PRUNE: u8 = 2;

/// The module's events, `borsh` in the block's events under module `"cgmp"`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Event {
    /// [`Call::Withdraw`]: its `TransferTog` is in this block's outbox with nonce `nonce`.
    Withdrawn {
        /// Who paid.
        from: AccountId,
        /// The Hub account credited.
        to: AccountId,
        /// Amount in atto-TOG.
        amount: Amount,
        /// The message's `channel_nonce` to the Hub.
        nonce: u64,
    },
    /// [`Call::Send`]: its `Call` is in this block's outbox.
    Sent {
        /// Who paid.
        sender: AccountId,
        /// The receiving AppChain.
        dest: ChainId,
        /// The message's `channel_nonce` to `dest`.
        nonce: u64,
    },
    /// [`Call::Prune`] deleted the record of message `nonce` to `dest`.
    Pruned {
        /// The receiving AppChain.
        dest: ChainId,
        /// The message's `channel_nonce`.
        nonce: u64,
    },
}

/// The module's metadata; its errors as [`dispatch_error`] numbers them.
pub fn metadata() -> tog_runtime_core::metadata::ModuleMetadata {
    tog_runtime_core::metadata::ModuleMetadata::from_names(
        "cgmp",
        &[
            (
                WITHDRAW,
                "withdraw",
                &[("to", "AccountId"), ("amount", "Amount"), ("fee", "Amount"), ("timeout", "Option<HubHeight>")],
            ),
            (
                SEND,
                "send",
                &[
                    ("dest", "ChainId"),
                    ("module", "ModuleId"),
                    ("call", "Vec<u8>"),
                    ("weight_limit", "Weight"),
                    ("fee", "Amount"),
                    ("timeout", "Option<HubHeight>"),
                ],
            ),
            (PRUNE, "prune", &[("dest", "ChainId"), ("nonce", "u64")]),
        ],
        &["to_hub", "pending_transfers", "pending_calls", "pending_call_count", "pending_calls_of", "owed_acks"],
        &["Withdrawn", "Sent", "Pruned"],
        &[
            "InsufficientBalance",
            "FeeBelowHubMinimum",
            "TooManyPending",
            "ChannelUnavailable",
            "CallTooLong",
            "NotPrunable",
            "SendFailed",
        ],
    )
}

/// The `DispatchError` of `e` for this module at index `module` in the runtime: `Module` errors
/// 0 the payer can't pay, 1 the fee is below the Hub's minimum, 2 too many messages wait for an
/// answer, 3 the channel can't take it (destination full, backlog, refused source, channel
/// limit), 6 any other send failure.
pub fn dispatch_error(e: SendError, module: u8) -> DispatchError {
    let error = match e {
        SendError::Balance(_) => 0,
        SendError::FeeBelowHubMinimum { .. } => 1,
        SendError::TooManyTransfers | SendError::TooManyPendingCalls | SendError::TooManyPendingCallsFromSender => 2,
        SendError::DestinationFull | SendError::Backlog | SendError::Refused | SendError::TooManyChannels => 3,
        SendError::BadOrigin => return DispatchError::BadOrigin,
        SendError::Storage => return DispatchError::Other("cgmp storage"),
        SendError::ToSelf | SendError::ToHub | SendError::Nonce => 6,
    };
    DispatchError::Module { module, error }
}

/// Dispatch `call` from `origin` in block context `cx`; `module` is this module's index in the
/// runtime. `withdraw` and `send` push their message to the outbox; `send` and `prune` read the
/// Hub at the relay parent: `cgmp.inbound[dest]`, the channel `(chain, dest)` and
/// `cgmp.refused[(chain, dest)]`. A `send` reserves `deposits` from its sender until its record
/// is deleted (§7.1).
pub fn dispatch<E: HostEnv>(
    e: &mut Scoped<'_, E>,
    cx: &Context,
    module: u8,
    origin: Origin,
    call: Call,
    deposits: CallDeposits,
) -> Result<(), DispatchError> {
    let err = |x: SendError| dispatch_error(x, module);
    match call {
        Call::Withdraw { to, amount, fee, timeout } => {
            let from = ensure_signed(origin)?;
            let h = timeout_height(cx.relay, timeout);
            let m = send_tog(e, cx.chain, &from, to, amount, fee, h, deposits.per_byte).map_err(err)?;
            e.outbox_push(&borsh::to_vec(&m).expect("in-memory borsh"));
            e.deposit_event("cgmp", &Event::Withdrawn { from, to, amount, nonce: m.channel_nonce });
        }
        Call::Send { dest, module: target, call, weight_limit, fee, timeout } => {
            let sender = ensure_signed(origin)?;
            if call.len() > MAX_CALL_LEN {
                return Err(DispatchError::Module { module, error: 4 });
            }
            let chain = cx.chain;
            let inbound: Vec<ChainId> =
                e.hub_read(&cgmp_inbound(&dest)).and_then(|b| borsh::from_slice(&b).ok()).unwrap_or_default();
            let delivered = hub_channel(e, chain, dest).map_or(0, |c| c.next_nonce);
            let refused = e.hub_read(&cgmp_refused(&chain, &dest)).is_some();
            let out = Outgoing {
                dest,
                timeout_height: timeout_height(cx.relay, timeout),
                fee,
                origin: CgmpOrigin::Account { chain, account: sender },
                payload: CgmpPayload::Call { module: target, call, weight_limit },
            };
            let at = AtDest { inbound: &inbound, delivered, refused };
            let m = send_call(e, chain, &sender, out, at, deposits).map_err(err)?;
            e.outbox_push(&borsh::to_vec(&m).expect("in-memory borsh"));
            e.deposit_event("cgmp", &Event::Sent { sender, dest, nonce: m.channel_nonce });
        }
        Call::Prune { dest, nonce } => {
            ensure_signed(origin)?;
            let channel = hub_channel(e, cx.chain, dest).unwrap_or_default();
            if !prune(e, dest, nonce, &channel, cx.relay).map_err(|x| err(x.into()))? {
                return Err(DispatchError::Module { module, error: 5 });
            }
            e.deposit_event("cgmp", &Event::Pruned { dest, nonce });
        }
    }
    Ok(())
}

/// The channel `chain → dest` on the Hub at the relay parent; `None` while it has none.
fn hub_channel(e: &mut impl HostEnv, chain: ChainId, dest: ChainId) -> Option<CgmpChannel> {
    e.hub_read(&cgmp_channel(&chain, &dest)).and_then(|b| borsh::from_slice(&b).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tog_runtime_core::memory::MemoryStorage;

    const SRC: ChainId = ChainId(7);

    fn msg(n: u64) -> CgmpMessage {
        CgmpMessage {
            version: CGMP_VERSION,
            source: SRC,
            dest: ChainId(9),
            channel_nonce: n,
            timeout_height: 1_000,
            fee: 0,
            origin: CgmpOrigin::Chain(SRC),
            payload: CgmpPayload::TransferTog { to: [3; 20], amount: u128::from(n) },
        }
    }

    /// The Hub's channel after messages `0..count`.
    fn channel(count: u64, max_lag: u32) -> CgmpChannel {
        let head = (0..count).fold(HEAD_0, |h, n| next_head(&h, &msg(n).hash()));
        CgmpChannel { head, last_nonce: count.checked_sub(1), next_nonce: 0, max_lag }
    }

    fn proof(from: u64, to: u64) -> Vec<Hash32> {
        (from..=to).map(|n| msg(n).hash()).collect()
    }

    #[test]
    fn messages_are_accepted_in_order_with_proofs() {
        let mut s = MemoryStorage::default();
        let ch = channel(3, 256);
        assert_eq!(accept(&mut s, &msg(0), Some(&proof(1, 2)), &ch, 1_000), Ok(Delivery::Execute));
        // Expired at the relay parent: consumed all the same, but not to be executed.
        assert_eq!(accept(&mut s, &msg(1), Some(&proof(2, 2)), &ch, 1_001), Ok(Delivery::Expired));
        assert_eq!(accept(&mut s, &msg(2), Some(&[]), &ch, 1_001), Ok(Delivery::Expired));
        let st = inbound(&mut s, SRC).unwrap();
        assert_eq!(st.next_nonce, 3);
        assert_eq!(st.queue_head, ch.head);
    }

    #[test]
    fn one_proof_on_the_last_message_covers_the_block() {
        let mut s = MemoryStorage::default();
        let ch = channel(5, 256);
        let mut run = InboxRun::default();
        run.accept(&mut s, &msg(0), None, &ch, 0).unwrap();
        run.accept(&mut s, &msg(1), None, &ch, 0).unwrap();
        run.accept(&mut s, &msg(2), Some(&proof(3, 4)), &ch, 0).unwrap();
        assert_eq!(run.finish(&mut s, &[(SRC, ch)], false), Ok(vec![(SRC, 3)]));
        assert_eq!(run.taken(SRC), 3);

        // The next block stops without a proof on its last message.
        let mut run = InboxRun::default();
        run.accept(&mut s, &msg(3), Some(&proof(4, 4)), &ch, 0).unwrap();
        run.accept(&mut s, &msg(4), None, &ch, 0).unwrap();
        assert_eq!(run.finish(&mut s, &[(SRC, ch)], false), Err(InboxError::MissingProof));
    }

    #[test]
    fn wrong_nonce_length_or_head_is_refused() {
        let mut s = MemoryStorage::default();
        let ch = channel(3, 256);
        assert_eq!(accept(&mut s, &msg(1), Some(&proof(2, 2)), &ch, 0), Err(InboxError::Nonce));
        assert_eq!(accept(&mut s, &msg(0), Some(&proof(1, 1)), &ch, 0), Err(InboxError::ProofLength));
        let mut forged = msg(0);
        forged.fee = 5;
        assert_eq!(accept(&mut s, &forged, Some(&proof(1, 2)), &ch, 0), Err(InboxError::ProofHead));
        let empty = CgmpChannel::default();
        assert_eq!(accept(&mut s, &msg(0), Some(&proof(1, 0)), &empty, 0), Err(InboxError::ProofLength));
        assert_eq!(inbound(&mut s, SRC).unwrap(), Inbound::default());
    }

    #[test]
    fn a_backlog_over_max_lag_must_drain_min_drain() {
        let mut s = MemoryStorage::default();
        // Nothing pending, or within max_lag: fine without taking anything.
        assert!(InboxRun::default().finish(&mut s, &[(SRC, channel(0, 0))], false).is_ok());
        assert!(InboxRun::default().finish(&mut s, &[(SRC, channel(2, 2))], false).is_ok());
        assert_eq!(InboxRun::default().finish(&mut s, &[(SRC, channel(3, 2))], false), Err(InboxError::Lag));

        // 100 pending over max_lag 2: taking 63 isn't enough, 64 is, though 36 stay pending.
        let ch = channel(100, 2);
        let take = |s: &mut MemoryStorage, n: u64| {
            let mut run = InboxRun::default();
            for i in 0..n {
                let p = (i + 1 == n).then(|| proof(i + 1, 99));
                run.accept(s, &msg(i), p.as_deref(), &ch, 0).unwrap();
            }
            run
        };
        let mut short = s.clone();
        let run = take(&mut short, 63);
        assert_eq!(run.finish(&mut short, &[(SRC, ch)], false), Err(InboxError::Lag));
        let run = take(&mut s, MIN_DRAIN);
        assert_eq!(run.finish(&mut s, &[(SRC, ch)], false), Ok(vec![(SRC, 64)]));
    }

    #[test]
    fn expired_messages_get_a_timeout_ack_but_acks_do_not() {
        let mut s = MemoryStorage::default();
        let a = timeout_ack(&mut s, ME, &msg(4), 0).unwrap().unwrap();
        assert_eq!((a.dest, a.fee, a.timeout_height, a.origin), (SRC, 0, u64::MAX, CgmpOrigin::Chain(ME)));
        assert_eq!(a.payload, CgmpPayload::Ack { of_nonce: 4, result: Err(CgmpError::Timeout) });
        let mut ack = msg(5);
        ack.payload = CgmpPayload::Ack { of_nonce: 0, result: Ok(()) };
        assert_eq!(timeout_ack(&mut s, ME, &ack, 0), Ok(None));
    }

    const ME: ChainId = ChainId(9);
    const A: AccountId = [1; 20];
    /// The destination at the relay parent.
    fn at(inbound: &[ChainId], delivered: u64, refused: bool) -> AtDest<'_> {
        AtDest { inbound, delivered, refused }
    }
    /// No deposit on pending calls, for tests about something else.
    const FREE: CallDeposits = CallDeposits { per_byte: 0, per_call: 0 };

    fn out(dest: ChainId) -> Outgoing {
        Outgoing {
            dest,
            timeout_height: 50,
            fee: 0,
            origin: CgmpOrigin::Chain(ME),
            payload: CgmpPayload::TransferTog { to: [2; 20], amount: 1 },
        }
    }

    #[test]
    fn send_numbers_each_channel_and_folds_its_head() {
        let mut s = MemoryStorage::default();
        let a = send(&mut s, ME, out(ChainId(4))).unwrap();
        let b = send(&mut s, ME, out(ChainId(2))).unwrap();
        let c = send(&mut s, ME, out(ChainId(4))).unwrap();
        assert_eq!((a.channel_nonce, b.channel_nonce, c.channel_nonce), (0, 0, 1));
        assert_eq!((a.source, a.version), (ME, CGMP_VERSION));
        let o = outbox(&mut s).unwrap();
        assert_eq!(o.iter().map(|c| (c.dest, c.last_nonce)).collect::<Vec<_>>(), [(ChainId(2), 0), (ChainId(4), 1)]);
        assert_eq!(o[1].head, next_head(&next_head(&HEAD_0, &a.hash()), &c.hash()));
        assert_eq!(outbox_root(&mut s).unwrap(), tog_types::cgmp::outbox_root(&o));
        assert_eq!(send(&mut s, ME, out(ME)), Err(SendError::ToSelf));
    }

    /// A message fee above the Hub's minimum.
    const FEE: Amount = 10_000_000_000_000_000;

    #[test]
    fn tog_leaves_and_enters_the_issuance() {
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &A, FEE + 100).unwrap();
        let payload = CgmpPayload::TransferTog { to: [5; 20], amount: 60 };
        let min = hub_fee(ME, &CgmpOrigin::Account { chain: ME, account: A }, &payload);
        assert!(min > CGMP_BASE_FEE && min < FEE);
        assert_eq!(send_tog(&mut s, ME, &A, [5; 20], 60, min - 1, 50, 0), Err(SendError::FeeBelowHubMinimum { min }));
        let m = send_tog(&mut s, ME, &A, [5; 20], 60, FEE, 50, 0).unwrap();
        assert_eq!(min_hub_fee(&m), min, "the length doesn't depend on nonce, timeout or fee");
        assert_eq!((m.dest, m.fee), (ChainId::HUB, FEE));
        assert_eq!(m.origin, CgmpOrigin::Account { chain: ME, account: A });
        assert_eq!(m.payload, payload);
        assert_eq!(balances::free_balance(&mut s, &A).unwrap(), 40);
        assert_eq!(balances::total_issuance(&mut s).unwrap(), 40);

        let before = outbox(&mut s).unwrap();
        assert_eq!(
            send_tog(&mut s, ME, &A, [5; 20], 30, FEE, 50, 0),
            Err(SendError::Balance(balances::Error::InsufficientBalance))
        );
        assert_eq!(outbox(&mut s).unwrap(), before, "nothing sent unpaid");

        let mut deposit = msg(0);
        deposit.source = ChainId::HUB;
        assert_eq!(receive_tog(&mut s, &deposit), Ok(Received::Credited));
        assert_eq!(balances::free_balance(&mut s, &[3; 20]).unwrap(), 0, "amount 0 credits nothing");
        let mut d = deposit.clone();
        d.payload = CgmpPayload::TransferTog { to: [3; 20], amount: 7 };
        receive_tog(&mut s, &d).unwrap();
        assert_eq!(balances::free_balance(&mut s, &[3; 20]).unwrap(), 7);
        assert_eq!(balances::total_issuance(&mut s).unwrap(), 47);
        assert_eq!(receive_tog(&mut s, &msg(1)), Ok(Received::NotTog), "only the Hub mints");
    }

    fn ack(of_nonce: u64, result: Result<(), CgmpError>) -> CgmpMessage {
        let mut m = msg(0);
        m.source = ChainId::HUB;
        m.payload = CgmpPayload::Ack { of_nonce, result };
        m
    }

    /// A message to the Hub holds its sender's storage deposit until the Hub acks it, however it
    /// ends; a sender who can't cover it sends nothing (R-6).
    #[test]
    fn a_message_to_the_hub_holds_a_deposit_until_its_ack() {
        let per_byte = storage_deposit::DEFAULT_PER_BYTE;
        let held = storage_deposit::deposit_for(TO_HUB_BYTES, per_byte).unwrap();
        let record = ToHub { account: A, kind: Kind::Transfer, amount: 0, fee: 0 };
        assert_eq!(borsh::object_length(&record).unwrap() as u64, TO_HUB_BYTES);
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &A, 2 * (FEE + 20 + held)).unwrap();
        for _ in 0..2 {
            send_tog(&mut s, ME, &A, [5; 20], 20, FEE, 50, per_byte).unwrap();
        }
        assert_eq!(balances::account(&mut s, &A).unwrap().reserved, 2 * held);
        receive_ack(&mut s, &ack(0, Ok(()))).unwrap();
        assert_eq!(balances::account(&mut s, &A).unwrap().reserved, held);
        receive_ack(&mut s, &ack(1, Err(CgmpError::Timeout))).unwrap();
        assert_eq!(balances::account(&mut s, &A).unwrap().reserved, 0);
        assert_eq!(balances::free_balance(&mut s, &A).unwrap(), FEE + 20 + 2 * held);

        // Enough for the amount and fee, not the deposit: refused, nothing sent or reserved.
        let mut poor = MemoryStorage::default();
        balances::deposit(&mut poor, &A, FEE + 20).unwrap();
        let before = outbox(&mut poor).unwrap();
        assert_eq!(
            send_tog(&mut poor, ME, &A, [5; 20], 20, FEE, 50, per_byte),
            Err(SendError::Balance(balances::Error::InsufficientBalance))
        );
        assert_eq!(outbox(&mut poor).unwrap(), before);
        assert_eq!(balances::account(&mut poor, &A).unwrap().total(), FEE + 20);
        // Enough for the deposit, not the amount: the deposit comes back.
        balances::deposit(&mut poor, &A, held).unwrap();
        assert!(send_tog(&mut poor, ME, &A, [5; 20], 21, FEE, 50, per_byte).is_err());
        assert_eq!(balances::account(&mut poor, &A).unwrap().reserved, 0);
        assert!(!storage_deposit::DEPOSITS.contains_key(&mut poor, &TO_HUB.key(&0)));
    }

    #[test]
    fn hub_acks_settle_what_the_chain_sent() {
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &A, 3 * FEE + 100).unwrap();
        for _ in 0..3 {
            send_tog(&mut s, ME, &A, [5; 20], 20, FEE, 50, 0).unwrap();
        }
        assert_eq!(next_nonce(&mut s, ChainId::HUB), Ok(3));
        assert_eq!(balances::total_issuance(&mut s).unwrap(), 40);

        // Taken: nothing comes back. Refused after the Hub took the fee: the amount comes back.
        // Refused before (timeout, fee not covered): the fee too.
        assert_eq!(receive_ack(&mut s, &ack(0, Ok(()))), Ok(Some(Acked::Taken { nonce: 0 })));
        let refused = Acked::Refunded { nonce: 1, error: CgmpError::SupplyLedgerUnderflow, minted: 20 };
        assert_eq!(receive_ack(&mut s, &ack(1, Err(CgmpError::SupplyLedgerUnderflow))), Ok(Some(refused)));
        let late = Acked::Refunded { nonce: 2, error: CgmpError::Timeout, minted: 20 + FEE };
        assert_eq!(receive_ack(&mut s, &ack(2, Err(CgmpError::Timeout))), Ok(Some(late)));
        assert_eq!(balances::free_balance(&mut s, &A).unwrap(), 80 + FEE);
        assert_eq!(balances::total_issuance(&mut s).unwrap(), 80 + FEE);

        // Each message settles once, and only the Hub's acks count.
        assert_eq!(receive_ack(&mut s, &ack(2, Err(CgmpError::Timeout))), Ok(None));
        assert!(!TO_HUB.contains_key(&mut s, &0));
        let mut forged = ack(0, Err(CgmpError::Timeout));
        forged.source = SRC;
        assert_eq!(receive_ack(&mut s, &forged), Ok(None));
        assert_eq!(receive_ack(&mut s, &msg(0)), Ok(None));
        assert_eq!(PENDING_TRANSFERS.get(&mut s).unwrap(), Some(0));

        // Transfers waiting for their Ack are bounded.
        PENDING_TRANSFERS.put(&mut s, &MAX_PENDING_TRANSFERS).unwrap();
        assert_eq!(send_tog(&mut s, ME, &A, [5; 20], 1, FEE, 50, 0), Err(SendError::TooManyTransfers));
        assert_eq!(balances::free_balance(&mut s, &A).unwrap(), 80 + FEE);
    }

    #[test]
    fn root_sets_the_chains_worker_set_rules_on_the_hub() {
        use tog_types::eligibility::HwFilter;
        use tog_types::job::IsolationTier;
        let rules = WorkerSetRules {
            min_isolation: IsolationTier::T0Gvisor,
            hw_filter: HwFilter {
                min_gpus: 0,
                cc: None,
                min_vram_bytes: 0,
                gpu_models: None,
                require_cc_capable: false,
                min_cpu_isa: None,
                min_ram_bytes: 0,
            },
            required_toolchains: vec![],
            min_bond: 1,
            min_reputation: 0,
            regions: None,
            accepts_external_jobs: false,
            allowlist: None,
            allowed_policies: None,
        };
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &A, FEE).unwrap();
        let signed = Origin::Signed(A);
        assert_eq!(set_worker_set_rules(&mut s, ME, &signed, &A, rules.clone(), FEE, 50, 0), Err(SendError::BadOrigin));

        let m = set_worker_set_rules(&mut s, ME, &Origin::Root, &A, rules.clone(), FEE, 50, 0).unwrap();
        assert_eq!((m.dest, m.origin.clone(), m.fee), (ChainId::HUB, CgmpOrigin::Chain(ME), FEE));
        let CgmpPayload::Call { module, call, .. } = &m.payload else { panic!() };
        assert_eq!(*module, APPCHAINS_MODULE);
        // `call = borsh((0u8, rules))` (0002 §4.7).
        assert_eq!(*call, borsh::to_vec(&(0u8, rules)).unwrap());
        assert_eq!(balances::free_balance(&mut s, &A).unwrap(), 0);

        // The Hub refused the rules: it kept the fee.
        let refused = Acked::Refunded { nonce: 0, error: CgmpError::DispatchFailed, minted: 0 };
        assert_eq!(receive_ack(&mut s, &ack(0, Err(CgmpError::DispatchFailed))), Ok(Some(refused)));
        assert_eq!(PENDING_TRANSFERS.get(&mut s).unwrap(), None, "not a transfer");
    }

    #[test]
    fn outgoing_channels_are_capped() {
        let mut s = MemoryStorage::default();
        for d in 0..MAX_OUT_CHANNELS as u32 {
            send(&mut s, ME, out(ChainId(100 + d))).unwrap();
        }
        assert_eq!(send(&mut s, ME, out(ChainId(1))), Err(SendError::TooManyChannels));
        // An existing channel keeps working.
        assert!(send(&mut s, ME, out(ChainId(100))).is_ok());
    }

    #[test]
    fn calls_to_appchains_are_recorded_refunded_on_timeout_and_pruned() {
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &A, 100).unwrap();
        let dest = ChainId(4);
        let mut o = out(dest);
        o.fee = 10;
        let m0 = send_call(&mut s, ME, &A, o.clone(), at(&[], 0, false), FREE).unwrap();
        let m1 = send_call(&mut s, ME, &A, o.clone(), at(&[], 0, false), FREE).unwrap();
        assert_eq!(balances::free_balance(&mut s, &A).unwrap(), 80);
        assert_eq!(PENDING_CALL_COUNT.get(&mut s).unwrap(), Some(2));

        // The destination timed message 0 out: its fee comes back.
        let mut ack = msg(0);
        ack.source = dest;
        ack.payload = CgmpPayload::Ack { of_nonce: m0.channel_nonce, result: Err(CgmpError::Timeout) };
        let p = receive_timeout(&mut s, &ack).unwrap().unwrap();
        assert_eq!((p.sender, p.fee), (A, 10));
        assert_eq!(balances::free_balance(&mut s, &A).unwrap(), 90);
        assert_eq!(receive_timeout(&mut s, &ack), Ok(None), "once");

        // Message 1 ran: prunable once the channel passed it within its timeout.
        let ch = |next_nonce| CgmpChannel { head: HEAD_0, last_nonce: Some(1), next_nonce, max_lag: 256 };
        assert_eq!(prune(&mut s, dest, m1.channel_nonce, &ch(1), 10), Ok(false), "not passed yet");
        assert_eq!(prune(&mut s, dest, m1.channel_nonce, &ch(2), 51), Ok(false), "passed too late to tell");
        assert_eq!(prune(&mut s, dest, m1.channel_nonce, &ch(2), 50), Ok(true));
        assert_eq!(PENDING_CALL_COUNT.get(&mut s).unwrap(), Some(0));

        assert_eq!(send_call(&mut s, ME, &A, out(ChainId::HUB), at(&[], 0, false), FREE), Err(SendError::ToHub));
        PENDING_CALL_COUNT.put(&mut s, &MAX_PENDING_CALLS).unwrap();
        assert_eq!(send_call(&mut s, ME, &A, o, at(&[], 0, false), FREE), Err(SendError::TooManyPendingCalls));
    }

    #[test]
    fn each_pending_call_holds_a_deposit_and_a_sender_has_at_most_16() {
        let mut s = MemoryStorage::default();
        let deposits = CallDeposits::default();
        let each = deposits.for_record().unwrap();
        assert!(each > DEFAULT_PENDING_CALL_DEPOSIT, "the flat deposit plus the bytes of the record");
        let dest = ChainId(4);
        let mut o = out(dest);
        o.fee = 10;
        let n = MAX_PENDING_CALLS_PER_SENDER;
        balances::deposit(&mut s, &A, Amount::from(n) * (each + 10) + 5).unwrap();

        // A sender who can't cover the deposit sends nothing.
        let poor: AccountId = [2; 20];
        balances::deposit(&mut s, &poor, each - 1 + 10).unwrap();
        let r = send_call(&mut s, ME, &poor, o.clone(), at(&[], 0, false), deposits);
        assert_eq!(r, Err(SendError::Balance(balances::Error::InsufficientBalance)));
        assert_eq!(balances::free_balance(&mut s, &poor).unwrap(), each - 1 + 10, "nothing taken");

        let sent: Vec<CgmpMessage> =
            (0..n).map(|_| send_call(&mut s, ME, &A, o.clone(), at(&[], 0, false), deposits).unwrap()).collect();
        let acc = balances::account(&mut s, &A).unwrap();
        assert_eq!((acc.free, acc.reserved), (5, Amount::from(n) * each));
        assert_eq!(PENDING_CALLS_OF.get(&mut s, &A).unwrap(), Some(n));
        // The 17th fails before anything is taken or sent, whatever its balance.
        balances::deposit(&mut s, &A, each + 10).unwrap();
        let r = send_call(&mut s, ME, &A, o.clone(), at(&[], 0, false), deposits);
        assert_eq!(r, Err(SendError::TooManyPendingCallsFromSender));
        assert_eq!(balances::free_balance(&mut s, &A).unwrap(), each + 15);
        assert_eq!(outbox(&mut s).unwrap()[0].last_nonce, u64::from(n) - 1);

        // A Timeout Ack returns the fee and the deposit, and frees a slot.
        let mut ack = msg(0);
        ack.source = dest;
        ack.payload = CgmpPayload::Ack { of_nonce: sent[0].channel_nonce, result: Err(CgmpError::Timeout) };
        assert_eq!(receive_timeout(&mut s, &ack).unwrap().unwrap().deposit, each);
        let acc = balances::account(&mut s, &A).unwrap();
        assert_eq!((acc.free, acc.reserved), (2 * each + 25, Amount::from(n - 1) * each));
        // So does a prune, which returns only the deposit: the fee paid for a message that ran.
        let ch = CgmpChannel { head: HEAD_0, last_nonce: Some(u64::from(n) - 1), next_nonce: 2, max_lag: 256 };
        assert_eq!(prune(&mut s, dest, sent[1].channel_nonce, &ch, 0), Ok(true));
        let acc = balances::account(&mut s, &A).unwrap();
        assert_eq!((acc.free, acc.reserved), (3 * each + 25, Amount::from(n - 2) * each));
        assert_eq!(PENDING_CALLS_OF.get(&mut s, &A).unwrap(), Some(n - 2));
        assert!(send_call(&mut s, ME, &A, o, at(&[], 0, false), deposits).is_ok());
        assert_eq!(PENDING_CALL_COUNT.get(&mut s).unwrap(), Some(n - 1));
    }

    #[test]
    fn a_full_destination_takes_no_new_channel() {
        let mut s = MemoryStorage::default();
        let full: Vec<ChainId> = (0..MAX_IN_CHANNELS as u32).map(|i| ChainId(200 + i)).chain([ChainId::HUB]).collect();
        assert_eq!(may_open(&mut s, ME, ChainId(4), &full), Ok(false));
        assert_eq!(may_open(&mut s, ME, ChainId(4), &full[1..]), Ok(true));
        assert_eq!(may_open(&mut s, ME, ChainId::HUB, &full), Ok(true));
        send(&mut s, ME, out(ChainId(4))).unwrap();
        assert_eq!(may_open(&mut s, ME, ChainId(4), &full), Ok(true), "already open");
        assert_eq!(
            send_call(&mut s, ME, &A, out(ChainId(5)), at(&full, 0, false), FREE),
            Err(SendError::DestinationFull)
        );
    }

    /// Fill this chain's channel to `dest` up to nonce `last`.
    fn sent_up_to(s: &mut MemoryStorage, dest: ChainId, last: u64) {
        let mut channels = outbox(s).unwrap();
        channels.retain(|c| c.dest != dest);
        channels.push(OutboxChannel { dest, head: HEAD_0, last_nonce: last });
        channels.sort_by_key(|c| c.dest);
        OUTBOX.put(s, &channels).unwrap();
    }

    #[test]
    fn a_send_that_would_take_a_channel_over_max_backlog_fails() {
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &A, 100).unwrap();
        let dest = ChainId(4);
        // Nonces 0..=1 022 sent, none processed: one more fills the channel to MAX_BACKLOG.
        sent_up_to(&mut s, dest, MAX_BACKLOG - 2);
        let m = send_call(&mut s, ME, &A, out(dest), at(&[], 0, false), FREE).unwrap();
        assert_eq!(m.channel_nonce, MAX_BACKLOG - 1);
        assert_eq!(send_call(&mut s, ME, &A, out(dest), at(&[], 0, false), FREE), Err(SendError::Backlog));
        // Once the destination processed one, there is room for one more.
        assert!(send_call(&mut s, ME, &A, out(dest), at(&[], 1, false), FREE).is_ok());
        // The Hub's own channel isn't capped here.
        assert_eq!(fits_backlog(&mut s, ChainId::HUB, 0), Ok(true));
    }

    #[test]
    fn timeout_acks_that_dont_fit_wait_in_order_and_go_out_when_there_is_room() {
        let mut s = MemoryStorage::default();
        // The channel back to SRC is full: nothing of it processed.
        sent_up_to(&mut s, SRC, MAX_BACKLOG - 1);
        assert_eq!(timeout_ack(&mut s, ME, &msg(4), 0), Ok(None));
        assert_eq!(timeout_ack(&mut s, ME, &msg(5), 0), Ok(None));
        assert_eq!(OWED_ACKS.get(&mut s, &SRC).unwrap(), Some(vec![4, 5]));
        assert_eq!(owed_sources(&mut s), Ok(vec![SRC]));
        // Room for one: the older Ack goes first; a new one queues behind the rest even with room.
        let sent = send_owed_acks(&mut s, ME, &[(SRC, 1)]).unwrap();
        let of = |m: &CgmpMessage| match m.payload {
            CgmpPayload::Ack { of_nonce, result: Err(CgmpError::Timeout) } => of_nonce,
            _ => panic!("not a Timeout Ack"),
        };
        assert_eq!(sent.iter().map(of).collect::<Vec<_>>(), [4]);
        assert_eq!(sent[0].channel_nonce, MAX_BACKLOG);
        assert_eq!(timeout_ack(&mut s, ME, &msg(6), 10), Ok(None));
        assert_eq!(OWED_ACKS.get(&mut s, &SRC).unwrap(), Some(vec![5, 6]));
        // With room for all, the queue empties and the source is forgotten.
        let sent = send_owed_acks(&mut s, ME, &[(SRC, 10)]).unwrap();
        assert_eq!(sent.iter().map(of).collect::<Vec<_>>(), [5, 6]);
        assert_eq!(OWED_ACKS.get(&mut s, &SRC).unwrap(), None);
        assert_eq!(owed_sources(&mut s), Ok(vec![]));
        // Then an Ack that fits goes out at once.
        assert!(timeout_ack(&mut s, ME, &msg(7), 10).unwrap().is_some());

        // A full queue drops the next Ack.
        let mut full = MemoryStorage::default();
        sent_up_to(&mut full, SRC, MAX_BACKLOG - 1);
        OWED_ACKS.insert(&mut full, &SRC, &(0..u64::from(MAX_PENDING_CALLS)).collect()).unwrap();
        OWED_SOURCES.put(&mut full, &vec![SRC]).unwrap();
        assert_eq!(timeout_ack(&mut full, ME, &msg(5_000), 0), Ok(None));
        assert_eq!(OWED_ACKS.get(&mut full, &SRC).unwrap().unwrap().len(), MAX_PENDING_CALLS as usize);
    }

    #[test]
    fn a_destination_that_refuses_this_chain_takes_no_call() {
        let mut s = MemoryStorage::default();
        balances::deposit(&mut s, &A, 100).unwrap();
        let mut o = out(ChainId(4));
        o.fee = 10;
        send_call(&mut s, ME, &A, o.clone(), at(&[], 0, false), FREE).unwrap();
        // Even on an open channel, and nothing is charged or recorded.
        assert_eq!(send_call(&mut s, ME, &A, o, at(&[ME], 0, true), FREE), Err(SendError::Refused));
        assert_eq!(balances::free_balance(&mut s, &A).unwrap(), 90);
        assert_eq!(PENDING_CALL_COUNT.get(&mut s).unwrap(), Some(1));
        assert_eq!(next_nonce(&mut s, ChainId(4)), Ok(1));
    }
}
