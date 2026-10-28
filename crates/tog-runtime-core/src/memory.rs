//! In-memory storage backends: [`MemoryStorage`] for tests and collators, and [`Overlay`] to apply
//! a call's writes only if it succeeds.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ops::Bound;

use crate::storage::{Storage, StorageKey};

/// Storage accesses of one block, as the PoV witness needs them: for every key touched, its value
/// **before** the block (`None` = absent). Keys only written, never read, are not in it.
pub type Witness = BTreeMap<StorageKey, Option<Vec<u8>>>;

/// A `BTreeMap` state that can record its reads into a [`Witness`].
#[derive(Clone, Debug, Default)]
pub struct MemoryStorage {
    map: BTreeMap<StorageKey, Vec<u8>>,
    recording: Option<Witness>,
}

impl MemoryStorage {
    /// Start recording reads; any earlier recording is dropped.
    pub fn start_recording(&mut self) {
        self.recording = Some(Witness::new());
    }

    /// Stop recording and return the witness (empty if recording was off).
    pub fn take_witness(&mut self) -> Witness {
        self.recording.take().unwrap_or_default()
    }

    /// Number of keys with a value.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether no key holds a value.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Every key-value pair, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&StorageKey, &Vec<u8>)> {
        self.map.iter()
    }

    /// The value at `key`, borrowed and not recorded: for readers that share the state.
    pub fn value(&self, key: &StorageKey) -> Option<&Vec<u8>> {
        self.map.get(key)
    }

    /// The first key after `key` holding a value, not recorded.
    pub fn key_after(&self, key: &StorageKey) -> Option<StorageKey> {
        self.map.range((Bound::Excluded(*key), Bound::Unbounded)).next().map(|(k, _)| *k)
    }

    /// Record `key` with its current value, unless it was recorded already.
    fn record(&mut self, key: &StorageKey) {
        if let Some(w) = &mut self.recording {
            w.entry(*key).or_insert_with(|| self.map.get(key).cloned());
        }
    }
}

impl Storage for MemoryStorage {
    fn get(&mut self, key: &StorageKey) -> Option<Vec<u8>> {
        self.record(key);
        self.map.get(key).cloned()
    }

    fn set(&mut self, key: &StorageKey, value: Vec<u8>) {
        // A write needs the old leaf's path in the proof too, so it counts as an access.
        self.record(key);
        self.map.insert(*key, value);
    }

    fn clear(&mut self, key: &StorageKey) {
        self.record(key);
        self.map.remove(key);
    }

    fn next_key(&mut self, key: &StorageKey) -> Option<StorageKey> {
        let next = self.map.range((Bound::Excluded(*key), Bound::Unbounded)).next().map(|(k, _)| *k);
        if let Some(k) = &next {
            self.record(k);
        }
        next
    }
}

/// Buffered changes over a base storage. Reads see the buffered writes; [`Overlay::commit`] applies
/// them to the base and dropping the overlay discards them. Used to revert a failed call.
pub struct Overlay<'a, S: Storage> {
    base: &'a mut S,
    changes: BTreeMap<StorageKey, Option<Vec<u8>>>,
    /// Each write's key and the change it replaced (`None`: the key had none), oldest first: what
    /// [`Overlay::restore`] undoes.
    journal: Vec<(StorageKey, Option<Option<Vec<u8>>>)>,
}

impl<'a, S: Storage> Overlay<'a, S> {
    /// An empty overlay over `base`.
    pub fn new(base: &'a mut S) -> Self {
        Overlay { base, changes: BTreeMap::new(), journal: Vec::new() }
    }

    /// Apply every buffered change to the base, and give the base back.
    pub fn commit(self) -> &'a mut S {
        for (k, v) in self.changes {
            match v {
                Some(v) => self.base.set(&k, v),
                None => self.base.clear(&k),
            }
        }
        self.base
    }

    /// The base, for what isn't storage (the host's other functions); its storage must not be
    /// written through this.
    pub fn base(&mut self) -> &mut S {
        self.base
    }

    /// The buffered changes, leaving the base as it was: `None` clears the key.
    pub fn into_changes(self) -> BTreeMap<StorageKey, Option<Vec<u8>>> {
        self.changes
    }

    /// Number of keys changed.
    pub fn changed(&self) -> usize {
        self.changes.len()
    }

    /// The changes buffered so far, to go back to with [`Overlay::restore`]: a nested call whose
    /// failure must not undo the outer one. A mark in the write journal, so taking one copies
    /// nothing (R-10).
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint(self.journal.len())
    }

    /// Drop every change made since `c` was taken. Checkpoints are restored innermost first; one
    /// taken before another that was restored stays valid.
    pub fn restore(&mut self, c: Checkpoint) {
        let from = c.0.min(self.journal.len());
        for (k, old) in self.journal.drain(from..).rev() {
            match old {
                Some(v) => self.changes.insert(k, v),
                None => self.changes.remove(&k),
            };
        }
    }

    fn write(&mut self, key: &StorageKey, value: Option<Vec<u8>>) {
        let old = self.changes.insert(*key, value);
        self.journal.push((*key, old));
    }
}

/// An [`Overlay`]'s changes at some point ([`Overlay::checkpoint`]).
#[derive(Clone, Copy, Debug)]
pub struct Checkpoint(usize);

impl<S: Storage> Storage for Overlay<'_, S> {
    fn get(&mut self, key: &StorageKey) -> Option<Vec<u8>> {
        match self.changes.get(key) {
            Some(v) => v.clone(),
            None => self.base.get(key),
        }
    }

    fn set(&mut self, key: &StorageKey, value: Vec<u8>) {
        self.write(key, Some(value));
    }

    fn clear(&mut self, key: &StorageKey) {
        self.write(key, None);
    }

    fn next_key(&mut self, key: &StorageKey) -> Option<StorageKey> {
        // Merge the base's next live key with the overlay's, skipping keys the overlay cleared.
        let mut from = *key;
        loop {
            let base = self.base.next_key(&from);
            let over = self.changes.range((Bound::Excluded(from), Bound::Unbounded)).find(|(_, v)| v.is_some());
            let over = over.map(|(k, _)| *k);
            let cand = match (base, over) {
                (Some(b), Some(o)) => b.min(o),
                (b, o) => b.or(o)?,
            };
            if matches!(self.changes.get(&cand), Some(None)) {
                from = cand;
                continue;
            }
            return Some(cand);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::storage_key;
    use alloc::vec;

    fn k(i: u8) -> StorageKey {
        let mut k = [0; 96];
        k[95] = i;
        k
    }

    #[test]
    fn witness_holds_values_before_the_block() {
        let mut s = MemoryStorage::default();
        s.set(&k(1), vec![1]);
        s.start_recording();
        assert_eq!(s.get(&k(1)), Some(vec![1]));
        s.set(&k(1), vec![2]);
        s.set(&k(2), vec![3]);
        assert_eq!(s.get(&k(3)), None);
        let w = s.take_witness();
        assert_eq!(w.get(&k(1)), Some(&Some(vec![1])));
        assert_eq!(w.get(&k(2)), Some(&None));
        assert_eq!(w.get(&k(3)), Some(&None));
        assert_eq!(w.len(), 3);
    }

    #[test]
    fn overlay_commits_or_discards() {
        let mut s = MemoryStorage::default();
        s.set(&k(1), vec![1]);
        {
            let mut o = Overlay::new(&mut s);
            o.set(&k(2), vec![2]);
            o.clear(&k(1));
            assert_eq!(o.get(&k(1)), None);
            // dropped: discarded
        }
        assert_eq!(s.get(&k(1)), Some(vec![1]));
        assert_eq!(s.get(&k(2)), None);
        let mut o = Overlay::new(&mut s);
        o.set(&k(2), vec![2]);
        o.clear(&k(1));
        o.commit();
        assert_eq!(s.get(&k(1)), None);
        assert_eq!(s.get(&k(2)), Some(vec![2]));
    }

    #[test]
    fn overlay_iteration_merges_and_skips_cleared() {
        let mut s = MemoryStorage::default();
        for i in [1, 3, 5] {
            s.set(&k(i), vec![i]);
        }
        let mut o = Overlay::new(&mut s);
        o.clear(&k(3));
        o.set(&k(4), vec![4]);
        let mut seen = vec![];
        let mut cur = k(0);
        while let Some(n) = o.next_key(&cur) {
            seen.push(n[95]);
            cur = n;
        }
        assert_eq!(seen, vec![1, 4, 5]);
    }

    #[test]
    fn next_key_on_typed_keys() {
        let mut s = MemoryStorage::default();
        let a = storage_key("m", "i", &[1]);
        s.set(&a, vec![]);
        assert_eq!(s.next_key(&[0; 96]), Some(a));
        assert_eq!(s.next_key(&a), None);
    }

    #[test]
    fn checkpoints_restore_nested_changes_innermost_first() {
        let mut base = MemoryStorage::default();
        base.set(&k(1), vec![1]);
        let mut o = Overlay::new(&mut base);
        o.set(&k(1), vec![2]);
        let outer = o.checkpoint();
        o.set(&k(1), vec![3]);
        o.clear(&k(2));
        let inner = o.checkpoint();
        o.set(&k(1), vec![4]);
        o.set(&k(3), vec![5]);
        o.clear(&k(1));
        o.restore(inner);
        assert_eq!((o.get(&k(1)), o.get(&k(3))), (Some(vec![3]), None));
        assert_eq!(o.changed(), 2);
        // An inner call that succeeded, then the outer one fails: back to before the outer.
        let inner = o.checkpoint();
        o.set(&k(4), vec![6]);
        let _ = inner;
        o.restore(outer);
        assert_eq!((o.get(&k(1)), o.get(&k(4))), (Some(vec![2]), None));
        assert_eq!(o.changed(), 1);
        o.restore(outer);
        assert_eq!(o.into_changes(), BTreeMap::from([(k(1), Some(vec![2]))]));
    }
}
