//! Bounded collections (TOG-SPEC-0007 §5). Runtime state may only hold collections with a
//! compile-time bound, so that no single call reads or writes an unbounded amount of state.

use alloc::vec::Vec;
use core::ops::Deref;

use borsh::io::{Error, ErrorKind, Read, Result as IoResult, Write};
use borsh::{BorshDeserialize, BorshSerialize};

/// A `Vec<T>` that never holds more than `N` items. Its Borsh encoding is the `Vec`'s
/// (`u32` length then items); decoding refuses a length above `N` before reading any item.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedVec<T, const N: usize>(Vec<T>);

/// The item a push or conversion would not fit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Full<T>(pub T);

impl<T, const N: usize> BoundedVec<T, N> {
    /// The bound.
    pub const BOUND: usize = N;

    /// An empty vector.
    pub const fn new() -> Self {
        BoundedVec(Vec::new())
    }

    /// Append `item`, or hand it back if the vector is full.
    pub fn try_push(&mut self, item: T) -> Result<(), Full<T>> {
        if self.0.len() >= N {
            return Err(Full(item));
        }
        self.0.push(item);
        Ok(())
    }

    /// Remove and return the item at `index`, shifting the rest left.
    pub fn remove(&mut self, index: usize) -> T {
        self.0.remove(index)
    }

    /// Keep only the items for which `f` is true.
    pub fn retain(&mut self, f: impl FnMut(&T) -> bool) {
        self.0.retain(f)
    }

    /// The inner `Vec`.
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Deref for BoundedVec<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T, const N: usize> TryFrom<Vec<T>> for BoundedVec<T, N> {
    type Error = Full<Vec<T>>;
    fn try_from(v: Vec<T>) -> Result<Self, Self::Error> {
        if v.len() > N {
            return Err(Full(v));
        }
        Ok(BoundedVec(v))
    }
}

impl<T: BorshSerialize, const N: usize> BorshSerialize for BoundedVec<T, N> {
    fn serialize<W: Write>(&self, w: &mut W) -> IoResult<()> {
        self.0.serialize(w)
    }
}

impl<T: BorshDeserialize, const N: usize> BorshDeserialize for BoundedVec<T, N> {
    fn deserialize_reader<R: Read>(r: &mut R) -> IoResult<Self> {
        let len = u32::deserialize_reader(r)? as usize;
        if len > N {
            return Err(Error::new(ErrorKind::InvalidData, "BoundedVec over its bound"));
        }
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            v.push(T::deserialize_reader(r)?);
        }
        Ok(BoundedVec(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn push_stops_at_the_bound() {
        let mut v = BoundedVec::<u8, 2>::new();
        v.try_push(1).unwrap();
        v.try_push(2).unwrap();
        assert_eq!(v.try_push(3), Err(Full(3)));
        assert_eq!(&*v, &[1, 2]);
    }

    #[test]
    fn encoding_is_the_vec_encoding() {
        let v = BoundedVec::<u16, 4>::try_from(vec![1, 2, 3]).unwrap();
        assert_eq!(borsh::to_vec(&v).unwrap(), borsh::to_vec(&vec![1u16, 2, 3]).unwrap());
        assert_eq!(borsh::from_slice::<BoundedVec<u16, 4>>(&borsh::to_vec(&v).unwrap()).unwrap(), v);
    }

    #[test]
    fn decoding_refuses_over_bound() {
        let bytes = borsh::to_vec(&vec![0u8; 3]).unwrap();
        assert!(borsh::from_slice::<BoundedVec<u8, 2>>(&bytes).is_err());
        // A huge declared length fails before any allocation of that size.
        assert!(borsh::from_slice::<BoundedVec<u8, 2>>(&u32::MAX.to_le_bytes()).is_err());
    }
}
