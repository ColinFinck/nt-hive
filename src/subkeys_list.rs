// Copyright 2020-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::bytes_subrange;
use crate::hive::Hive;
use crate::index_root::{IndexRootIter, IndexRootIterMut};
use crate::key_node::KeyNode;
use crate::leaf::{LeafIter, LeafIterMut, LeafType};
use ::byteorder::LittleEndian;
use core::iter::FusedIterator;
use core::mem;
use core::ops::{Deref, DerefMut, Range};
use zerocopy::*;

/// On-Disk Structure of a Subkeys List Header.
/// This is common for all subkey types (Fast Leaf, Hash Leaf, Index Leaf, Index Root).
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
pub(crate) struct SubkeysListHeader {
    pub(crate) signature: [u8; 2],
    pub(crate) count: U16<LittleEndian>,
}

pub struct SubkeysList<H: Deref<Target = Hive<B>>, B: ByteSlice> {
    hive: H,
    header_range: Range<usize>,
    pub(crate) data_range: Range<usize>,
}

/// A list of subkeys (common handling)
/// Signature: lf | lh | li | ri
impl<H, B> SubkeysList<H, B>
where
    H: Deref<Target = Hive<B>>,
    B: ByteSlice,
{
    pub(crate) fn new(hive: H, cell_range: Range<usize>) -> Result<Self> {
        Self::new_internal(hive, cell_range, true)
    }

    pub(crate) fn new_without_index_root(hive: H, cell_range: Range<usize>) -> Result<Self> {
        // This function only exists to share validation code with `IndexRootInnerIter`.
        Self::new_internal(hive, cell_range, false)
    }

    fn new_internal(hive: H, cell_range: Range<usize>, index_root_supported: bool) -> Result<Self> {
        let header_range = bytes_subrange(&cell_range, mem::size_of::<SubkeysListHeader>())
            .ok_or_else(|| NtHiveError::InvalidHeaderSize {
                offset: hive.offset_of_data_offset(cell_range.start),
                expected: mem::size_of::<SubkeysListHeader>(),
                actual: cell_range.len(),
            })?;
        let data_range = header_range.end..cell_range.end;

        let subkeys_list = Self {
            hive,
            header_range,
            data_range,
        };
        subkeys_list.validate_signature(index_root_supported)?;

        Ok(subkeys_list)
    }

    pub(crate) fn header(&self) -> LayoutVerified<&[u8], SubkeysListHeader> {
        LayoutVerified::new(&self.hive.data[self.header_range.clone()]).unwrap()
    }

    pub fn iter(&self) -> Result<SubkeyIter<B>> {
        let header = self.header();
        let count = header.count.get();
        let count_field_offset = self.hive.offset_of_field(&header.count);

        match &header.signature {
            b"lf" | b"lh" | b"li" => {
                // Fast Leaf, Hash Leaf or Index Leaf
                let leaf_type = LeafType::from_signature(&header.signature).unwrap();
                let iter = LeafIter::new(
                    &self.hive,
                    count,
                    count_field_offset,
                    self.data_range.clone(),
                    leaf_type,
                )?;
                Ok(SubkeyIter::Leaf(iter))
            }
            b"ri" => {
                // Index Root
                let iter = IndexRootIter::new(
                    &self.hive,
                    count,
                    count_field_offset,
                    self.data_range.clone(),
                )?;
                Ok(SubkeyIter::IndexRoot(iter))
            }
            _ => unreachable!(),
        }
    }

    fn validate_signature(&self, index_root_supported: bool) -> Result<()> {
        let header = self.header();

        match &header.signature {
            // Index Leaf / Fast Leaf / Hash Leaf
            b"lf" | b"lh" | b"li" => return Ok(()),

            // Index Root
            b"ri" => {
                if index_root_supported {
                    return Ok(());
                }
            }

            // Anything else
            _ => (),
        }

        let expected_signature: &[u8] = if index_root_supported {
            b"lf|lh|li|ri"
        } else {
            b"lf|lh|li"
        };

        Err(NtHiveError::InvalidTwoByteSignature {
            offset: self.hive.offset_of_field(&header.signature),
            expected: expected_signature,
            actual: header.signature,
        })
    }
}

impl<H, B> SubkeysList<H, B>
where
    H: DerefMut<Target = Hive<B>>,
    B: ByteSliceMut,
{
    pub(crate) fn iter_mut(&mut self) -> Result<SubkeyIterMut<B>> {
        let header = self.header();
        let count = header.count.get();
        let count_field_offset = self.hive.offset_of_field(&header.count);

        match &header.signature {
            b"lf" | b"lh" | b"li" => {
                // Fast Leaf, Hash Leaf or Index Leaf
                let leaf_type = LeafType::from_signature(&header.signature).unwrap();
                let iter = LeafIterMut::new(
                    &mut self.hive,
                    count,
                    count_field_offset,
                    self.data_range.clone(),
                    leaf_type,
                )?;
                Ok(SubkeyIterMut::Leaf(iter))
            }
            b"ri" => {
                // Index Root
                let iter = IndexRootIterMut::new(
                    &mut self.hive,
                    count,
                    count_field_offset,
                    self.data_range.clone(),
                )?;
                Ok(SubkeyIterMut::IndexRoot(iter))
            }
            _ => unreachable!(),
        }
    }
}

/// Iterator for a list of subkeys (common handling)
/// Signature: lf | lh | li | ri
#[derive(Clone)]
pub enum SubkeyIter<'a, B: ByteSlice> {
    IndexRoot(IndexRootIter<'a, B>),
    Leaf(LeafIter<'a, B>),
}

impl<'a, B> Iterator for SubkeyIter<'a, B>
where
    B: ByteSlice,
{
    type Item = Result<KeyNode<&'a Hive<B>, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::IndexRoot(iter) => iter.next(),
            Self::Leaf(iter) => iter.next(),
        }
    }

    fn count(self) -> usize {
        match self {
            Self::IndexRoot(iter) => iter.count(),
            Self::Leaf(iter) => iter.count(),
        }
    }

    fn last(self) -> Option<Self::Item> {
        match self {
            Self::IndexRoot(iter) => iter.last(),
            Self::Leaf(iter) => iter.last(),
        }
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        match self {
            Self::IndexRoot(iter) => iter.nth(n),
            Self::Leaf(iter) => iter.nth(n),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::IndexRoot(iter) => iter.size_hint(),
            Self::Leaf(iter) => iter.size_hint(),
        }
    }
}

impl<'a, B> FusedIterator for SubkeyIter<'a, B> where B: ByteSlice {}

/// Iterator for a list of mutable subkeys (common handling)
/// Signature: lf | lh | li | ri
pub(crate) enum SubkeyIterMut<'a, B: ByteSliceMut> {
    IndexRoot(IndexRootIterMut<'a, B>),
    Leaf(LeafIterMut<'a, B>),
}

impl<'a, B> SubkeyIterMut<'a, B>
where
    B: ByteSliceMut,
{
    pub fn next(&mut self) -> Option<Result<KeyNode<&mut Hive<B>, B>>> {
        match self {
            Self::IndexRoot(iter) => iter.next(),
            Self::Leaf(iter) => iter.next(),
        }
    }
}
