// Copyright 2020-2025 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use core::iter::FusedIterator;
use core::mem;
use core::ops::Range;

use zerocopy::byteorder::LittleEndian;
use zerocopy::{
    SplitByteSliceMut, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, SplitByteSlice, Unaligned, U16,
};

use crate::error::{NtHiveError, Result};
use crate::helpers::byte_subrange;
use crate::hive::Hive;
use crate::index_root::{IndexRootKeyNodes, IndexRootKeyNodesMut};
use crate::key_node::{KeyNode, KeyNodeMut};
use crate::leaf::{LeafKeyNodes, LeafKeyNodesMut, LeafType};

/// On-Disk Structure of a Subkeys List header.
/// This is common for all subkey types (Fast Leaf, Hash Leaf, Index Leaf, Index Root).
#[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
#[repr(packed)]
pub(crate) struct SubkeysListHeader {
    pub(crate) signature: [u8; 2],
    pub(crate) count: U16<LittleEndian>,
}

/// Subkeys of a single [`KeyNode`].
///
/// A Subkeys List generalizes over all structures used to manage subkeys.
/// These are: Fast Leaf (`lf`), Hash Leaf (`lh`), Index Leaf (`li`), Index Root (`ri`).
pub(crate) struct SubkeysList<'h, B: SplitByteSlice> {
    hive: &'h Hive<B>,
    header_range: Range<usize>,
    pub(crate) data_range: Range<usize>,
}

impl<'h, B> SubkeysList<'h, B>
where
    B: SplitByteSlice,
{
    pub(crate) fn new(hive: &'h Hive<B>, cell_range: Range<usize>) -> Result<Self> {
        Self::new_internal(hive, cell_range, true)
    }

    pub(crate) fn new_without_index_root(
        hive: &'h Hive<B>,
        cell_range: Range<usize>,
    ) -> Result<Self> {
        // This function only exists to share validation code with `LeafItemRanges`.
        Self::new_internal(hive, cell_range, false)
    }

    fn new_internal(
        hive: &'h Hive<B>,
        cell_range: Range<usize>,
        index_root_supported: bool,
    ) -> Result<Self> {
        let header_range = byte_subrange(&cell_range, mem::size_of::<SubkeysListHeader>())
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

    pub(crate) fn header(&self) -> Ref<&[u8], SubkeysListHeader> {
        Ref::from_bytes(&self.hive.data[self.header_range.clone()]).unwrap()
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

/// Iterator over
///   all subkeys of a [`KeyNode`],
///   returning a constant [`KeyNode`] for each subkey.
///
/// This iterator combines [`IndexRootKeyNodes`] and [`LeafKeyNodes`].
/// Refer to them for a more technical documentation.
///
/// On-Disk Signatures: `lf`, `lh`, `li`, `ri`
#[derive(Clone)]
pub enum SubKeyNodes<'h, B: SplitByteSlice> {
    IndexRoot(IndexRootKeyNodes<'h, B>),
    Leaf(LeafKeyNodes<'h, B>),
}

impl<'h, B> SubKeyNodes<'h, B>
where
    B: SplitByteSlice,
{
    pub(crate) fn new(hive: &'h Hive<B>, cell_range: Range<usize>) -> Result<Self> {
        let subkeys_list = SubkeysList::new(hive, cell_range)?;
        let header = subkeys_list.header();
        let signature = header.signature;
        let count = header.count.get();
        let count_field_offset = subkeys_list.hive.offset_of_field(&header.count);
        let data_range = subkeys_list.data_range;

        match &signature {
            b"lf" | b"lh" | b"li" => {
                // Fast Leaf, Hash Leaf or Index Leaf
                let leaf_type = LeafType::from_signature(&signature).unwrap();
                let iter =
                    LeafKeyNodes::new(hive, count, count_field_offset, data_range, leaf_type)?;
                Ok(Self::Leaf(iter))
            }
            b"ri" => {
                // Index Root
                let iter = IndexRootKeyNodes::new(hive, count, count_field_offset, data_range)?;
                Ok(Self::IndexRoot(iter))
            }
            _ => unreachable!(),
        }
    }
}

impl<'h, B> Iterator for SubKeyNodes<'h, B>
where
    B: SplitByteSlice,
{
    type Item = Result<KeyNode<'h, B>>;

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

impl<'h, B> FusedIterator for SubKeyNodes<'h, B> where B: SplitByteSlice {}

/// Iterator over
///   all subkeys of a [`KeyNode`],
///   returning a mutable [`KeyNode`] for each subkey.
///
/// This iterator combines [`IndexRootKeyNodesMut`] and [`LeafKeyNodesMut`].
/// Refer to them for a more technical documentation.
///
/// On-Disk Signatures: `lf`, `lh`, `li`, `ri`
pub(crate) enum SubKeyNodesMut<'h, B: SplitByteSliceMut> {
    IndexRoot(IndexRootKeyNodesMut<'h, B>),
    Leaf(LeafKeyNodesMut<'h, B>),
}

impl<'h, B> SubKeyNodesMut<'h, B>
where
    B: SplitByteSliceMut,
{
    pub(crate) fn new(hive: &'h mut Hive<B>, cell_range: Range<usize>) -> Result<Self> {
        let subkeys_list = SubkeysList::new(&*hive, cell_range)?;
        let header = subkeys_list.header();
        let signature = header.signature;
        let count = header.count.get();
        let count_field_offset = subkeys_list.hive.offset_of_field(&header.count);
        let data_range = subkeys_list.data_range;

        match &signature {
            b"lf" | b"lh" | b"li" => {
                // Fast Leaf, Hash Leaf or Index Leaf
                let leaf_type = LeafType::from_signature(&signature).unwrap();
                let iter =
                    LeafKeyNodesMut::new(hive, count, count_field_offset, data_range, leaf_type)?;
                Ok(Self::Leaf(iter))
            }
            b"ri" => {
                // Index Root
                let iter = IndexRootKeyNodesMut::new(hive, count, count_field_offset, data_range)?;
                Ok(Self::IndexRoot(iter))
            }
            _ => unreachable!(),
        }
    }

    pub fn next(&mut self) -> Option<Result<KeyNodeMut<B>>> {
        match self {
            Self::IndexRoot(iter) => iter.next(),
            Self::Leaf(iter) => iter.next(),
        }
    }
}
