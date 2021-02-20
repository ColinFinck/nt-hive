// Copyright 2020-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::byte_subrange;
use crate::hive::Hive;
use crate::index_root::IndexRootItemRange;
use crate::key_node::KeyNode;
use crate::subkeys_list::SubkeysList;
use ::byteorder::LittleEndian;
use core::iter::FusedIterator;
use core::mem;
use core::ops::{Deref, Range};
use zerocopy::*;

/// On-Disk Structure of a Fast Leaf item (On-Disk Signature: `lf`).
/// They are supported since Windows NT 4.
#[allow(dead_code)]
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct FastLeafItem {
    key_node_offset: U32<LittleEndian>,
    name_hint: [u8; 4],
}

/// On-Disk Structure of a Hash Leaf item (On-Disk Signature: `lh`).
/// They are supported since Windows XP.
#[allow(dead_code)]
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct HashLeafItem {
    key_node_offset: U32<LittleEndian>,
    name_hash: [u8; 4],
}

/// On-Disk Structure of an Index Leaf item (On-Disk Signature: `li`).
/// They are supported in all Windows versions.
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct IndexLeafItem {
    key_node_offset: U32<LittleEndian>,
}

/// All known and supported Leaf types.
///
/// We first had only Index Leafs, then got Fast Leafs with Windows NT 4 which add a
/// `name_hint` (first 4 characters of the key name), and finally got Hash Leafs with
/// Windows XP which come with a `name_hash` (simple hash of the entire key name)
/// instead.
/// Both Fast Leafs and Hash Leafs were introduced to speed up key lookups.
/// However, their performance benefits are marginal to non-existing in 2020
/// when we assume that the entire registry hive is randomly accessible.
/// Therefore, the nt-hive crate treats all types equally by only accessing the
/// `key_node_offset` field and ignoring all other fields.
#[derive(Clone, Copy)]
pub(crate) enum LeafType {
    Fast,
    Hash,
    Index,
}

impl LeafType {
    pub(crate) fn from_signature(signature: &[u8]) -> Option<Self> {
        match signature {
            b"lf" => Some(Self::Fast),
            b"lh" => Some(Self::Hash),
            b"li" => Some(Self::Index),
            _ => None,
        }
    }

    fn item_size(&self) -> usize {
        match self {
            Self::Fast => mem::size_of::<FastLeafItem>(),
            Self::Hash => mem::size_of::<HashLeafItem>(),
            Self::Index => mem::size_of::<IndexLeafItem>(),
        }
    }
}

/// Byte range of a single Leaf item returned by [`LeafItemRanges`].
pub(crate) struct LeafItemRange(Range<usize>);

impl LeafItemRange {
    pub fn key_node_offset<B>(&self, hive: &Hive<B>) -> u32
    where
        B: ByteSlice,
    {
        // We make use of the fact that a `FastLeafItem` or `HashLeafItem` is just an
        // `IndexLeafItem` with additional fields.
        // As they all have the `key_node_offset` as their first field, treat them equally.
        let (index_leaf_item, _) =
            LayoutVerified::<&[u8], IndexLeafItem>::new_from_prefix(&hive.data[self.0.clone()])
                .unwrap();
        index_leaf_item.key_node_offset.get()
    }
}

impl Deref for LeafItemRange {
    type Target = Range<usize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Iterator over
///   a contiguous range of data bytes containing Leaf items of any type (Fast/Hash/Index),
///   returning a [`LeafItemRange`] for each Leaf item.
///
/// On-Disk Signatures: `lf`, `lh`, `li`
#[derive(Clone)]
pub(crate) struct LeafItemRanges {
    items_range: Range<usize>,
    leaf_type: LeafType,
}

impl LeafItemRanges {
    pub fn new(
        count: u16,
        count_field_offset: usize,
        data_range: Range<usize>,
        leaf_type: LeafType,
    ) -> Result<Self> {
        let byte_count = count as usize * leaf_type.item_size();

        let items_range = byte_subrange(&data_range, byte_count).ok_or_else(|| {
            NtHiveError::InvalidSizeField {
                offset: count_field_offset,
                expected: byte_count,
                actual: data_range.len(),
            }
        })?;

        Ok(Self {
            items_range,
            leaf_type,
        })
    }

    pub fn from_index_root_item_range<B>(
        hive: &Hive<B>,
        index_root_item_range: IndexRootItemRange,
    ) -> Result<Self>
    where
        B: ByteSlice,
    {
        let subkeys_list_offset = index_root_item_range.subkeys_list_offset(hive);
        let cell_range = hive.cell_range_from_data_offset(subkeys_list_offset)?;
        let subkeys_list = SubkeysList::new_without_index_root(hive, cell_range)?;

        let header = subkeys_list.header();
        let count = header.count.get();
        let count_field_offset = hive.offset_of_field(&header.count);

        // Subkeys Lists belonging to Index Root items need to contain at least 1 item.
        // Otherwise, we can't perform efficient binary search on them, which is the sole reason
        // Index Roots exist.
        if count == 0 {
            return Err(NtHiveError::InvalidSizeField {
                offset: count_field_offset,
                expected: 1,
                actual: 0,
            });
        }

        let leaf_type = LeafType::from_signature(&header.signature).unwrap();
        LeafItemRanges::new(
            count,
            count_field_offset,
            subkeys_list.data_range,
            leaf_type,
        )
    }
}

impl Iterator for LeafItemRanges {
    type Item = LeafItemRange;

    fn next(&mut self) -> Option<Self::Item> {
        let item_size = self.leaf_type.item_size();
        let item_range = byte_subrange(&self.items_range, item_size)?;
        self.items_range.start += item_size;

        Some(LeafItemRange(item_range))
    }

    fn count(self) -> usize {
        let (size, _) = self.size_hint();
        size
    }

    fn last(mut self) -> Option<Self::Item> {
        let (size, _) = self.size_hint();
        if size == 0 {
            return None;
        }

        self.nth(size - 1)
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        // `n` is arbitrary and usize, so we may hit boundaries here. Check that!
        let bytes_to_skip = n.checked_mul(self.leaf_type.item_size())?;
        self.items_range.start = self.items_range.start.checked_add(bytes_to_skip)?;
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.items_range.len() / self.leaf_type.item_size();
        (size, Some(size))
    }
}

impl<B: ByteSlice> From<LeafKeyNodes<'_, B>> for LeafItemRanges {
    fn from(leaf_key_nodes: LeafKeyNodes<'_, B>) -> LeafItemRanges {
        leaf_key_nodes.leaf_item_ranges
    }
}

impl ExactSizeIterator for LeafItemRanges {}
impl FusedIterator for LeafItemRanges {}

/// Iterator over
///   a contiguous range of data bytes containing Leaf items of any type (Fast/Hash/Index),
///   returning a constant [`KeyNode`] for each Leaf item,
///   used by [`SubKeyNodes`].
///
/// On-Disk Signatures: `lf`, `lh`, `li`
///
/// [`SubKeyNodes`]: crate::subkeys_list::SubKeyNodes
#[derive(Clone)]
pub struct LeafKeyNodes<'a, B: ByteSlice> {
    hive: &'a Hive<B>,
    leaf_item_ranges: LeafItemRanges,
}

impl<'a, B> LeafKeyNodes<'a, B>
where
    B: ByteSlice,
{
    pub(crate) fn new(
        hive: &'a Hive<B>,
        count: u16,
        count_field_offset: usize,
        data_range: Range<usize>,
        leaf_type: LeafType,
    ) -> Result<Self> {
        let leaf_item_ranges =
            LeafItemRanges::new(count, count_field_offset, data_range, leaf_type)?;

        Ok(Self {
            hive,
            leaf_item_ranges,
        })
    }
}

impl<'a, B> Iterator for LeafKeyNodes<'a, B>
where
    B: ByteSlice,
{
    type Item = Result<KeyNode<&'a Hive<B>, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        let leaf_item_range = self.leaf_item_ranges.next()?;
        let key_node = iter_try!(KeyNode::from_leaf_item_range(self.hive, leaf_item_range));
        Some(Ok(key_node))
    }

    fn count(self) -> usize {
        self.leaf_item_ranges.count()
    }

    fn last(mut self) -> Option<Self::Item> {
        let (size, _) = self.size_hint();
        if size == 0 {
            return None;
        }

        self.nth(size - 1)
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        // `n` is arbitrary and usize, so we may hit boundaries here. Check that!
        let bytes_to_skip = n.checked_mul(self.leaf_item_ranges.leaf_type.item_size())?;
        self.leaf_item_ranges.items_range.start = self
            .leaf_item_ranges
            .items_range
            .start
            .checked_add(bytes_to_skip)?;
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.leaf_item_ranges.size_hint()
    }
}

impl<'a, B> ExactSizeIterator for LeafKeyNodes<'a, B> where B: ByteSlice {}
impl<'a, B> FusedIterator for LeafKeyNodes<'a, B> where B: ByteSlice {}

/// Iterator over
///   a contiguous range of data bytes containing Leaf items of any type (Fast/Hash/Index),
///   returning a mutable [`KeyNode`] for each Leaf item,
///   used by [`SubKeyNodesMut`].
///
/// On-Disk Signatures: `lf`, `lh`, `li`
///
/// [`SubKeyNodesMut`]: crate::subkeys_list::SubKeyNodesMut
pub(crate) struct LeafKeyNodesMut<'a, B: ByteSliceMut> {
    hive: &'a mut Hive<B>,
    leaf_item_ranges: LeafItemRanges,
}

impl<'a, B> LeafKeyNodesMut<'a, B>
where
    B: ByteSliceMut,
{
    pub(crate) fn new(
        hive: &'a mut Hive<B>,
        count: u16,
        count_field_offset: usize,
        data_range: Range<usize>,
        leaf_type: LeafType,
    ) -> Result<Self> {
        let leaf_item_ranges =
            LeafItemRanges::new(count, count_field_offset, data_range, leaf_type)?;

        Ok(Self {
            hive,
            leaf_item_ranges,
        })
    }

    pub(crate) fn next(&mut self) -> Option<Result<KeyNode<&mut Hive<B>, B>>> {
        let leaf_item_range = self.leaf_item_ranges.next()?;
        let key_node = iter_try!(KeyNode::from_leaf_item_range(
            &mut *self.hive,
            leaf_item_range
        ));
        Some(Ok(key_node))
    }
}
