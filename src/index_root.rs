// Copyright 2019-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::byte_subrange;
use crate::hive::Hive;
use crate::key_node::KeyNode;
use crate::leaf::LeafItemRanges;
use ::byteorder::LittleEndian;
use core::iter::FusedIterator;
use core::mem;
use core::ops::{Deref, Range};
use zerocopy::*;

/// On-Disk Structure of a single Index Root item.
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct IndexRootItem {
    subkeys_list_offset: U32<LittleEndian>,
}

/// Byte range of a single Index Root item returned by [`IndexRootItemRanges`].
pub(crate) struct IndexRootItemRange(Range<usize>);

impl IndexRootItemRange {
    pub fn subkeys_list_offset<B>(&self, hive: &Hive<B>) -> u32
    where
        B: ByteSlice,
    {
        let item = LayoutVerified::<&[u8], IndexRootItem>::new(&hive.data[self.0.clone()]).unwrap();
        item.subkeys_list_offset.get()
    }
}

impl Deref for IndexRootItemRange {
    type Target = Range<usize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Iterator over
///   a contiguous range of data bytes containing Index Root items,
///   returning an [`IndexRootItemRange`] for each Index Root item.
///
/// On-Disk Signature: `ri`
#[derive(Clone)]
pub(crate) struct IndexRootItemRanges {
    items_range: Range<usize>,
}

impl IndexRootItemRanges {
    fn new(count: u16, count_field_offset: usize, data_range: Range<usize>) -> Result<Self> {
        let byte_count = count as usize * mem::size_of::<IndexRootItem>();

        let items_range = byte_subrange(&data_range, byte_count).ok_or_else(|| {
            NtHiveError::InvalidSizeField {
                offset: count_field_offset,
                expected: byte_count,
                actual: data_range.len(),
            }
        })?;

        Ok(Self { items_range })
    }
}

impl Iterator for IndexRootItemRanges {
    type Item = IndexRootItemRange;

    fn next(&mut self) -> Option<Self::Item> {
        let item_range = byte_subrange(&self.items_range, mem::size_of::<IndexRootItem>())?;
        self.items_range.start += mem::size_of::<IndexRootItem>();

        Some(IndexRootItemRange(item_range))
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
        let bytes_to_skip = n.checked_mul(mem::size_of::<IndexRootItem>())?;
        self.items_range.start = self.items_range.start.checked_add(bytes_to_skip)?;
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.items_range.len() / mem::size_of::<IndexRootItem>();
        (size, Some(size))
    }
}

impl ExactSizeIterator for IndexRootItemRanges {}
impl FusedIterator for IndexRootItemRanges {}

impl<B: ByteSlice> From<IndexRootKeyNodes<'_, B>> for IndexRootItemRanges {
    fn from(index_root_key_nodes: IndexRootKeyNodes<'_, B>) -> IndexRootItemRanges {
        index_root_key_nodes.index_root_item_ranges
    }
}

/// Iterator over
///   a contiguous range of data bytes containing Index Root items,
///   returning a constant [`KeyNode`] for each Leaf item of each Index Root item,
///   used by [`SubKeyNodes`]
///
/// On-Disk Signature: `ri`
///
/// [`SubKeyNodes`]: crate::subkeys_list::SubKeyNodes
#[derive(Clone)]
pub struct IndexRootKeyNodes<'a, B: ByteSlice> {
    hive: &'a Hive<B>,
    index_root_item_ranges: IndexRootItemRanges,
    leaf_item_ranges: Option<LeafItemRanges>,
}

impl<'a, B> IndexRootKeyNodes<'a, B>
where
    B: ByteSlice,
{
    pub(crate) fn new(
        hive: &'a Hive<B>,
        count: u16,
        count_field_offset: usize,
        data_range: Range<usize>,
    ) -> Result<Self> {
        let index_root_item_ranges =
            IndexRootItemRanges::new(count, count_field_offset, data_range)?;

        Ok(Self {
            hive,
            index_root_item_ranges,
            leaf_item_ranges: None,
        })
    }
}

impl<'a, B> Iterator for IndexRootKeyNodes<'a, B>
where
    B: ByteSlice,
{
    type Item = Result<KeyNode<&'a Hive<B>, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(leaf_item_ranges) = self.leaf_item_ranges.as_mut() {
                if let Some(leaf_item_range) = leaf_item_ranges.next() {
                    let key_node =
                        iter_try!(KeyNode::from_leaf_item_range(self.hive, leaf_item_range));
                    return Some(Ok(key_node));
                }
            }

            // No leaf_item_ranges or the last one has been fully iterated.
            // So get the next Index Root item and build leaf_item_ranges out of that.
            let index_root_item_range = self.index_root_item_ranges.next()?;
            let leaf_item_ranges = iter_try!(LeafItemRanges::from_index_root_item_range(
                self.hive,
                index_root_item_range
            ));
            self.leaf_item_ranges = Some(leaf_item_ranges);
        }
    }
}

impl<'a, B> FusedIterator for IndexRootKeyNodes<'a, B> where B: ByteSlice {}

/// Iterator over
///   a contiguous range of data bytes containing Index Root items,
///   returning a mutable [`KeyNode`] for each Leaf item of each Index Root item,
///   used by [`SubKeyNodesMut`].
///
/// On-Disk Signature: `ri`
///
/// [`SubKeyNodesMut`]: crate::subkeys_list::SubKeyNodesMut
pub(crate) struct IndexRootKeyNodesMut<'a, B: ByteSliceMut> {
    hive: &'a mut Hive<B>,
    index_root_item_ranges: IndexRootItemRanges,
    leaf_item_ranges: Option<LeafItemRanges>,
}

impl<'a, B> IndexRootKeyNodesMut<'a, B>
where
    B: ByteSliceMut,
{
    pub(crate) fn new(
        hive: &'a mut Hive<B>,
        count: u16,
        count_field_offset: usize,
        data_range: Range<usize>,
    ) -> Result<Self> {
        let index_root_item_ranges =
            IndexRootItemRanges::new(count, count_field_offset, data_range)?;

        Ok(Self {
            hive,
            index_root_item_ranges,
            leaf_item_ranges: None,
        })
    }

    pub(crate) fn next(&mut self) -> Option<Result<KeyNode<&mut Hive<B>, B>>> {
        loop {
            if let Some(leaf_item_ranges) = self.leaf_item_ranges.as_mut() {
                if let Some(leaf_item_range) = leaf_item_ranges.next() {
                    let key_node = iter_try!(KeyNode::from_leaf_item_range(
                        &mut *self.hive,
                        leaf_item_range
                    ));
                    return Some(Ok(key_node));
                }
            }

            // No leaf_item_ranges or the last one has been fully iterated.
            // So get the next Index Root item and build leaf_item_ranges out of that.
            let index_root_item_range = self.index_root_item_ranges.next()?;
            let leaf_item_ranges = iter_try!(LeafItemRanges::from_index_root_item_range(
                self.hive,
                index_root_item_range
            ));
            self.leaf_item_ranges = Some(leaf_item_ranges);
        }
    }
}
