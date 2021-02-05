// Copyright 2019-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::bytes_subrange;
use crate::hive::Hive;
use crate::key_node::KeyNode;
use crate::leaf::LeafElementRangeIter;
use ::byteorder::LittleEndian;
use core::iter::FusedIterator;
use core::mem;
use core::ops::{Deref, Range};
use zerocopy::*;

/// On-Disk Structure of an Index Root element.
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct IndexRootElement {
    subkeys_list_offset: U32<LittleEndian>,
}

/// A typed range of bytes returned by [`IndexRootElementRangeIter`].
pub(crate) struct IndexRootElementRange(Range<usize>);

impl IndexRootElementRange {
    pub fn subkeys_list_offset<B>(&self, hive: &Hive<B>) -> u32
    where
        B: ByteSlice,
    {
        let element =
            LayoutVerified::<&[u8], IndexRootElement>::new(&hive.data[self.0.clone()]).unwrap();
        element.subkeys_list_offset.get()
    }
}

impl Deref for IndexRootElementRange {
    type Target = Range<usize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Iterator over
///   a contiguous data range containing Index Root elements,
///   returning an [`IndexRootElementRange`] for each Index Root element.
///
/// On-Disk Signature: `ri`
#[derive(Clone)]
pub(crate) struct IndexRootElementRangeIter {
    elements_range: Range<usize>,
}

impl IndexRootElementRangeIter {
    pub(crate) fn new(
        count: u16,
        count_field_offset: usize,
        data_range: Range<usize>,
    ) -> Result<Self> {
        let bytes_count = count as usize * mem::size_of::<IndexRootElement>();

        let elements_range = bytes_subrange(&data_range, bytes_count).ok_or_else(|| {
            NtHiveError::InvalidSizeField {
                offset: count_field_offset,
                expected: bytes_count,
                actual: data_range.len(),
            }
        })?;

        Ok(Self { elements_range })
    }
}

impl Iterator for IndexRootElementRangeIter {
    type Item = IndexRootElementRange;

    fn next(&mut self) -> Option<Self::Item> {
        let element_range =
            bytes_subrange(&self.elements_range, mem::size_of::<IndexRootElement>())?;
        self.elements_range.start += mem::size_of::<IndexRootElement>();

        Some(IndexRootElementRange(element_range))
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
        let bytes_to_skip = n.checked_mul(mem::size_of::<IndexRootElement>())?;
        self.elements_range.start = self.elements_range.start.checked_add(bytes_to_skip)?;
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.elements_range.len() / mem::size_of::<IndexRootElement>();
        (size, Some(size))
    }
}

impl ExactSizeIterator for IndexRootElementRangeIter {}
impl FusedIterator for IndexRootElementRangeIter {}

/// Iterator over
///   a contiguous data range containing Index Root elements,
///   returning a constant [`KeyNode`] for each Leaf element of each Index Root element.
///
/// On-Disk Signature: `ri`
#[derive(Clone)]
pub struct IndexRootIter<'a, B: ByteSlice> {
    hive: &'a Hive<B>,
    pub(crate) index_root_element_range_iter: IndexRootElementRangeIter,
    leaf_element_range_iter: Option<LeafElementRangeIter>,
}

impl<'a, B> IndexRootIter<'a, B>
where
    B: ByteSlice,
{
    pub(crate) fn new(
        hive: &'a Hive<B>,
        count: u16,
        count_field_offset: usize,
        data_range: Range<usize>,
    ) -> Result<Self> {
        let index_root_element_range_iter =
            IndexRootElementRangeIter::new(count, count_field_offset, data_range)?;

        Ok(Self {
            hive,
            index_root_element_range_iter,
            leaf_element_range_iter: None,
        })
    }
}

impl<'a, B> Iterator for IndexRootIter<'a, B>
where
    B: ByteSlice,
{
    type Item = Result<KeyNode<&'a Hive<B>, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(leaf_iter) = self.leaf_element_range_iter.as_mut() {
                if let Some(leaf_element_range) = leaf_iter.next() {
                    let key_node = iter_try!(KeyNode::from_leaf_element_range(
                        self.hive,
                        leaf_element_range
                    ));
                    return Some(Ok(key_node));
                }
            }

            // No leaf_iter or the last one has been fully iterated.
            // So get the next Index Root element and build a leaf_iter out of that.
            let index_root_element_range = self.index_root_element_range_iter.next()?;
            let leaf_iter = iter_try!(LeafElementRangeIter::from_index_root_element_range(
                self.hive,
                index_root_element_range
            ));
            self.leaf_element_range_iter = Some(leaf_iter);
        }
    }
}

impl<'a, B> FusedIterator for IndexRootIter<'a, B> where B: ByteSlice {}

/// Iterator over
///   a contiguous data range containing Index Root elements,
///   returning a mutable [`KeyNode`] for each Leaf element of each Index Root element.
///
/// On-Disk Signature: `ri`
pub(crate) struct IndexRootIterMut<'a, B: ByteSliceMut> {
    hive: &'a mut Hive<B>,
    index_root_element_range_iter: IndexRootElementRangeIter,
    leaf_element_range_iter: Option<LeafElementRangeIter>,
}

impl<'a, B> IndexRootIterMut<'a, B>
where
    B: ByteSliceMut,
{
    pub(crate) fn new(
        hive: &'a mut Hive<B>,
        count: u16,
        count_field_offset: usize,
        data_range: Range<usize>,
    ) -> Result<Self> {
        let index_root_element_range_iter =
            IndexRootElementRangeIter::new(count, count_field_offset, data_range)?;

        Ok(Self {
            hive,
            index_root_element_range_iter,
            leaf_element_range_iter: None,
        })
    }

    pub(crate) fn next<'e>(&'e mut self) -> Option<Result<KeyNode<&'e mut Hive<B>, B>>> {
        loop {
            if let Some(leaf_iter) = self.leaf_element_range_iter.as_mut() {
                if let Some(leaf_element_range) = leaf_iter.next() {
                    let key_node = iter_try!(KeyNode::from_leaf_element_range(
                        &mut *self.hive,
                        leaf_element_range
                    ));
                    return Some(Ok(key_node));
                }
            }

            // No leaf_iter or the last one has been fully iterated.
            // So get the next Index Root element and build a leaf_iter out of that.
            let index_root_element_range = self.index_root_element_range_iter.next()?;
            let leaf_iter = iter_try!(LeafElementRangeIter::from_index_root_element_range(
                self.hive,
                index_root_element_range
            ));
            self.leaf_element_range_iter = Some(leaf_iter);
        }
    }
}
