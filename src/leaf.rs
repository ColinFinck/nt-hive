// Copyright 2020-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::bytes_subrange;
use crate::hive::Hive;
use crate::key_node::KeyNode;
use ::byteorder::LittleEndian;
use core::iter::FusedIterator;
use core::mem;
use core::ops::Range;
use zerocopy::*;

/// On-Disk Structure of a Fast Leaf Element.
/// They are supported since Windows NT 4.
#[allow(dead_code)]
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct FastLeafElement {
    key_node_offset: U32<LittleEndian>,
    name_hint: [u8; 4],
}

/// On-Disk Structure of a Hash Leaf Element.
/// They are supported since Windows XP.
#[allow(dead_code)]
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct HashLeafElement {
    key_node_offset: U32<LittleEndian>,
    name_hash: [u8; 4],
}

/// On-Disk Structure of an Index Leaf Element.
/// They are supported in all Windows versions.
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct IndexLeafElement {
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

    fn element_size(&self) -> usize {
        match self {
            Self::Fast => mem::size_of::<FastLeafElement>(),
            Self::Hash => mem::size_of::<HashLeafElement>(),
            Self::Index => mem::size_of::<IndexLeafElement>(),
        }
    }
}

/// Iterator over Leaf elements returning the offset of each.
#[derive(Clone)]
pub(crate) struct LeafElementOffsetIter {
    elements_range: Range<usize>,
    leaf_type: LeafType,
}

impl LeafElementOffsetIter {
    pub(crate) fn new(
        count: u16,
        count_field_offset: usize,
        data_range: Range<usize>,
        leaf_type: LeafType,
    ) -> Result<Self> {
        let bytes_count = count as usize * leaf_type.element_size();

        let elements_range = bytes_subrange(&data_range, bytes_count).ok_or_else(|| {
            NtHiveError::InvalidSizeField {
                offset: count_field_offset,
                expected: bytes_count,
                actual: data_range.len(),
            }
        })?;

        Ok(Self {
            elements_range,
            leaf_type,
        })
    }
}

impl Iterator for LeafElementOffsetIter {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let element_size = self.leaf_type.element_size();
        let element_range = bytes_subrange(&self.elements_range, element_size)?;
        self.elements_range.start += element_size;

        Some(element_range.start)
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
        let bytes_to_skip = n.checked_mul(self.leaf_type.element_size())?;
        self.elements_range.start = self.elements_range.start.checked_add(bytes_to_skip)?;
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.elements_range.len() / self.leaf_type.element_size();
        (size, Some(size))
    }
}

impl ExactSizeIterator for LeafElementOffsetIter {}
impl FusedIterator for LeafElementOffsetIter {}

pub(crate) fn key_node_offset_from_leaf_element_offset<B>(
    hive: &Hive<B>,
    leaf_element_offset: usize,
) -> u32
where
    B: ByteSlice,
{
    // We use the fact here that a `FastLeafElement` or `HashLeafElement` is just an
    // `IndexLeafElement` with additional fields.
    // As they all have the `key_node_offset` as the first field, treat them equally.
    let index_leaf_element_range =
        leaf_element_offset..leaf_element_offset + mem::size_of::<IndexLeafElement>();
    let index_leaf_element =
        LayoutVerified::<&[u8], IndexLeafElement>::new(&hive.data[index_leaf_element_range])
            .unwrap();
    index_leaf_element.key_node_offset.get()
}

/// Iterator over Leaf elements returning constant `KeyNode`s.
#[derive(Clone)]
pub struct LeafIter<'a, B: ByteSlice> {
    hive: &'a Hive<B>,
    inner_iter: LeafElementOffsetIter,
}

impl<'a, B> LeafIter<'a, B>
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
        let inner_iter =
            LeafElementOffsetIter::new(count, count_field_offset, data_range, leaf_type)?;
        Ok(Self { hive, inner_iter })
    }
}

impl<'a, B> Iterator for LeafIter<'a, B>
where
    B: ByteSlice,
{
    type Item = Result<KeyNode<&'a Hive<B>, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        let leaf_element_offset = self.inner_iter.next()?;
        let key_node_offset =
            key_node_offset_from_leaf_element_offset(&self.hive, leaf_element_offset);
        let cell_range = iter_try!(self.hive.cell_range_from_data_offset(key_node_offset));
        let key_node = iter_try!(KeyNode::new(self.hive, cell_range));
        Some(Ok(key_node))
    }

    fn count(self) -> usize {
        self.inner_iter.count()
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
        let bytes_to_skip = n.checked_mul(self.inner_iter.leaf_type.element_size())?;
        self.inner_iter.elements_range.start = self
            .inner_iter
            .elements_range
            .start
            .checked_add(bytes_to_skip)?;
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner_iter.size_hint()
    }
}

impl<'a, B> ExactSizeIterator for LeafIter<'a, B> where B: ByteSlice {}
impl<'a, B> FusedIterator for LeafIter<'a, B> where B: ByteSlice {}

/// Iterator over Leaf elements returning mutable `KeyNode`s.
pub struct LeafIterMut<'a, B: ByteSliceMut> {
    hive: &'a mut Hive<B>,
    inner_iter: LeafElementOffsetIter,
}

impl<'a, B> LeafIterMut<'a, B>
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
        let inner_iter =
            LeafElementOffsetIter::new(count, count_field_offset, data_range, leaf_type)?;
        Ok(Self { hive, inner_iter })
    }

    pub(crate) fn next<'e>(&'e mut self) -> Option<Result<KeyNode<&'e mut Hive<B>, B>>> {
        let leaf_element_offset = self.inner_iter.next()?;
        let key_node_offset =
            key_node_offset_from_leaf_element_offset(&self.hive, leaf_element_offset);
        let cell_range = iter_try!(self.hive.cell_range_from_data_offset(key_node_offset));
        let key_node = iter_try!(KeyNode::new(&mut *self.hive, cell_range));
        Some(Ok(key_node))
    }
}
