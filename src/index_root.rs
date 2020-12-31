// Copyright 2019-2020 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

//!
//! Index Roots are supported in all Windows versions.
//!

use crate::error::{NtHiveError, Result};
use crate::hive::Hive;
use crate::key_node::KeyNode;
use crate::leaf::{key_node_offset_from_leaf_element_offset, LeafElementOffsetIter, LeafType};
use crate::subkeys_list::SubkeysList;
use ::byteorder::LittleEndian;
use core::iter::FusedIterator;
use core::mem;
use core::ops::Range;
use zerocopy::*;

/// On-Disk Structure of an Index Root Element.
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct IndexRootElement {
    subkeys_list_offset: U32<LittleEndian>,
}

impl IndexRootElement {
    fn elements_range(
        count: u16,
        count_field_offset: usize,
        data_range: Range<usize>,
    ) -> Result<Range<usize>> {
        let count = count as usize;
        let elements_range = data_range.start..data_range.start + count * mem::size_of::<Self>();

        if elements_range.end > data_range.end {
            return Err(NtHiveError::InvalidSizeField {
                offset: count_field_offset,
                expected: elements_range.len(),
                actual: data_range.len(),
            });
        }

        Ok(elements_range)
    }

    fn next_element_range(elements_range: &mut Range<usize>) -> Option<Range<usize>> {
        let element_range = elements_range.start..elements_range.start + mem::size_of::<Self>();
        if element_range.end > elements_range.end {
            return None;
        }

        elements_range.start += mem::size_of::<Self>();

        Some(element_range)
    }
}

/// Iterator over Index Root Elements.
#[derive(Clone)]
pub struct IndexRootIter<'a, B: ByteSlice> {
    hive: &'a Hive<B>,
    elements_range: Range<usize>,
    inner_iter: Option<LeafElementOffsetIter>,
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
        let elements_range =
            IndexRootElement::elements_range(count, count_field_offset, data_range)?;

        Ok(Self {
            hive,
            elements_range,
            inner_iter: None,
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
            if let Some(inner_iter) = self.inner_iter.as_mut() {
                if let Some(leaf_element_offset) = inner_iter.next() {
                    let key_node_offset =
                        key_node_offset_from_leaf_element_offset(&self.hive, leaf_element_offset);
                    let cell_range =
                        iter_try!(self.hive.cell_range_from_data_offset(key_node_offset));
                    let key_node = iter_try!(KeyNode::new(self.hive, cell_range));
                    return Some(Ok(key_node));
                }
            }

            // No inner iterator or the last inner iterator has been fully iterated.
            // So get the next inner iterator.
            let element_range = IndexRootElement::next_element_range(&mut self.elements_range)?;
            let element =
                LayoutVerified::<&[u8], IndexRootElement>::new(&self.hive.data[element_range])
                    .unwrap();

            let subkeys_list_offset = element.subkeys_list_offset.get();
            let cell_range = iter_try!(self.hive.cell_range_from_data_offset(subkeys_list_offset));
            let subkeys_list =
                iter_try!(SubkeysList::new_without_index_root(&*self.hive, cell_range));

            let header = subkeys_list.header();
            let leaf_type = LeafType::from_signature(&header.signature).unwrap();
            let inner_iter = iter_try!(LeafElementOffsetIter::new(
                header.count.get(),
                self.hive.offset_of_field(&header.count),
                subkeys_list.data_range,
                leaf_type
            ));
            self.inner_iter = Some(inner_iter);
        }
    }
}

impl<'a, B> FusedIterator for IndexRootIter<'a, B> where B: ByteSlice {}

/// Iterator over mutable Index Root Elements.
pub(crate) struct IndexRootIterMut<'a, B: ByteSliceMut> {
    hive: &'a mut Hive<B>,
    elements_range: Range<usize>,
    inner_iter: Option<LeafElementOffsetIter>,
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
        let elements_range =
            IndexRootElement::elements_range(count, count_field_offset, data_range)?;

        Ok(Self {
            hive,
            elements_range,
            inner_iter: None,
        })
    }

    pub(crate) fn next<'e>(&'e mut self) -> Option<Result<KeyNode<&'e mut Hive<B>, B>>> {
        loop {
            if let Some(inner_iter) = self.inner_iter.as_mut() {
                if let Some(leaf_element_offset) = inner_iter.next() {
                    let key_node_offset =
                        key_node_offset_from_leaf_element_offset(&self.hive, leaf_element_offset);
                    let cell_range =
                        iter_try!(self.hive.cell_range_from_data_offset(key_node_offset));
                    let key_node = iter_try!(KeyNode::new(&mut *self.hive, cell_range));
                    return Some(Ok(key_node));
                }
            }

            // No inner iterator or the last inner iterator has been fully iterated.
            // So get the next inner iterator.
            let element_range = IndexRootElement::next_element_range(&mut self.elements_range)?;
            let element =
                LayoutVerified::<&[u8], IndexRootElement>::new(&self.hive.data[element_range])
                    .unwrap();

            let subkeys_list_offset = element.subkeys_list_offset.get();
            let cell_range = iter_try!(self.hive.cell_range_from_data_offset(subkeys_list_offset));
            let subkeys_list =
                iter_try!(SubkeysList::new_without_index_root(&*self.hive, cell_range));

            let header = subkeys_list.header();
            let leaf_type = LeafType::from_signature(&header.signature).unwrap();
            let inner_iter = iter_try!(LeafElementOffsetIter::new(
                header.count.get(),
                self.hive.offset_of_field(&header.count),
                subkeys_list.data_range,
                leaf_type
            ));
            self.inner_iter = Some(inner_iter);
        }
    }
}
