// Copyright 2019-2020 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

//!
//! Index Roots are supported in all Windows versions.
//!

use crate::error::{NtHiveError, Result};
use crate::fast_leaf::FastLeafElement;
use crate::hash_leaf::HashLeafElement;
use crate::hive::Hive;
use crate::index_leaf::IndexLeafElement;
use crate::key_node::KeyNode;
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
pub struct IndexRootIter<'a, B: ByteSlice> {
    hive: &'a Hive<B>,
    elements_range: Range<usize>,
    inner_info: Option<IndexRootIterInnerInfo>,
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
            inner_info: None,
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
            if let Some(inner_info) = self.inner_info.as_mut() {
                if let Some(key_node_offset) = inner_info.next_key_node_offset(&self.hive) {
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
                iter_try!(SubkeysList::new_without_index_root(self.hive, cell_range));

            let header = subkeys_list.header();
            let data_range = subkeys_list.data_range.clone();
            let signature = header.signature;
            let count = header.count.get();
            let count_field_offset = self.hive.offset_of_field(&header.count);

            let elements_range = match &signature {
                b"lf" => {
                    // Fast Leaf
                    iter_try!(FastLeafElement::elements_range(
                        count,
                        count_field_offset,
                        data_range
                    ))
                }
                b"lh" => {
                    // Hash Leaf
                    iter_try!(HashLeafElement::elements_range(
                        count,
                        count_field_offset,
                        data_range
                    ))
                }
                b"li" => {
                    // Index Leaf
                    iter_try!(IndexLeafElement::elements_range(
                        count,
                        count_field_offset,
                        data_range
                    ))
                }
                _ => unreachable!(),
            };

            self.inner_info = Some(IndexRootIterInnerInfo {
                signature,
                elements_range,
            });
        }
    }
}

impl<'a, B> FusedIterator for IndexRootIter<'a, B> where B: ByteSlice {}

/// Inner "iterator" for Index Root to iterate over the linked Fast Leafs/Hash Leafs/Index Leafs.
///
/// We only use element indexes here and don't encapsulate any of the iterator structs (`FastLeafIter`/`HashLeafIter`/...)
/// This wouldn't work for `IndexRootIterMut`, because iterator structs contain a reference to `Hive`
/// and `IndexRootIterMut` already contains a mutable reference to `Hive`.
struct IndexRootIterInnerInfo {
    signature: [u8; 2],
    elements_range: Range<usize>,
}

impl IndexRootIterInnerInfo {
    fn next_key_node_offset<B>(&mut self, hive: &Hive<B>) -> Option<u32>
    where
        B: ByteSlice,
    {
        match &self.signature {
            b"lf" => FastLeafElement::next_key_node_offset(hive, &mut self.elements_range),
            b"lh" => HashLeafElement::next_key_node_offset(hive, &mut self.elements_range),
            b"li" => IndexLeafElement::next_key_node_offset(hive, &mut self.elements_range),
            _ => unreachable!(),
        }
    }
}

/// Iterator over mutable Index Root Elements.
pub(crate) struct IndexRootIterMut<'a, B: ByteSliceMut> {
    hive: &'a mut Hive<B>,
    elements_range: Range<usize>,
    inner_info: Option<IndexRootIterInnerInfo>,
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
            inner_info: None,
        })
    }

    pub(crate) fn next<'e>(&'e mut self) -> Option<Result<KeyNode<&'e mut Hive<B>, B>>> {
        loop {
            if let Some(inner_info) = self.inner_info.as_mut() {
                if let Some(key_node_offset) = inner_info.next_key_node_offset(&self.hive) {
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
            let data_range = subkeys_list.data_range.clone();
            let signature = header.signature;
            let count = header.count.get();
            let count_field_offset = self.hive.offset_of_field(&header.count);

            let elements_range = match &signature {
                b"lf" => {
                    // Fast Leaf
                    iter_try!(FastLeafElement::elements_range(
                        count,
                        count_field_offset,
                        data_range
                    ))
                }
                b"lh" => {
                    // Hash Leaf
                    iter_try!(HashLeafElement::elements_range(
                        count,
                        count_field_offset,
                        data_range
                    ))
                }
                b"li" => {
                    // Index Leaf
                    iter_try!(IndexLeafElement::elements_range(
                        count,
                        count_field_offset,
                        data_range
                    ))
                }
                _ => unreachable!(),
            };

            self.inner_info = Some(IndexRootIterInnerInfo {
                signature,
                elements_range,
            });
        }
    }
}
