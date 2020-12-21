// Copyright 2019-2020 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

//!
//! Index Roots are supported in all Windows versions.
//!

use crate::error::{NtHiveError, Result};
use crate::fast_leaf::{FastLeafElement, FastLeafIter};
use crate::hash_leaf::{HashLeafElement, HashLeafIter};
use crate::hive::Hive;
use crate::index_leaf::{IndexLeafElement, IndexLeafIter};
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
    inner_iter: Option<IndexRootInnerIter<'a, B>>,
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
            if let Some(iter) = &mut self.inner_iter {
                // Retrieve the next element from the inner iterator.
                let item = iter.next();
                if item.is_some() {
                    return item;
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
            let count = header.count.get();
            let count_field_offset = self.hive.offset_of_field(&header.count);
            self.inner_iter = match &header.signature {
                b"lf" => {
                    // Fast Leaf
                    let iter = iter_try!(FastLeafIter::new(
                        &self.hive,
                        count,
                        count_field_offset,
                        subkeys_list.data_range
                    ));
                    Some(IndexRootInnerIter::FastLeaf(iter))
                }
                b"lh" => {
                    // Hash Leaf
                    let iter = iter_try!(HashLeafIter::new(
                        &self.hive,
                        count,
                        count_field_offset,
                        subkeys_list.data_range
                    ));
                    Some(IndexRootInnerIter::HashLeaf(iter))
                }
                b"li" => {
                    // Index Leaf
                    let iter = iter_try!(IndexLeafIter::new(
                        &self.hive,
                        count,
                        count_field_offset,
                        subkeys_list.data_range
                    ));
                    Some(IndexRootInnerIter::IndexLeaf(iter))
                }
                _ => unreachable!(),
            };
        }
    }
}

impl<'a, B> FusedIterator for IndexRootIter<'a, B> where B: ByteSlice {}

/// Inner iterator for a list of subkeys of an Index Root (common handling)
/// Signature: li | lf | lh
#[allow(clippy::enum_variant_names)]
enum IndexRootInnerIter<'a, B: ByteSlice> {
    FastLeaf(FastLeafIter<'a, B>),
    HashLeaf(HashLeafIter<'a, B>),
    IndexLeaf(IndexLeafIter<'a, B>),
}

impl<'a, B> Iterator for IndexRootInnerIter<'a, B>
where
    B: ByteSlice,
{
    type Item = Result<KeyNode<&'a Hive<B>, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::FastLeaf(iter) => iter.next(),
            Self::HashLeaf(iter) => iter.next(),
            Self::IndexLeaf(iter) => iter.next(),
        }
    }
}

/// Iterator over mutable Index Root Elements.
pub(crate) struct IndexRootIterMut<'a, B: ByteSliceMut> {
    hive: &'a mut Hive<B>,
    elements_range: Range<usize>,
    inner_info: Option<IndexRootIterMutInnerInfo>,
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

    fn next_inner_key_node_offset(&mut self) -> Option<u32> {
        // Retrieve the next element from the inner iterator.
        let info = self.inner_info.as_mut()?;

        match &info.signature {
            b"lf" => FastLeafElement::next_key_node_offset(&self.hive, &mut info.elements_range),
            b"lh" => HashLeafElement::next_key_node_offset(&self.hive, &mut info.elements_range),
            b"li" => IndexLeafElement::next_key_node_offset(&self.hive, &mut info.elements_range),
            _ => unreachable!(),
        }
    }

    pub(crate) fn next<'e>(&'e mut self) -> Option<Result<KeyNode<&'e mut Hive<B>, B>>> {
        // Due to lifetimes and the borrow checker, the implementation of IndexRootIterMut
        // is fundamentally different to IndexRootIter.
        // This may be revisited when GATs have landed.
        loop {
            if let Some(key_node_offset) = self.next_inner_key_node_offset() {
                let cell_range = iter_try!(self.hive.cell_range_from_data_offset(key_node_offset));
                let key_node = iter_try!(KeyNode::new(&mut *self.hive, cell_range));
                return Some(Ok(key_node));
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

            self.inner_info = Some(IndexRootIterMutInnerInfo {
                signature,
                elements_range,
            });
        }
    }
}

struct IndexRootIterMutInnerInfo {
    signature: [u8; 2],
    elements_range: Range<usize>,
}
