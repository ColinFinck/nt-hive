// Copyright 2019-2020 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

//!
//! Hash Leafs are supported since Windows XP.
//!

use crate::error::{NtHiveError, Result};
use crate::hive::Hive;
use crate::key_node::KeyNode;
use ::byteorder::LittleEndian;
use core::iter::FusedIterator;
use core::mem;
use core::ops::Range;
use zerocopy::*;

/// On-Disk Structure of a Hash Leaf Element.
#[allow(dead_code)]
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
pub(crate) struct HashLeafElement {
    key_node_offset: U32<LittleEndian>,
    name_hash: [u8; 4],
}

impl HashLeafElement {
    pub(crate) fn elements_range(
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

    pub(crate) fn next_key_node_offset<B>(
        hive: &Hive<B>,
        elements_range: &mut Range<usize>,
    ) -> Option<u32>
    where
        B: ByteSlice,
    {
        let element_range = elements_range.start..elements_range.start + mem::size_of::<Self>();
        if element_range.end > elements_range.end {
            return None;
        }

        elements_range.start += mem::size_of::<Self>();

        let element = LayoutVerified::<&[u8], Self>::new(&hive.data[element_range]).unwrap();
        Some(element.key_node_offset.get())
    }
}

/// Iterator over Hash Leaf Elements.
pub struct HashLeafIter<'a, B: ByteSlice> {
    hive: &'a Hive<B>,
    elements_range: Range<usize>,
}

impl<'a, B> HashLeafIter<'a, B>
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
            HashLeafElement::elements_range(count, count_field_offset, data_range)?;

        Ok(Self {
            hive,
            elements_range,
        })
    }
}

impl<'a, B> Iterator for HashLeafIter<'a, B>
where
    B: ByteSlice,
{
    type Item = Result<KeyNode<&'a Hive<B>, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        let key_node_offset =
            HashLeafElement::next_key_node_offset(&self.hive, &mut self.elements_range)?;
        let cell_range = iter_try!(self.hive.cell_range_from_data_offset(key_node_offset));
        let key_node = iter_try!(KeyNode::new(self.hive, cell_range));

        self.elements_range.start += mem::size_of::<HashLeafElement>();
        Some(Ok(key_node))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.elements_range.len() / mem::size_of::<HashLeafElement>();
        (size, Some(size))
    }
}

impl<'a, B> ExactSizeIterator for HashLeafIter<'a, B> where B: ByteSlice {}
impl<'a, B> FusedIterator for HashLeafIter<'a, B> where B: ByteSlice {}

/// Iterator over mutable Hash Leaf Elements.
pub(crate) struct HashLeafIterMut<'a, B: ByteSliceMut> {
    hive: &'a mut Hive<B>,
    elements_range: Range<usize>,
}

impl<'a, B> HashLeafIterMut<'a, B>
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
            HashLeafElement::elements_range(count, count_field_offset, data_range)?;

        Ok(Self {
            hive,
            elements_range,
        })
    }

    pub fn next<'e>(&'e mut self) -> Option<Result<KeyNode<&'e mut Hive<B>, B>>> {
        let key_node_offset =
            HashLeafElement::next_key_node_offset(&self.hive, &mut self.elements_range)?;
        let cell_range = iter_try!(self.hive.cell_range_from_data_offset(key_node_offset));
        let key_node = iter_try!(KeyNode::new(&mut *self.hive, cell_range));

        self.elements_range.start += mem::size_of::<HashLeafElement>();
        Some(Ok(key_node))
    }
}
