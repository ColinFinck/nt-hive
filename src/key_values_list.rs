// Copyright 2020-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::bytes_subrange;
use crate::hive::Hive;
use crate::key_value::KeyValue;
use ::byteorder::LittleEndian;
use core::iter::FusedIterator;
use core::mem;
use core::ops::Range;
use zerocopy::*;

/// On-Disk Structure of a Key Values List Element.
#[allow(dead_code)]
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
pub(crate) struct KeyValuesListElement {
    key_value_offset: U32<LittleEndian>,
}

impl KeyValuesListElement {
    pub(crate) fn elements_range(
        count: u32,
        count_field_offset: usize,
        cell_range: Range<usize>,
    ) -> Result<Range<usize>> {
        let bytes_count = count as usize * mem::size_of::<Self>();

        bytes_subrange(&cell_range, bytes_count).ok_or_else(|| NtHiveError::InvalidSizeField {
            offset: count_field_offset,
            expected: bytes_count,
            actual: cell_range.len(),
        })
    }

    pub(crate) fn next_key_value_offset<B>(
        hive: &Hive<B>,
        elements_range: &mut Range<usize>,
    ) -> Option<u32>
    where
        B: ByteSlice,
    {
        let element_range = bytes_subrange(&elements_range, mem::size_of::<Self>())?;
        elements_range.start += mem::size_of::<Self>();

        let element = LayoutVerified::<&[u8], Self>::new(&hive.data[element_range]).unwrap();
        Some(element.key_value_offset.get())
    }
}

/// Iterator over Key Values.
#[derive(Clone)]
pub struct KeyValueIter<'a, B: ByteSlice> {
    hive: &'a Hive<B>,
    elements_range: Range<usize>,
}

impl<'a, B> KeyValueIter<'a, B>
where
    B: ByteSlice,
{
    pub(crate) fn new(
        hive: &'a Hive<B>,
        count: u32,
        count_field_offset: usize,
        cell_range: Range<usize>,
    ) -> Result<Self> {
        let elements_range =
            KeyValuesListElement::elements_range(count, count_field_offset, cell_range)?;

        Ok(Self {
            hive,
            elements_range,
        })
    }
}

impl<'a, B> Iterator for KeyValueIter<'a, B>
where
    B: ByteSlice,
{
    type Item = Result<KeyValue<&'a Hive<B>, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        let key_value_offset =
            KeyValuesListElement::next_key_value_offset(&self.hive, &mut self.elements_range)?;
        let cell_range = iter_try!(self.hive.cell_range_from_data_offset(key_value_offset));
        let key_value = iter_try!(KeyValue::new(self.hive, cell_range));

        self.elements_range.start += mem::size_of::<KeyValuesListElement>();
        Some(Ok(key_value))
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
        let bytes_to_skip = n.checked_mul(mem::size_of::<KeyValuesListElement>())?;
        self.elements_range.start = self.elements_range.start.checked_add(bytes_to_skip)?;
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.elements_range.len() / mem::size_of::<KeyValuesListElement>();
        (size, Some(size))
    }
}

impl<'a, B> ExactSizeIterator for KeyValueIter<'a, B> where B: ByteSlice {}
impl<'a, B> FusedIterator for KeyValueIter<'a, B> where B: ByteSlice {}
