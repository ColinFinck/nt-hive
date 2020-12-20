// Copyright 2020 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
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
        let count = count as usize;
        let elements_range = cell_range.start..cell_range.start + count * mem::size_of::<Self>();

        if elements_range.end > cell_range.end {
            return Err(NtHiveError::InvalidSizeField {
                offset: count_field_offset,
                expected: elements_range.len(),
                actual: cell_range.len(),
            });
        }

        Ok(elements_range)
    }

    pub(crate) fn next_key_value_offset<B>(
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
        Some(element.key_value_offset.get())
    }
}

/// Iterator over Key Values.
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

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.elements_range.len() / mem::size_of::<KeyValuesListElement>();
        (size, Some(size))
    }
}

impl<'a, B> ExactSizeIterator for KeyValueIter<'a, B> where B: ByteSlice {}
impl<'a, B> FusedIterator for KeyValueIter<'a, B> where B: ByteSlice {}
