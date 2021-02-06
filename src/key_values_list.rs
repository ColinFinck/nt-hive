// Copyright 2020-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::byte_subrange;
use crate::hive::Hive;
use crate::key_value::KeyValue;
use ::byteorder::LittleEndian;
use core::iter::FusedIterator;
use core::mem;
use core::ops::{Deref, Range};
use zerocopy::*;

/// On-Disk Structure of a Key Values List item.
#[allow(dead_code)]
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct KeyValuesListItem {
    key_value_offset: U32<LittleEndian>,
}

/// Byte range of a single Key Values list item returned by [`KeyValuesListItemRanges`].
struct KeyValuesListItemRange(Range<usize>);

impl KeyValuesListItemRange {
    fn key_value_offset<B>(&self, hive: &Hive<B>) -> u32
    where
        B: ByteSlice,
    {
        let item =
            LayoutVerified::<&[u8], KeyValuesListItem>::new(&hive.data[self.0.clone()]).unwrap();
        item.key_value_offset.get()
    }
}

impl Deref for KeyValuesListItemRange {
    type Target = Range<usize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Iterator over
///   a contiguous range of data bytes containing Key Value items,
///   returning a [`KeyValuesListItemRange`] for each item.
///
/// On-Disk Signature: `vk`
#[derive(Clone)]
struct KeyValuesListItemRanges {
    items_range: Range<usize>,
}

impl KeyValuesListItemRanges {
    pub(crate) fn new(
        count: u32,
        count_field_offset: usize,
        cell_range: Range<usize>,
    ) -> Result<Self> {
        let byte_count = count as usize * mem::size_of::<KeyValuesListItem>();

        let items_range = byte_subrange(&cell_range, byte_count).ok_or_else(|| {
            NtHiveError::InvalidSizeField {
                offset: count_field_offset,
                expected: byte_count,
                actual: cell_range.len(),
            }
        })?;

        Ok(Self { items_range })
    }
}

impl Iterator for KeyValuesListItemRanges {
    type Item = KeyValuesListItemRange;

    fn next(&mut self) -> Option<Self::Item> {
        let item_range = byte_subrange(&self.items_range, mem::size_of::<KeyValuesListItem>())?;
        self.items_range.start += mem::size_of::<KeyValuesListItem>();

        Some(KeyValuesListItemRange(item_range))
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
        let bytes_to_skip = n.checked_mul(mem::size_of::<KeyValuesListItem>())?;
        self.items_range.start = self.items_range.start.checked_add(bytes_to_skip)?;
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.items_range.len() / mem::size_of::<KeyValuesListItem>();
        (size, Some(size))
    }
}

impl ExactSizeIterator for KeyValuesListItemRanges {}
impl FusedIterator for KeyValuesListItemRanges {}

/// Iterator over
///   a contiguous range of data bytes containing Key Value items,
///   returning a constant [`KeyValue`] for each item.
///
/// On-Disk Signature: `vk`
#[derive(Clone)]
pub struct KeyValues<'a, B: ByteSlice> {
    hive: &'a Hive<B>,
    key_values_list_item_ranges: KeyValuesListItemRanges,
}

impl<'a, B> KeyValues<'a, B>
where
    B: ByteSlice,
{
    pub(crate) fn new(
        hive: &'a Hive<B>,
        count: u32,
        count_field_offset: usize,
        cell_range: Range<usize>,
    ) -> Result<Self> {
        let key_values_list_item_ranges =
            KeyValuesListItemRanges::new(count, count_field_offset, cell_range)?;

        Ok(Self {
            hive,
            key_values_list_item_ranges,
        })
    }
}

impl<'a, B> Iterator for KeyValues<'a, B>
where
    B: ByteSlice,
{
    type Item = Result<KeyValue<&'a Hive<B>, B>>;

    fn next(&mut self) -> Option<Self::Item> {
        let key_values_list_item_range = self.key_values_list_item_ranges.next()?;
        let key_value_offset = key_values_list_item_range.key_value_offset(self.hive);
        let cell_range = iter_try!(self.hive.cell_range_from_data_offset(key_value_offset));
        let key_value = iter_try!(KeyValue::new(self.hive, cell_range));
        Some(Ok(key_value))
    }

    fn count(self) -> usize {
        self.key_values_list_item_ranges.count()
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
        let bytes_to_skip = n.checked_mul(mem::size_of::<KeyValuesListItem>())?;
        self.key_values_list_item_ranges.items_range.start = self
            .key_values_list_item_ranges
            .items_range
            .start
            .checked_add(bytes_to_skip)?;
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.key_values_list_item_ranges.size_hint()
    }
}

impl<'a, B> ExactSizeIterator for KeyValues<'a, B> where B: ByteSlice {}
impl<'a, B> FusedIterator for KeyValues<'a, B> where B: ByteSlice {}
