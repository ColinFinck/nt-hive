// Copyright 2020-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::byte_subrange;
use crate::hive::Hive;
use ::byteorder::LittleEndian;
use core::cmp;
use core::iter::FusedIterator;
use core::mem;
use core::ops::{Deref, Range};
use zerocopy::*;

/// Number of bytes that a single Big Data segment can hold.
/// Every Big Data segment contains that many data bytes except for the last one.
///
/// This is also the threshold to decide whether Key Value Data is considered Big Data or not.
/// Up to this size, data fits into a single cell and is handled via KeyValueData::Small.
/// Everything above needs a Big Data structure and is handled through KeyValueData::Big.
pub(crate) const BIG_DATA_SEGMENT_SIZE: usize = 16344;

/// On-Disk Structure of a Big Data header.
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct BigDataHeader {
    signature: [u8; 2],
    segment_count: U16<LittleEndian>,
    segment_list_offset: U32<LittleEndian>,
}

/// On-Disk Structure of a Big Data list item.
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct BigDataListItem {
    segment_offset: U32<LittleEndian>,
}

/// Byte range of a single Big Data list item returned by [`BigDataListItemRanges`].
struct BigDataListItemRange(Range<usize>);

impl BigDataListItemRange {
    fn segment_offset<B>(&self, hive: &Hive<B>) -> u32
    where
        B: ByteSlice,
    {
        let item =
            LayoutVerified::<&[u8], BigDataListItem>::new(&hive.data[self.0.clone()]).unwrap();
        item.segment_offset.get()
    }
}

impl Deref for BigDataListItemRange {
    type Target = Range<usize>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Iterator over
///   a contiguous range of data bytes containing Big Data list items,
///   returning a [`BigDataListItemRange`] for each item.
///
/// On-Disk Signature: `db`
#[derive(Clone)]
struct BigDataListItemRanges {
    items_range: Range<usize>,
}

impl BigDataListItemRanges {
    fn new<B>(
        hive: &Hive<B>,
        data_size: u32,
        data_size_field_offset: usize,
        header_cell_range: Range<usize>,
    ) -> Result<Self>
    where
        B: ByteSlice,
    {
        let data_size = data_size as usize;

        // The passed `header_cell_range` contains just the `BigDataHeader`.
        // Verify this header.
        let header_range = byte_subrange(&header_cell_range, mem::size_of::<BigDataHeader>())
            .ok_or_else(|| NtHiveError::InvalidHeaderSize {
                offset: hive.offset_of_data_offset(header_cell_range.start),
                expected: mem::size_of::<BigDataHeader>(),
                actual: header_cell_range.len(),
            })?;

        let header = LayoutVerified::new(&hive.data[header_range]).unwrap();
        Self::validate_signature(&hive, &header)?;

        // Check the `segment_count` of the `BigDataHeader`.
        // Verify that we have enough segments to contain the entire data.
        let segment_count = header.segment_count.get();
        let max_data_size = segment_count as usize * BIG_DATA_SEGMENT_SIZE;
        if data_size > max_data_size {
            return Err(NtHiveError::InvalidSizeField {
                offset: data_size_field_offset,
                expected: max_data_size,
                actual: data_size,
            });
        }

        // Get the Big Data segment list referenced by the `segment_list_offset`.
        let segment_list_offset = header.segment_list_offset.get();
        let segment_list_cell_range = hive.cell_range_from_data_offset(segment_list_offset)?;

        // Finally calculate the range of Big Data list items we want to iterate over.
        let byte_count = segment_count as usize * mem::size_of::<BigDataListItem>();

        let items_range = byte_subrange(&segment_list_cell_range, byte_count).ok_or_else(|| {
            NtHiveError::InvalidSizeField {
                offset: hive.offset_of_field(&header.segment_count),
                expected: byte_count,
                actual: segment_list_cell_range.len(),
            }
        })?;

        Ok(Self { items_range })
    }

    fn validate_signature<B>(
        hive: &Hive<B>,
        header: &LayoutVerified<&[u8], BigDataHeader>,
    ) -> Result<()>
    where
        B: ByteSlice,
    {
        let signature = &header.signature;
        let expected_signature = b"db";

        if signature == expected_signature {
            Ok(())
        } else {
            Err(NtHiveError::InvalidTwoByteSignature {
                offset: hive.offset_of_field(signature),
                expected: expected_signature,
                actual: *signature,
            })
        }
    }
}

impl Iterator for BigDataListItemRanges {
    type Item = BigDataListItemRange;

    fn next(&mut self) -> Option<Self::Item> {
        let item_range = byte_subrange(&self.items_range, mem::size_of::<BigDataListItem>())?;
        self.items_range.start += mem::size_of::<BigDataListItem>();

        Some(BigDataListItemRange(item_range))
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
        let bytes_to_skip = n.checked_mul(mem::size_of::<BigDataListItem>())?;
        self.items_range.start = self.items_range.start.checked_add(bytes_to_skip)?;
        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.items_range.len() / mem::size_of::<BigDataListItem>();
        (size, Some(size))
    }
}

impl ExactSizeIterator for BigDataListItemRanges {}
impl FusedIterator for BigDataListItemRanges {}

/// Iterator over
///   a contiguous range of data bytes containing Big Data list items,
///   returning a constant byte slice for each item,
///   used by [`KeyValueData`].
///
/// On-Disk Signature: `db`
///
/// [`KeyValueData`]: crate::key_value::KeyValueData
#[derive(Clone)]
pub struct BigDataSlices<'a, B: ByteSlice> {
    hive: &'a Hive<B>,
    big_data_list_item_ranges: BigDataListItemRanges,
    bytes_left: usize,
}

impl<'a, B> BigDataSlices<'a, B>
where
    B: ByteSlice,
{
    pub(crate) fn new(
        hive: &'a Hive<B>,
        data_size: u32,
        data_size_field_offset: usize,
        header_cell_range: Range<usize>,
    ) -> Result<Self> {
        let big_data_list_item_ranges =
            BigDataListItemRanges::new(hive, data_size, data_size_field_offset, header_cell_range)?;

        Ok(Self {
            hive,
            big_data_list_item_ranges,
            bytes_left: data_size as usize,
        })
    }
}

impl<'a, B> Iterator for BigDataSlices<'a, B>
where
    B: ByteSlice,
{
    type Item = Result<&'a [u8]>;

    fn next(&mut self) -> Option<Self::Item> {
        // Every segment contains BIG_DATA_SEGMENT_SIZE bytes of data except for the last one.
        let bytes_to_return = cmp::min(self.bytes_left, BIG_DATA_SEGMENT_SIZE);
        if bytes_to_return == 0 {
            return None;
        }

        // Get the next segment offset and adjust `bytes_left` accordingly.
        let big_data_list_item_range = self.big_data_list_item_ranges.next()?;
        let segment_offset = big_data_list_item_range.segment_offset(&self.hive);
        self.bytes_left -= bytes_to_return;

        // Get the cell belonging to that offset and check if it contains as many bytes
        // as we expect.
        let cell_range = iter_try!(self.hive.cell_range_from_data_offset(segment_offset));
        let data_range = iter_try!(byte_subrange(&cell_range, bytes_to_return).ok_or_else(|| {
            NtHiveError::InvalidDataSize {
                offset: self.hive.offset_of_data_offset(cell_range.start),
                expected: bytes_to_return,
                actual: cell_range.len(),
            }
        }));

        // Return a byte slice containing this segment's data.
        Some(Ok(&self.hive.data[data_range]))
    }

    fn count(self) -> usize {
        self.big_data_list_item_ranges.count()
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
        let bytes_to_skip = n.checked_mul(BIG_DATA_SEGMENT_SIZE)?;
        self.bytes_left = self.bytes_left.saturating_sub(bytes_to_skip);
        if self.bytes_left == 0 {
            return None;
        }

        // This calculation is safe considering that we have checked the
        // multiplication and subtraction above.
        self.big_data_list_item_ranges.items_range.start += n * mem::size_of::<BigDataListItem>();

        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.big_data_list_item_ranges.size_hint()
    }
}

impl<'a, B> ExactSizeIterator for BigDataSlices<'a, B> where B: ByteSlice {}
impl<'a, B> FusedIterator for BigDataSlices<'a, B> where B: ByteSlice {}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_big_data() {
        let testhive = crate::helpers::tests::testhive_vec();
        let hive = Hive::new(testhive.as_ref()).unwrap();
        let root_key_node = hive.root_key_node().unwrap();
        let key_node = root_key_node.subkey("big-data-test").unwrap().unwrap();

        // Key Value "A" should be filled with 16343 'A' bytes and still fit into a cell.
        let key_value = key_node.value("A").unwrap().unwrap();
        assert_eq!(key_value.data_type().unwrap(), KeyValueDataType::RegBinary);
        assert_eq!(key_value.data_size(), 16343);

        let expected_data = vec![b'A'; 16343];
        let key_value_data = key_value.data().unwrap();
        assert!(matches!(key_value_data, KeyValueData::Small(_)));
        assert_eq!(key_value_data.into_vec().unwrap(), expected_data);

        // Key Value "B" should be filled with 16344 'B' bytes and still fit into a cell.
        let key_value = key_node.value("B").unwrap().unwrap();
        assert_eq!(key_value.data_type().unwrap(), KeyValueDataType::RegBinary);
        assert_eq!(key_value.data_size(), 16344);

        let expected_data = vec![b'B'; 16344];
        let key_value_data = key_value.data().unwrap();
        assert!(matches!(key_value_data, KeyValueData::Small(_)));
        assert_eq!(key_value_data.into_vec().unwrap(), expected_data);

        // Key Value "C" should be filled with 16345 'C' bytes and require a Big Data structure.
        let key_value = key_node.value("C").unwrap().unwrap();
        assert_eq!(key_value.data_type().unwrap(), KeyValueDataType::RegBinary);
        assert_eq!(key_value.data_size(), 16345);

        let expected_data = vec![b'C'; 16345];
        let key_value_data = key_value.data().unwrap();
        assert!(matches!(key_value_data, KeyValueData::Big(_)));
        assert_eq!(key_value_data.into_vec().unwrap(), expected_data);
    }
}
