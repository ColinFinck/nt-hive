// Copyright 2020-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::bytes_subrange;
use crate::hive::Hive;
use ::byteorder::LittleEndian;
use core::cmp;
use core::iter::FusedIterator;
use core::mem;
use core::ops::Range;
use zerocopy::*;

/// Number of bytes that a single Big Data Segment can hold.
/// Every Big Data Segment contains that many data bytes except for the last one.
///
/// This is also the threshold to decide whether Key Value Data is considered Big Data or not.
/// Up to this size, data fits into a single cell and is handled via KeyValueData::Small.
/// Everything above needs a Big Data structure and is handled through KeyValueData::Big.
pub(crate) const BIG_DATA_SEGMENT_SIZE: usize = 16344;

/// On-Disk Structure of a Big Data Header.
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct BigDataHeader {
    signature: [u8; 2],
    segment_count: U16<LittleEndian>,
    segment_list_offset: U32<LittleEndian>,
}

/// On-Disk Structure of a Key Values List Element.
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct BigDataListElement {
    segment_offset: U32<LittleEndian>,
}

impl BigDataListElement {
    fn elements_range(
        count: u16,
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

    fn next_segment_offset<B>(hive: &Hive<B>, elements_range: &mut Range<usize>) -> Option<u32>
    where
        B: ByteSlice,
    {
        let element_range = bytes_subrange(elements_range, mem::size_of::<Self>())?;
        elements_range.start += mem::size_of::<Self>();

        let element = LayoutVerified::<&[u8], Self>::new(&hive.data[element_range]).unwrap();
        Some(element.segment_offset.get())
    }
}

/// Iterator over Big Data Segments.
#[derive(Clone)]
pub struct BigDataIter<'a, B: ByteSlice> {
    hive: &'a Hive<B>,
    elements_range: Range<usize>,
    bytes_left: usize,
}

impl<'a, B> BigDataIter<'a, B>
where
    B: ByteSlice,
{
    pub(crate) fn new(
        hive: &'a Hive<B>,
        data_size: u32,
        data_size_field_offset: usize,
        header_cell_range: Range<usize>,
    ) -> Result<Self> {
        let data_size = data_size as usize;

        // The passed `header_cell_range` contains just the `BigDataHeader`.
        // Verify this header.
        let header_range = bytes_subrange(&header_cell_range, mem::size_of::<BigDataHeader>())
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

        // Get the Big Data Segment List referenced by the `segment_list_offset`.
        let segment_list_offset = header.segment_list_offset.get();
        let segment_list_cell_range = hive.cell_range_from_data_offset(segment_list_offset)?;

        // Finally calculate the range of Big Data Segment List Elements we want to iterate over.
        let segment_count_field_offset = hive.offset_of_field(&header.segment_count);
        let elements_range = BigDataListElement::elements_range(
            segment_count,
            segment_count_field_offset,
            segment_list_cell_range,
        )?;

        Ok(Self {
            hive,
            elements_range,
            bytes_left: data_size,
        })
    }

    fn validate_signature(
        hive: &'a Hive<B>,
        header: &LayoutVerified<&[u8], BigDataHeader>,
    ) -> Result<()> {
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

impl<'a, B> Iterator for BigDataIter<'a, B>
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

        // Get the next segment offset (advancing our `elements_range` cursor) and
        // adjust `bytes_left` accordingly.
        let segment_offset =
            BigDataListElement::next_segment_offset(&self.hive, &mut self.elements_range)?;
        self.bytes_left -= bytes_to_return;

        // Get the cell belonging to that offset and check if it contains as many bytes
        // as we expect.
        let cell_range = iter_try!(self.hive.cell_range_from_data_offset(segment_offset));
        let data_range = iter_try!(bytes_subrange(&cell_range, bytes_to_return).ok_or_else(|| {
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
        let bytes_to_skip = n.checked_mul(BIG_DATA_SEGMENT_SIZE)?;
        self.bytes_left = self.bytes_left.saturating_sub(bytes_to_skip);
        if self.bytes_left == 0 {
            return None;
        }

        // This calculation is safe considering that we have checked the
        // multiplication and subtraction above.
        self.elements_range.start += n * mem::size_of::<BigDataListElement>();

        self.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.elements_range.len() / mem::size_of::<BigDataListElement>();
        (size, Some(size))
    }
}

impl<'a, B> ExactSizeIterator for BigDataIter<'a, B> where B: ByteSlice {}
impl<'a, B> FusedIterator for BigDataIter<'a, B> where B: ByteSlice {}
