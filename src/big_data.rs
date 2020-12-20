// Copyright 2020 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
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

    fn next_segment_offset<B>(hive: &Hive<B>, elements_range: &mut Range<usize>) -> Option<u32>
    where
        B: ByteSlice,
    {
        let element_range = elements_range.start..elements_range.start + mem::size_of::<Self>();
        if element_range.end > elements_range.end {
            return None;
        }

        elements_range.start += mem::size_of::<Self>();

        let element = LayoutVerified::<&[u8], Self>::new(&hive.data[element_range]).unwrap();
        Some(element.segment_offset.get())
    }
}

/// Iterator over Big Data Segments.
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
        let header_range =
            header_cell_range.start..header_cell_range.start + mem::size_of::<BigDataHeader>();
        if header_range.end > header_cell_range.end {
            return Err(NtHiveError::InvalidHeaderSize {
                offset: hive.offset_of_data_offset(header_cell_range.start),
                expected: mem::size_of::<BigDataHeader>(),
                actual: header_cell_range.len(),
            });
        }

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

        let segment_offset =
            BigDataListElement::next_segment_offset(&self.hive, &mut self.elements_range)?;
        let cell_range = iter_try!(self.hive.cell_range_from_data_offset(segment_offset));
        if cell_range.len() < bytes_to_return {
            return Some(Err(NtHiveError::InvalidDataSize {
                offset: self.hive.offset_of_data_offset(cell_range.start),
                expected: bytes_to_return,
                actual: cell_range.len(),
            }));
        }

        let data_range = cell_range.start..cell_range.start + bytes_to_return;

        self.elements_range.start += mem::size_of::<BigDataListElement>();
        self.bytes_left -= bytes_to_return;

        Some(Ok(&self.hive.data[data_range]))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let size = self.elements_range.len() / mem::size_of::<BigDataListElement>();
        (size, Some(size))
    }
}

impl<'a, B> ExactSizeIterator for BigDataIter<'a, B> where B: ByteSlice {}
impl<'a, B> FusedIterator for BigDataIter<'a, B> where B: ByteSlice {}
