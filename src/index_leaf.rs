// Copyright 2019-2020 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::key::Key;
use crate::NtHiveError;
use core::convert::TryInto;
use core::mem;
use memoffset::span_of;

/// On-Disk Structure of an Index Leaf Header.
/// Every Index Leaf has an `IndexLeafHeader` followed by one or more `IndexLeafElement`s.
/// Index Leafs are supported in all Windows versions.
#[repr(C, packed)]
struct IndexLeafHeader {
    signature: [u8; 2],
    count: u16,
}

/// On-Disk Structure of an Index Leaf Element.
#[repr(C, packed)]
struct IndexLeafElement {
    key_node_offset: u32,
}

/// Iterator over Index Leaf Elements.
pub(crate) struct IndexLeafIter<'a> {
    key: &'a Key<'a>,
    current_offset: usize,
    end_offset: usize,
}

impl<'a> IndexLeafIter<'a> {
    /// Creates a new `IndexLeafIter` from a `Key` structure and an offset relative to the Hive Bin.
    /// The caller must have checked that this offset really refers to an Index Leaf!
    pub(crate) fn new(key: &'a Key<'a>, offset: u32) -> Self {
        // Get the `IndexLeafHeader` structure at the current offset.
        let header_start = key.hivebin_offset + offset as usize;
        let header_end = header_start + mem::size_of::<IndexLeafHeader>();
        let header_slice = &key.hive.hive_data[header_start..header_end];

        // Ensure that this is really an Index Leaf.
        let signature = &header_slice[span_of!(IndexLeafHeader, signature)];
        assert!(signature == b"li");

        // Read the number of `IndexLeafElement`s and calculate the end offset.
        let count_bytes = &header_slice[span_of!(IndexLeafHeader, count)];
        let count = u16::from_le_bytes(count_bytes.try_into().unwrap()) as usize;
        let end_offset = header_end + count * mem::size_of::<IndexLeafElement>();

        // Return an `IndexLeafIter` structure to iterate over the keys referred by this Index Leaf.
        Self {
            key: key,
            current_offset: header_end,
            end_offset: end_offset,
        }
    }
}

impl<'a> Iterator for IndexLeafIter<'a> {
    type Item = Result<Key<'a>, NtHiveError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_offset < self.end_offset {
            // Get the `IndexLeafElement` structure at the current offset.
            let element_start = self.current_offset;
            let element_end = element_start + mem::size_of::<IndexLeafElement>();
            let element_slice = &self.key.hive.hive_data[element_start..element_end];

            // Read the offset of this element's Key Node from the `IndexLeafElement` structure.
            let key_node_offset_bytes = &element_slice[span_of!(IndexLeafElement, key_node_offset)];
            let key_node_offset = u32::from_le_bytes(key_node_offset_bytes.try_into().unwrap());

            // Advance to the next `IndexLeafElement`.
            self.current_offset += mem::size_of::<IndexLeafElement>();

            // Return a `Key` structure for this Key Node.
            Some(Ok(Key {
                hive: self.key.hive,
                hivebin_offset: self.key.hivebin_offset,
                cell_offset: self.key.hivebin_offset + key_node_offset as usize,
            }))
        } else {
            None
        }
    }
}
