// Copyright 2019 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::key::Key;
use core::mem;


/// On-Disk Structure of a Fast Leaf Header.
/// Every Fast Leaf has a `FastLeafHeader` followed by one or more `FastLeafElement`s.
/// Fast Leafs are supported since Windows NT 4.
#[repr(C, packed)]
struct FastLeafHeader {
    signature: [u8; 2],
    count: u16,
}

/// On-Disk Structure of a Fast Leaf Element.
#[repr(C, packed)]
struct FastLeafElement {
    key_node_offset: u32,
    name_hint: [u8; 4],
}

/// Iterator over Fast Leaf Elements.
pub(crate) struct FastLeafIter<'a> {
    key: &'a Key<'a>,
    current_offset: usize,
    end_offset: usize,
}

impl<'a> FastLeafIter<'a> {
    /// Creates a new `FastLeafIter` from a `Key` structure and an offset relative to the Hive Bin.
    /// The caller must have checked that this offset really refers to a Fast Leaf!
    pub(crate) fn new(key: &'a Key<'a>, offset: u32) -> Self {
        // Get the `FastLeafHeader` structure at the current offset.
        let header_start = key.hivebin_offset + offset as usize;
        let header_end = header_start + mem::size_of::<FastLeafHeader>();
        let header_slice = &key.hive.hive_data[header_start..header_end];
        let header = unsafe { &*(header_slice.as_ptr() as *const FastLeafHeader) };

        // Ensure that this is really a Fast Leaf.
        assert!(&header.signature == b"lf");

        // Read the number of `FastLeafElement`s and calculate the end offset.
        let count = u16::from_le(header.count) as usize;
        let end_offset = header_end + count * mem::size_of::<FastLeafElement>();

        // Return a `FastLeafIter` structure to iterate over the keys referred by this Fast Leaf.
        Self {
            key: key,
            current_offset: header_end,
            end_offset: end_offset,
        }
    }
}

impl<'a> Iterator for FastLeafIter<'a> {
    type Item = Key<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_offset < self.end_offset {
            // Get the `FastLeafElement` structure at the current offset.
            let element_start = self.current_offset;
            let element_end = element_start + mem::size_of::<FastLeafElement>();
            let element_slice = &self.key.hive.hive_data[element_start..element_end];
            let element = unsafe { &*(element_slice.as_ptr() as *const FastLeafElement) };

            // Read the offset of this element's Key Node from the `FastLeafElement` structure.
            let key_node_offset = u32::from_le(element.key_node_offset);

            // Advance to the next `FastLeafElement`.
            self.current_offset += mem::size_of::<FastLeafElement>();

            // Return a `Key` structure for this Key Node.
            Some(Key {
                hive: self.key.hive,
                hivebin_offset: self.key.hivebin_offset,
                cell_offset: self.key.hivebin_offset + key_node_offset as usize,
            })
        } else {
            None
        }
    }
}
