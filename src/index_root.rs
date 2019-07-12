// Copyright 2019 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::fast_leaf::FastLeafIter;
use crate::hash_leaf::HashLeafIter;
use crate::index_leaf::IndexLeafIter;
use crate::key::Key;
use core::mem;


/// On-Disk Structure of an Index Root Header.
/// Every Index Root has an `IndexRootHeader` followed by one or more `IndexRootElement`s.
/// Index Roots are supported in all Windows versions.
#[repr(C, packed)]
struct IndexRootHeader {
    signature: [u8; 2],
    count: u16,
}

/// On-Disk Structure of an Index Root Element.
#[repr(C, packed)]
struct IndexRootElement {
    subkeys_list_offset: u32,
}

enum InnerIterators<'a> {
    FastLeaf(FastLeafIter<'a>),
    HashLeaf(HashLeafIter<'a>),
    IndexLeaf(IndexLeafIter<'a>),
}

/// Iterator over Index Root Elements.
pub(crate) struct IndexRootIter<'a> {
    key: &'a Key<'a>,
    inner_iter: Option<InnerIterators<'a>>,
    current_offset: usize,
    end_offset: usize,
}

impl<'a> IndexRootIter<'a> {
    /// Creates a new `IndexRootIter` from a `Key` structure and an offset relative to the Hive Bin.
    /// The caller must have checked that this offset really refers to an Index Root!
    pub(crate) fn new(key: &'a Key<'a>, offset: u32) -> Self {
        // Get the `IndexRootHeader` structure at the current offset.
        let header_start = key.hivebin_offset + offset as usize;
        let header_end = header_start + mem::size_of::<IndexRootHeader>();
        let header_slice = &key.hive.hive_data[header_start..header_end];
        let header = unsafe { &*(header_slice.as_ptr() as *const IndexRootHeader) };

        // Ensure that this is really an Index Root.
        assert!(&header.signature == b"ri");

        // Read the number of `IndexRootElement`s and calculate the end offset.
        let count = u16::from_le(header.count) as usize;
        let end_offset = header_end + count * mem::size_of::<IndexRootElement>();

        // Return an `IndexRootIter` structure to iterate over the keys referred by this Index Root.
        Self {
            key: key,
            inner_iter: None,
            current_offset: header_end,
            end_offset: end_offset,
        }
    }
}

impl<'a> Iterator for IndexRootIter<'a> {
    type Item = Key<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut item = None;

        while item.is_none() {
            // Do we already have an inner iterator for a current Subkeys List?
            if let Some(iter) = &mut self.inner_iter {
                // Retrieve the next element from the inner iterator.
                item = match iter {
                    InnerIterators::FastLeaf(iter) => iter.next(),
                    InnerIterators::HashLeaf(iter) => iter.next(),
                    InnerIterators::IndexLeaf(iter) => iter.next(),
                };
                if item.is_some() {
                    // We have a `Key` to return.
                    break;
                }
            }

            // No inner iterator or the last inner iterator has been fully iterated.
            // So get the next inner iterator.
            if self.current_offset < self.end_offset {
                // Get the `IndexRootElement` structure at the current offset.
                let element_start = self.current_offset;
                let element_end = element_start + mem::size_of::<IndexRootElement>();
                let element_slice = &self.key.hive.hive_data[element_start..element_end];
                let element = unsafe { &*(element_slice.as_ptr() as *const IndexRootElement) };

                // Read the offset of this element's Subkeys List from the `IndexRootElement` structure.
                let subkeys_list_offset = u32::from_le(element.subkeys_list_offset);

                // Advance to the next `IndexRootElement`.
                self.current_offset += mem::size_of::<IndexRootElement>();

                // Read the signature of this Subkeys List.
                let signature_start = self.key.hivebin_offset + subkeys_list_offset as usize;
                let signature_end = signature_start + 2;
                let signature = &self.key.hive.hive_data[signature_start..signature_end];

                // Check the Subkeys List type and create the corresponding inner iterator.
                self.inner_iter = match signature {
                    b"li" => {
                        // Index Leaf
                        Some(InnerIterators::IndexLeaf(IndexLeafIter::new(self.key, subkeys_list_offset)))
                    }
                    b"lf" => {
                        // Fast Leaf
                        Some(InnerIterators::FastLeaf(FastLeafIter::new(self.key, subkeys_list_offset)))
                    }
                    b"lh" => {
                        // Hash Leaf
                        Some(InnerIterators::HashLeaf(HashLeafIter::new(self.key, subkeys_list_offset)))
                    }
                    _ => {
                        // TODO: Better error handling
                        panic!("Unknown signature");
                    }
                };
            } else {
                // All Subkeys Lists have been iterated.
                break;
            }
        }

        item
    }
}
