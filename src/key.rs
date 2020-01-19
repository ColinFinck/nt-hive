// Copyright 2019-2020 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::fast_leaf::FastLeafIter;
use crate::hash_leaf::HashLeafIter;
use crate::hive::Hive;
use crate::index_leaf::IndexLeafIter;
use crate::index_root::IndexRootIter;
use crate::NtHiveError;
use core::convert::TryInto;
use memoffset::span_of;

/// On-Disk Structure of a Key Node
#[repr(C, packed)]
struct KeyNode {
    signature: [u8; 2],
    flags: u16,
    timestamp: u64,
    spare: u32,
    parent: u32,
    subkey_count: u32,
    volatile_subkey_count: u32,
    subkeys_list_offset: u32,
    volatile_subkeys_list_offset: u32,
    keyvalues_count: u32,
    keyvalues_list_offset: u32,
    key_security_offset: u32,
    class_name_offset: u32,
    max_subkey_name: u32,
    max_subkey_class_name: u32,
    max_value_name: u32,
    max_value_data: u32,
    work_var: u32,
    key_name_length: u32,
    class_name_length: u32,
}

/// Common fields of all subkey types (Index Root, Index Leaf, Fast Leaf, Hash Leaf)
#[repr(C, packed)]
pub(crate) struct SubkeyCommon {
    pub(crate) signature: [u8; 2],
}

pub struct Key<'a> {
    pub(crate) hive: &'a Hive,
    pub(crate) hivebin_offset: usize,
    pub(crate) cell_offset: usize,
}

impl<'a> Key<'a> {
    pub fn subkeys(&self) -> Result<Subkeys, NtHiveError> {
        let key_node_slice = &self.hive.hive_data[self.cell_offset..];
        let offset_bytes = &key_node_slice[span_of!(KeyNode, subkeys_list_offset)];
        let offset = u32::from_le_bytes(offset_bytes.try_into().unwrap());

        Subkeys::new(self, offset)
    }

    pub fn validate(&self) -> Result<(), NtHiveError> {
        let key_node_slice = &self.hive.hive_data[self.cell_offset..];
        let signature = &key_node_slice[span_of!(KeyNode, signature)];
        let expected_signature = b"nk";

        if signature == expected_signature {
            Ok(())
        } else {
            Err(NtHiveError::InvalidSignature {
                actual: signature.to_vec(),
                expected: expected_signature.to_vec(),
                offset: signature.as_ptr() as usize - self.hive.hive_data.as_ptr() as usize,
            })
        }
    }
}

enum SubkeyIterators<'a> {
    FastLeaf(FastLeafIter<'a>),
    HashLeaf(HashLeafIter<'a>),
    IndexLeaf(IndexLeafIter<'a>),
    IndexRoot(IndexRootIter<'a>),
}

pub struct Subkeys<'a> {
    inner_iter: SubkeyIterators<'a>,
}

impl<'a> Subkeys<'a> {
    fn new(key: &'a Key<'a>, offset: u32) -> Result<Self, NtHiveError> {
        // Read the signature of this Subkeys List.
        let subkey_slice = &key.hive.hive_data[key.hivebin_offset + offset as usize..];
        let signature = &subkey_slice[span_of!(SubkeyCommon, signature)];

        // Check the Subkeys List type and create the corresponding inner iterator.
        let inner_iter = match signature {
            b"ri" => {
                // Index Root
                SubkeyIterators::IndexRoot(IndexRootIter::new(key, offset))
            }
            b"li" => {
                // Index Leaf
                SubkeyIterators::IndexLeaf(IndexLeafIter::new(key, offset))
            }
            b"lf" => {
                // Fast Leaf
                SubkeyIterators::FastLeaf(FastLeafIter::new(key, offset))
            }
            b"lh" => {
                // Hash Leaf
                SubkeyIterators::HashLeaf(HashLeafIter::new(key, offset))
            }
            _ => {
                return Err(NtHiveError::InvalidSignature {
                    actual: signature.to_vec(),
                    expected: b"ri|li|lf|lh".to_vec(),
                    offset: signature.as_ptr() as usize - key.hive.hive_data.as_ptr() as usize,
                });
            }
        };

        Ok(Self {
            inner_iter: inner_iter,
        })
    }
}

impl<'a> Iterator for Subkeys<'a> {
    type Item = Result<Key<'a>, NtHiveError>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner_iter {
            SubkeyIterators::FastLeaf(iter) => iter.next(),
            SubkeyIterators::HashLeaf(iter) => iter.next(),
            SubkeyIterators::IndexLeaf(iter) => iter.next(),
            SubkeyIterators::IndexRoot(iter) => iter.next(),
        }
    }
}
