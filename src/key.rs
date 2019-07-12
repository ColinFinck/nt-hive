// Copyright 2019 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::fast_leaf::FastLeafIter;
use crate::hash_leaf::HashLeafIter;
use crate::hive::Hive;
use crate::index_leaf::IndexLeafIter;
use crate::index_root::IndexRootIter;
use core::mem;


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

pub struct Key<'a> {
    pub(crate) hive: &'a Hive,
    pub(crate) hivebin_offset: usize,
    pub(crate) cell_offset: usize,
}

#[derive(Debug)]
pub enum KeyError {
    InvalidSignature,
}

impl<'a> Key<'a> {
    fn key_node(&self) -> &KeyNode {
        let key_node_size = mem::size_of::<KeyNode>();
        let key_node_slice = &self.hive.hive_data[self.cell_offset..key_node_size];
        let key_node = unsafe { &*(key_node_slice.as_ptr() as *const KeyNode) };
        key_node
    }

    pub fn subkeys(&self) -> Subkeys {
        let key_node = self.key_node();
        let offset = u32::from_le(key_node.subkeys_list_offset);

        Subkeys {
            key: self,
            offset: offset,
        }
    }

    pub fn validate(&self) -> Result<(), KeyError> {
        let key_node = self.key_node();
        if &key_node.signature == b"nk" {
            Ok(())
        } else {
            Err(KeyError::InvalidSignature)
        }
    }
}

pub struct Subkeys<'a> {
    key: &'a Key<'a>,
    offset: u32,
}

impl<'a> Subkeys<'a> {
    pub fn find(&self, name: &str) -> Option<Key> {
        // TODO
        None
    }

    pub fn iter(&self) -> SubkeyIter {
        SubkeyIter::new(self.key, self.offset)
    }
}


enum SubkeyIterators<'a> {
    FastLeaf(FastLeafIter<'a>),
    HashLeaf(HashLeafIter<'a>),
    IndexLeaf(IndexLeafIter<'a>),
    IndexRoot(IndexRootIter<'a>),
}

pub struct SubkeyIter<'a> {
    inner_iter: SubkeyIterators<'a>,
}

impl<'a> SubkeyIter<'a> {
    fn new(key: &'a Key<'a>, offset: u32) -> Self {
        // Read the signature of this Subkeys List.
        let signature_start = key.hivebin_offset + offset as usize;
        let signature_end = signature_start + 2;
        let signature = &key.hive.hive_data[signature_start..signature_end];

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
                // TODO: Better error handling
                panic!("Unknown signature");
            }
        };

        Self {
            inner_iter: inner_iter,
        }
    }
}

impl<'a> Iterator for SubkeyIter<'a> {
    type Item = Key<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner_iter {
            SubkeyIterators::FastLeaf(iter) => iter.next(),
            SubkeyIterators::HashLeaf(iter) => iter.next(),
            SubkeyIterators::IndexLeaf(iter) => iter.next(),
            SubkeyIterators::IndexRoot(iter) => iter.next(),
        }
    }
}
