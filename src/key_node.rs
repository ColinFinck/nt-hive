// Copyright 2019-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::byte_subrange;
use crate::hive::Hive;
use crate::index_root::IndexRootItemRanges;
use crate::key_value::KeyValue;
use crate::key_values_list::KeyValues;
use crate::leaf::{LeafItemRange, LeafItemRanges};
use crate::string::NtHiveNameString;
use crate::subkeys_list::{SubKeyNodes, SubKeyNodesMut};
use ::byteorder::LittleEndian;
use bitflags::bitflags;
use core::cmp::Ordering;
use core::mem;
use core::ops::{Deref, DerefMut, Range};
use core::ptr;
use zerocopy::*;

bitflags! {
    struct KeyNodeFlags: u16 {
        /// This is a volatile key (not stored on disk).
        const KEY_IS_VOLATILE = 0x0001;
        /// This is the mount point of another hive (not stored on disk).
        const KEY_HIVE_EXIT = 0x0002;
        /// This is the root key.
        const KEY_HIVE_ENTRY = 0x0004;
        /// This key cannot be deleted.
        const KEY_NO_DELETE = 0x0008;
        /// This key is a symbolic link.
        const KEY_SYM_LINK = 0x0010;
        /// The key name is in (extended) ASCII instead of UTF-16LE.
        const KEY_COMP_NAME = 0x0020;
        /// This key is a predefined handle.
        const KEY_PREDEF_HANDLE = 0x0040;
        /// This key was virtualized at least once.
        const KEY_VIRT_MIRRORED = 0x0080;
        /// This is a virtual key.
        const KEY_VIRT_TARGET = 0x0100;
        /// This key is part of a virtual store path.
        const KEY_VIRTUAL_STORE = 0x0200;
    }
}

/// On-Disk Structure of a Key Node header.
#[allow(dead_code)]
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct KeyNodeHeader {
    signature: [u8; 2],
    flags: U16<LittleEndian>,
    timestamp: U64<LittleEndian>,
    spare: U32<LittleEndian>,
    parent: U32<LittleEndian>,
    subkey_count: U32<LittleEndian>,
    volatile_subkey_count: U32<LittleEndian>,
    subkeys_list_offset: U32<LittleEndian>,
    volatile_subkeys_list_offset: U32<LittleEndian>,
    key_values_count: U32<LittleEndian>,
    key_values_list_offset: U32<LittleEndian>,
    key_security_offset: U32<LittleEndian>,
    class_name_offset: U32<LittleEndian>,
    max_subkey_name: U32<LittleEndian>,
    max_subkey_class_name: U32<LittleEndian>,
    max_value_name: U32<LittleEndian>,
    max_value_data: U32<LittleEndian>,
    work_var: U32<LittleEndian>,
    key_name_length: U16<LittleEndian>,
    class_name_length: U16<LittleEndian>,
}

/// Byte range of a single Key Node item.
#[derive(Clone, Eq, PartialEq)]
struct KeyNodeItemRange {
    header_range: Range<usize>,
    data_range: Range<usize>,
}

impl KeyNodeItemRange {
    fn from_cell_range<B>(hive: &Hive<B>, cell_range: Range<usize>) -> Result<Self>
    where
        B: ByteSlice,
    {
        let header_range =
            byte_subrange(&cell_range, mem::size_of::<KeyNodeHeader>()).ok_or_else(|| {
                NtHiveError::InvalidHeaderSize {
                    offset: hive.offset_of_data_offset(cell_range.start),
                    expected: mem::size_of::<KeyNodeHeader>(),
                    actual: cell_range.len(),
                }
            })?;
        let data_range = header_range.end..cell_range.end;

        let key_node_item_range = Self {
            header_range,
            data_range,
        };
        key_node_item_range.validate_signature(hive)?;

        Ok(key_node_item_range)
    }

    fn from_leaf_item_range<B>(hive: &Hive<B>, leaf_item_range: LeafItemRange) -> Result<Self>
    where
        B: ByteSlice,
    {
        let key_node_offset = leaf_item_range.key_node_offset(hive);
        let cell_range = hive.cell_range_from_data_offset(key_node_offset)?;
        let key_node = Self::from_cell_range(hive, cell_range)?;
        Ok(key_node)
    }

    fn binary_search_subkey_in_index_root<B>(
        &self,
        hive: &Hive<B>,
        name: &str,
        index_root_item_ranges: IndexRootItemRanges,
    ) -> Option<Result<Self>>
    where
        B: ByteSlice,
    {
        // The following textbook binary search algorithm requires signed math.
        // Fortunately, Index Roots have a u16 `count` field, hence we should be able to convert to i32.
        assert!(index_root_item_ranges.len() <= u16::MAX as usize);
        let mut left = 0i32;
        let mut right = index_root_item_ranges.len() as i32 - 1;

        while left <= right {
            // Select the middle Index Root item given the current boundaries and get an
            // iterator over its Leaf items.
            let mid = (left + right) / 2;

            let index_root_item_range = index_root_item_ranges.clone().nth(mid as usize).unwrap();
            let leaf_item_ranges = iter_try!(LeafItemRanges::from_index_root_item_range(
                hive,
                index_root_item_range
            ));

            // Check the name of the FIRST Key Node of the selected Index Root item.
            let leaf_item_range = leaf_item_ranges.clone().next().unwrap();
            let key_node_item_range = iter_try!(Self::from_leaf_item_range(hive, leaf_item_range));
            let key_node_name = iter_try!(key_node_item_range.name(hive));

            match key_node_name.partial_cmp(name).unwrap() {
                Ordering::Equal => return Some(Ok(key_node_item_range)),
                Ordering::Less => (),
                Ordering::Greater => {
                    // The FIRST Key Node of the selected Index Root item has a name that comes
                    // AFTER the name we are looking for.
                    // Hence, the searched Key Node must be in an Index Root item BEFORE the selected one.
                    right = mid - 1;
                    continue;
                }
            }

            // Check the name of the LAST Key Node of the selected Index Root item.
            let leaf_item_range = leaf_item_ranges.clone().last().unwrap();
            let key_node_item_range = iter_try!(Self::from_leaf_item_range(hive, leaf_item_range));
            let key_node_name = iter_try!(key_node_item_range.name(hive));

            match key_node_name.partial_cmp(name).unwrap() {
                Ordering::Equal => return Some(Ok(key_node_item_range)),
                Ordering::Less => {
                    // The LAST Key Node of the selected Index Root item has a name that comes
                    // BEFORE the name we are looking for.
                    // Hence, the searched Key Node must be in an Index Root item AFTER the selected one.
                    left = mid + 1;
                    continue;
                }
                Ordering::Greater => (),
            }

            // If the searched Key Node exists at all, it must be in this Leaf.
            return self.binary_search_subkey_in_leaf(hive, name, leaf_item_ranges);
        }

        None
    }

    fn binary_search_subkey_in_leaf<B>(
        &self,
        hive: &Hive<B>,
        name: &str,
        leaf_item_ranges: LeafItemRanges,
    ) -> Option<Result<Self>>
    where
        B: ByteSlice,
    {
        // The following textbook binary search algorithm requires signed math.
        // Fortunately, Leafs have a u16 `count` field, hence we should be able to convert to i32.
        assert!(leaf_item_ranges.len() <= u16::MAX as usize);
        let mut left = 0i32;
        let mut right = leaf_item_ranges.len() as i32 - 1;

        while left <= right {
            // Select the middle Leaf item given the current boundaries and get its name.
            let mid = (left + right) / 2;

            let leaf_item_range = leaf_item_ranges.clone().nth(mid as usize).unwrap();
            let key_node_item_range = iter_try!(Self::from_leaf_item_range(hive, leaf_item_range));
            let key_node_name = iter_try!(key_node_item_range.name(hive));

            // Check if it's the name we are looking for, otherwise adjust the boundaries accordingly.
            match key_node_name.partial_cmp(name).unwrap() {
                Ordering::Equal => return Some(Ok(key_node_item_range)),
                Ordering::Less => left = mid + 1,
                Ordering::Greater => right = mid - 1,
            }
        }

        None
    }

    fn header<'a, B>(&self, hive: &'a Hive<B>) -> LayoutVerified<&'a [u8], KeyNodeHeader>
    where
        B: ByteSlice,
    {
        LayoutVerified::new(&hive.data[self.header_range.clone()]).unwrap()
    }

    fn header_mut<'a, B>(
        &self,
        hive: &'a mut Hive<B>,
    ) -> LayoutVerified<&'a mut [u8], KeyNodeHeader>
    where
        B: ByteSliceMut,
    {
        LayoutVerified::new(&mut hive.data[self.header_range.clone()]).unwrap()
    }

    fn name<'a, B>(&self, hive: &'a Hive<B>) -> Result<NtHiveNameString<'a>>
    where
        B: ByteSlice,
    {
        let header = self.header(hive);
        let flags = KeyNodeFlags::from_bits_truncate(header.flags.get());
        let key_name_length = header.key_name_length.get() as usize;

        let key_name_range = byte_subrange(&self.data_range, key_name_length).ok_or_else(|| {
            NtHiveError::InvalidSizeField {
                offset: hive.offset_of_field(&header.key_name_length),
                expected: key_name_length as usize,
                actual: self.data_range.len(),
            }
        })?;
        let key_name_bytes = &hive.data[key_name_range];

        if flags.contains(KeyNodeFlags::KEY_COMP_NAME) {
            Ok(NtHiveNameString::Latin1(key_name_bytes))
        } else {
            Ok(NtHiveNameString::Utf16LE(key_name_bytes))
        }
    }

    fn subkey<B>(&self, hive: &Hive<B>, name: &str) -> Option<Result<Self>>
    where
        B: ByteSlice,
    {
        let cell_range = iter_try!(self.subkeys_cell_range(hive)?);
        let subkeys = iter_try!(SubKeyNodes::new(hive, cell_range));

        match subkeys {
            SubKeyNodes::IndexRoot(iter) => {
                let index_root_item_ranges = IndexRootItemRanges::from(iter);
                self.binary_search_subkey_in_index_root(hive, name, index_root_item_ranges)
            }
            SubKeyNodes::Leaf(iter) => {
                let leaf_item_ranges = LeafItemRanges::from(iter);
                self.binary_search_subkey_in_leaf(hive, name, leaf_item_ranges)
            }
        }
    }

    fn subkeys_cell_range<B>(&self, hive: &Hive<B>) -> Option<Result<Range<usize>>>
    where
        B: ByteSlice,
    {
        let header = self.header(&hive);
        let subkeys_list_offset = header.subkeys_list_offset.get();
        if subkeys_list_offset == u32::MAX {
            // This Key Node has no subkeys.
            return None;
        }

        let cell_range = iter_try!(hive.cell_range_from_data_offset(subkeys_list_offset));
        Some(Ok(cell_range))
    }

    fn subpath<B>(&self, hive: &Hive<B>, path: &str) -> Option<Result<Self>>
    where
        B: ByteSlice,
    {
        let mut key_node_item_range = self.clone();

        for component in path.split('\\') {
            // Just skip duplicate, leading, and trailing backslashes.
            if !component.is_empty() {
                key_node_item_range = iter_try!(key_node_item_range.subkey(hive, component)?);
            }
        }

        Some(Ok(key_node_item_range))
    }

    fn validate_signature<B>(&self, hive: &Hive<B>) -> Result<()>
    where
        B: ByteSlice,
    {
        let header = self.header(hive);
        let signature = &header.signature;
        let expected_signature = b"nk";

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

    fn value<'a, B>(
        &self,
        hive: &'a Hive<B>,
        name: &str,
    ) -> Option<Result<KeyValue<&'a Hive<B>, B>>>
    where
        B: ByteSlice,
    {
        let mut values = iter_try!(self.values(hive)?);

        // Key Values are not sorted, so we can only iterate until we find a match.
        values.find(|key_value| {
            let key_value = match key_value {
                Ok(key_value) => key_value,
                Err(_) => return true,
            };
            let key_value_name = match key_value.name() {
                Ok(name) => name,
                Err(_) => return true,
            };

            key_value_name == name
        })
    }

    fn values<'a, B>(&self, hive: &'a Hive<B>) -> Option<Result<KeyValues<'a, B>>>
    where
        B: ByteSlice,
    {
        let header = self.header(hive);
        let key_values_list_offset = header.key_values_list_offset.get();
        if key_values_list_offset == u32::MAX {
            // This Key Node has no values.
            return None;
        }

        let cell_range = iter_try!(hive.cell_range_from_data_offset(key_values_list_offset));
        let count = header.key_values_count.get();
        let count_field_offset = hive.offset_of_field(&header.key_values_count);

        Some(KeyValues::new(hive, count, count_field_offset, cell_range))
    }
}

/// A single key that belongs to a [`Hive`].
/// It has a name and possibly subkeys ([`KeyNode`]) and values ([`KeyValue`]).
///
/// On-Disk Signature: `nk`
///
/// [`KeyValue`]: crate::key_value::KeyValue
#[derive(Clone)]
pub struct KeyNode<H: Deref<Target = Hive<B>>, B: ByteSlice> {
    hive: H,
    item_range: KeyNodeItemRange,
}

impl<H, B> KeyNode<H, B>
where
    H: Deref<Target = Hive<B>>,
    B: ByteSlice,
{
    pub(crate) fn from_cell_range(hive: H, cell_range: Range<usize>) -> Result<Self> {
        let item_range = KeyNodeItemRange::from_cell_range(&hive, cell_range)?;
        Ok(Self { hive, item_range })
    }

    pub(crate) fn from_leaf_item_range(hive: H, leaf_item_range: LeafItemRange) -> Result<Self> {
        let item_range = KeyNodeItemRange::from_leaf_item_range(&hive, leaf_item_range)?;
        Ok(Self { hive, item_range })
    }

    /// Returns the name of this Key Node.
    pub fn name(&self) -> Result<NtHiveNameString> {
        self.item_range.name(&self.hive)
    }

    /// Finds a single subkey by name using efficient binary search.
    pub fn subkey(&self, name: &str) -> Option<Result<KeyNode<&Hive<B>, B>>> {
        let item_range = iter_try!(self.item_range.subkey(&self.hive, name)?);

        Some(Ok(KeyNode {
            hive: &self.hive,
            item_range,
        }))
    }

    /// Returns an iterator over the subkeys of this Key Node.
    pub fn subkeys(&self) -> Option<Result<SubKeyNodes<B>>> {
        let cell_range = iter_try!(self.item_range.subkeys_cell_range(&self.hive)?);
        Some(SubKeyNodes::new(&self.hive, cell_range))
    }

    /// Traverses the given subpath and returns the [`KeyNode`] of the last path element.
    ///
    /// Path elements must be separated by backslashes.
    pub fn subpath(&self, path: &str) -> Option<Result<KeyNode<&Hive<B>, B>>> {
        let item_range = iter_try!(self.item_range.subpath(&self.hive, path)?);

        Some(Ok(KeyNode {
            hive: &self.hive,
            item_range,
        }))
    }

    /// Finds a single value by name.
    pub fn value(&self, name: &str) -> Option<Result<KeyValue<&Hive<B>, B>>> {
        self.item_range.value(&self.hive, name)
    }

    /// Returns an iterator over the values of this Key Node.
    pub fn values(&self) -> Option<Result<KeyValues<B>>> {
        self.item_range.values(&self.hive)
    }
}

impl<B> PartialEq for KeyNode<&Hive<B>, B>
where
    B: ByteSlice,
{
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.hive, other.hive) && self.item_range == other.item_range
    }
}

impl<B> Eq for KeyNode<&Hive<B>, B> where B: ByteSlice {}

impl<H, B> KeyNode<H, B>
where
    H: DerefMut<Target = Hive<B>>,
    B: ByteSliceMut,
{
    pub(crate) fn clear_volatile_subkeys(&mut self) -> Result<()> {
        let mut header = self.item_range.header_mut(&mut self.hive);
        header.volatile_subkey_count.set(0);

        if let Some(subkeys) = self.subkeys_mut() {
            let mut subkeys = subkeys?;
            while let Some(subkey) = subkeys.next() {
                subkey?.clear_volatile_subkeys()?;
            }
        }

        Ok(())
    }

    pub(crate) fn subkeys_mut(&mut self) -> Option<Result<SubKeyNodesMut<B>>> {
        let cell_range = iter_try!(self.item_range.subkeys_cell_range(&self.hive)?);
        Some(SubKeyNodesMut::new(&mut self.hive, cell_range))
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_character_encoding() {
        let testhive = crate::helpers::tests::testhive_vec();
        let hive = Hive::new(testhive.as_ref()).unwrap();
        let root_key_node = hive.root_key_node().unwrap();
        let key_node = root_key_node
            .subkey("character-encoding-test")
            .unwrap()
            .unwrap();

        // Prove that Latin1 characters are always stored with 1 byte per character.
        let subkey = key_node.subkey("äöü").unwrap().unwrap();
        assert!(matches!(
            subkey.name().unwrap(),
            NtHiveNameString::Latin1(&[0xe4, 0xf6, 0xfc])
        ));

        // Prove that all characters of the Unicode Basic Multilingual Plane are compared case-insensitively
        // by trying to find both "Full-Width Uppercase A" (U+FF21) and "Full-Width Lowercase A" (U+FF41),
        // and ending up with the same subkeys.
        let subkey1 = key_node.subkey("Ａ").unwrap().unwrap();
        let subkey2 = key_node.subkey("ａ").unwrap().unwrap();
        assert!(subkey1 == subkey2);

        // Prove that this isn't the case outside the Unicode Basic Multilingual Plane
        // by trying the same for "Deseret Uppercase H" (U+10410) and "Deseret Lowercase H" (U+10438).
        let subkey1 = key_node.subkey("𐐐").unwrap().unwrap();
        let subkey2 = key_node.subkey("𐐸").unwrap().unwrap();
        assert!(subkey1 != subkey2);
    }

    #[test]
    fn test_subkey() {
        // Prove that our binary search algorithm finds every subkey of "subkey-test".
        let testhive = crate::helpers::tests::testhive_vec();
        let hive = Hive::new(testhive.as_ref()).unwrap();
        let root_key_node = hive.root_key_node().unwrap();
        let key_node = root_key_node.subkey("subkey-test").unwrap().unwrap();

        for i in 0..512 {
            let subkey_name = format!("key{}", i);
            assert!(
                matches!(key_node.subkey(&subkey_name), Some(Ok(_))),
                "Could not find subkey \"{}\"",
                subkey_name
            );
        }
    }

    #[test]
    fn test_subkeys() {
        // Keep in mind that subkeys in the hive are sorted like key0, key1, key10, key11, ...
        // We can create the same order by adding them to a vector and sorting that vector.
        let mut key_names = Vec::with_capacity(512);
        for i in 0..512 {
            key_names.push(format!("key{}", i));
        }

        key_names.sort_unstable();

        // Iterate through subkeys of "subkey-test" and prove that they are sorted just like our vector.
        let testhive = crate::helpers::tests::testhive_vec();
        let hive = Hive::new(testhive.as_ref()).unwrap();
        let root_key_node = hive.root_key_node().unwrap();
        let key_node = root_key_node.subkey("subkey-test").unwrap().unwrap();

        let subkeys = key_node.subkeys().unwrap().unwrap();

        for (subkey, expected_key_name) in subkeys.zip(key_names.iter()) {
            let subkey = subkey.unwrap();
            assert_eq!(subkey.name().unwrap(), expected_key_name.as_str());
        }
    }

    #[test]
    fn test_subpath() {
        let testhive = crate::helpers::tests::testhive_vec();
        let hive = Hive::new(testhive.as_ref()).unwrap();
        let root_key_node = hive.root_key_node().unwrap();
        let key_node = root_key_node.subkey("subpath-test").unwrap().unwrap();

        assert!(matches!(key_node.subpath("no-subkeys"), Some(Ok(_))));
        assert!(matches!(key_node.subpath("\\no-subkeys"), Some(Ok(_))));
        assert!(matches!(key_node.subpath("no-subkeys\\"), Some(Ok(_))));
        assert!(matches!(key_node.subpath("\\no-subkeys\\"), Some(Ok(_))));
        assert!(matches!(key_node.subpath("no-subkeys\\non-existing"), None));

        assert!(matches!(
            key_node.subpath("with-single-level-subkey"),
            Some(Ok(_))
        ));
        assert!(matches!(
            key_node.subpath("with-single-level-subkey\\subkey"),
            Some(Ok(_))
        ));
        assert!(matches!(
            key_node.subpath("with-single-level-subkey\\\\subkey"),
            Some(Ok(_))
        ));
        assert!(matches!(
            key_node.subpath("with-single-level-subkey\\\\subkey\\"),
            Some(Ok(_))
        ));
        assert!(matches!(
            key_node.subpath("with-single-level-subkey\\subkey\\non-existing-too"),
            None
        ));

        assert!(matches!(
            key_node.subpath("with-two-levels-of-subkeys\\subkey1\\subkey2"),
            Some(Ok(_))
        ));
        assert!(matches!(
            key_node.subpath("with-two-levels-of-subkeys\\subkey1\\\\subkey2"),
            Some(Ok(_))
        ));

        assert!(matches!(key_node.subpath("non-existing"), None));
        assert!(matches!(key_node.subpath("non-existing\\sub"), None));
    }
}
