// Copyright 2019-2020 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::hive::Hive;
use crate::string::NtHiveString;
use crate::subkeys_list::SubkeysList;
use ::byteorder::LittleEndian;
use bitflags::bitflags;
use core::mem;
use core::ops::{Deref, DerefMut, Range};
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

/// On-Disk Structure of a Key Node Header.
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
    keyvalues_count: U32<LittleEndian>,
    keyvalues_list_offset: U32<LittleEndian>,
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

/// A key that can contain subkeys and values.
/// Signature: nk
pub struct KeyNode<H: Deref<Target = Hive<B>>, B: ByteSlice> {
    hive: H,
    header_range: Range<usize>,
    data_range: Range<usize>,
}

impl<H, B> KeyNode<H, B>
where
    H: Deref<Target = Hive<B>>,
    B: ByteSlice,
{
    pub(crate) fn new(hive: H, cell_range: Range<usize>) -> Result<Self> {
        let header_range = cell_range.start..cell_range.start + mem::size_of::<KeyNodeHeader>();
        if header_range.end > cell_range.end {
            return Err(NtHiveError::InvalidHeaderSize {
                offset: hive.offset_of_data_offset(cell_range.start),
                expected: mem::size_of::<KeyNodeHeader>(),
                actual: cell_range.len(),
            });
        }

        let data_range = header_range.end..cell_range.end;

        let key_node = Self {
            hive,
            header_range,
            data_range,
        };
        key_node.validate_signature()?;

        Ok(key_node)
    }

    fn header(&self) -> LayoutVerified<&[u8], KeyNodeHeader> {
        LayoutVerified::new(&self.hive.data[self.header_range.clone()]).unwrap()
    }

    pub fn key_name(&self) -> Result<NtHiveString> {
        let header = self.header();
        let flags = KeyNodeFlags::from_bits_truncate(header.flags.get());
        let key_name_length = header.key_name_length.get() as usize;

        let key_name_range = self.data_range.start..self.data_range.start + key_name_length;
        if key_name_range.end > self.data_range.end {
            return Err(NtHiveError::InvalidSizeField {
                offset: self.hive.offset_of_field(&header.key_name_length),
                expected: key_name_length as usize,
                actual: self.data_range.len(),
            });
        }

        let key_name_bytes = &self.hive.data[key_name_range];

        if flags.contains(KeyNodeFlags::KEY_COMP_NAME) {
            Ok(NtHiveString::AsciiExtended(key_name_bytes))
        } else {
            Ok(NtHiveString::Utf16LE(key_name_bytes))
        }
    }

    pub fn subkeys(&self) -> Option<Result<SubkeysList<&Hive<B>, B>>> {
        let header = self.header();
        let subkeys_list_offset = header.subkeys_list_offset.get();
        if subkeys_list_offset == u32::MAX {
            // This Key Node has no subkeys.
            return None;
        }

        let cell_range = iter_try!(self.hive.cell_range_from_data_offset(subkeys_list_offset));
        Some(SubkeysList::new(&self.hive, cell_range))
    }

    fn validate_signature(&self) -> Result<()> {
        let header = self.header();
        let signature = &header.signature;
        let expected_signature = b"nk";

        if signature == expected_signature {
            Ok(())
        } else {
            Err(NtHiveError::InvalidTwoByteSignature {
                offset: self.hive.offset_of_field(signature),
                expected: expected_signature,
                actual: *signature,
            })
        }
    }
}

impl<H, B> KeyNode<H, B>
where
    H: DerefMut<Target = Hive<B>>,
    B: ByteSliceMut,
{
    fn header_mut(&mut self) -> LayoutVerified<&mut [u8], KeyNodeHeader> {
        LayoutVerified::new(&mut self.hive.data[self.header_range.clone()]).unwrap()
    }

    pub(crate) fn clear_volatile_subkeys(&mut self) -> Result<()> {
        let mut header = self.header_mut();
        header.volatile_subkey_count.set(0);

        if let Some(subkeys_result) = self.subkeys_mut() {
            let mut subkeys = subkeys_result?;
            let mut iter = subkeys.iter_mut()?;
            while let Some(subkey) = iter.next() {
                subkey?.clear_volatile_subkeys()?;
            }
        }

        Ok(())
    }

    pub(crate) fn subkeys_mut(&mut self) -> Option<Result<SubkeysList<&mut Hive<B>, B>>> {
        let header = self.header();
        let subkeys_list_offset = header.subkeys_list_offset.get();
        if subkeys_list_offset == u32::MAX {
            // This Key Node has no subkeys.
            return None;
        }

        let cell_range = iter_try!(self.hive.cell_range_from_data_offset(subkeys_list_offset));
        Some(SubkeysList::new(&mut self.hive, cell_range))
    }
}
