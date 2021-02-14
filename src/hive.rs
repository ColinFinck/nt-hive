// Copyright 2019-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use crate::error::{NtHiveError, Result};
use crate::helpers::byte_subrange;
use crate::key_node::KeyNode;
use ::byteorder::LittleEndian;
use core::convert::TryInto;
use core::ops::Range;
use core::{mem, u32};
use memoffset::offset_of;
use zerocopy::*;

#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct CellHeader {
    size: I32<LittleEndian>,
}

#[repr(u32)]
pub enum HiveMinorVersions {
    WindowsNT3_1Beta = 0,
    WindowsNT3_1 = 1,
    WindowsNT3_5 = 2,
    WindowsNT4 = 3,
    WindowsXPBeta = 4,
    WindowsXP = 5,
    WindowsVista = 6,
}

#[allow(dead_code)]
#[repr(u32)]
enum HiveFileTypes {
    Primary = 0,
    Log = 1,
    External = 2,
}

#[repr(u32)]
enum HiveFileFormats {
    Memory = 1,
}

#[allow(dead_code)]
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
struct HiveBaseBlock {
    signature: [u8; 4],
    primary_sequence_number: U32<LittleEndian>,
    secondary_sequence_number: U32<LittleEndian>,
    timestamp: U64<LittleEndian>,
    major_version: U32<LittleEndian>,
    minor_version: U32<LittleEndian>,
    file_type: U32<LittleEndian>,
    file_format: U32<LittleEndian>,
    root_cell_offset: U32<LittleEndian>,
    data_size: U32<LittleEndian>,
    clustering_factor: U32<LittleEndian>,
    file_name: [U16<LittleEndian>; 32],
    padding_1: [u8; 256],
    padding_2: [u8; 128],
    padding_3: [u8; 12],
    checksum: U32<LittleEndian>,
    padding_4: [u8; 2048],
    padding_5: [u8; 1024],
    padding_6: [u8; 256],
    padding_7: [u8; 236],
    padding_8: [u8; 12],
    boot_type: U32<LittleEndian>,
    boot_recover: U32<LittleEndian>,
}

pub struct Hive<B: ByteSlice> {
    base_block: LayoutVerified<B, HiveBaseBlock>,
    pub(crate) data: B,
}

impl<B> Hive<B>
where
    B: ByteSlice,
{
    /// Converts a vector of bytes to a `Hive`.
    ///
    /// This function calls [`validate`] on the passed bytes to check the
    /// hive's basic block and rejects any hive that fails validation.
    pub fn new(bytes: B) -> Result<Self> {
        let length = bytes.len();
        let (base_block, data) = LayoutVerified::new_from_prefix(bytes).ok_or_else(|| {
            NtHiveError::InvalidHeaderSize {
                offset: 0,
                expected: mem::size_of::<HiveBaseBlock>(),
                actual: length,
            }
        })?;

        let hive = Self { base_block, data };
        hive.validate()?;

        Ok(hive)
    }

    pub(crate) fn cell_range_from_data_offset(&self, data_offset: u32) -> Result<Range<usize>> {
        // Only valid data offsets are accepted here.
        assert!(data_offset != u32::MAX);

        // Accept only u32 data offsets, but convert them into usize right away for
        // slice range operations and fearless calculations.
        let data_offset = data_offset as usize;

        // Get the cell header.
        let remaining_range = data_offset..self.data.len();
        let header_range = byte_subrange(&remaining_range, mem::size_of::<CellHeader>())
            .ok_or_else(|| NtHiveError::InvalidHeaderSize {
                offset: self.offset_of_data_offset(data_offset),
                expected: mem::size_of::<CellHeader>(),
                actual: remaining_range.len(),
            })?;
        let cell_data_offset = header_range.end;

        // After the check above, the following operation must succeed, so we can just `unwrap`.
        let header = LayoutVerified::<&[u8], CellHeader>::new(&self.data[header_range]).unwrap();
        let cell_size = header.size.get();

        // A cell with size > 0 is unallocated and shouldn't be processed any further by us.
        if cell_size > 0 {
            return Err(NtHiveError::UnallocatedCell {
                offset: self.offset_of_data_offset(data_offset),
                size: cell_size,
            });
        }
        let cell_size = cell_size.abs() as usize;

        // The cell size must be a multiple of 8 bytes
        let expected_alignment = 8;
        if cell_size % expected_alignment != 0 {
            return Err(NtHiveError::InvalidSizeFieldAlignment {
                offset: self.offset_of_field(&header.size),
                size: cell_size,
                expected_alignment,
            });
        }

        // Get the actual data range and verify that it's inside our hive data.
        let remaining_range = cell_data_offset..self.data.len();
        let cell_data_range = byte_subrange(&remaining_range, cell_size).ok_or_else(|| {
            NtHiveError::InvalidSizeField {
                offset: self.offset_of_field(&header.size),
                expected: cell_size,
                actual: remaining_range.len(),
            }
        })?;

        Ok(cell_data_range)
    }

    /// Calculate a field's offset from the very beginning of the hive bytes.
    ///
    /// Note that this function primarily exists to provide absolute hive file offsets when reporting errors.
    /// It cannot be used to index into the hive bytes, because they are initially split into `base_block`
    /// and `data`.
    pub(crate) fn offset_of_field<T>(&self, field: &T) -> usize {
        let field_address = field as *const T as usize;
        let base_address = self.base_block.bytes().as_ptr() as usize;

        assert!(field_address > base_address);
        field_address - base_address
    }

    /// Calculate a data offset's offset from the very beginning of the hive bytes.
    pub(crate) fn offset_of_data_offset(&self, data_offset: usize) -> usize {
        data_offset + mem::size_of::<HiveBaseBlock>()
    }

    /// Returns the major version of this hive.
    ///
    /// The only known value is `1`.
    pub fn major_version(&self) -> u32 {
        self.base_block.major_version.get()
    }

    /// Returns the minor version of this hive.
    ///
    /// Known values can be found in [`HiveMinorVersions`].
    pub fn minor_version(&self) -> u32 {
        self.base_block.minor_version.get()
    }

    /// Returns the root [`KeyNode`] of this hive.
    pub fn root_key_node(&self) -> Result<KeyNode<&Self, B>> {
        let root_cell_offset = self.base_block.root_cell_offset.get();
        let cell_range = self.cell_range_from_data_offset(root_cell_offset)?;
        KeyNode::from_cell_range(self, cell_range)
    }

    /// Performs all validations on this hive.
    fn validate(&self) -> Result<()> {
        self.validate_signature()?;
        self.validate_sequence_numbers()?;
        self.validate_version()?;
        self.validate_file_type()?;
        self.validate_file_format()?;
        self.validate_data_size()?;
        self.validate_clustering_factor()?;
        self.validate_checksum()?;
        Ok(())
    }

    fn validate_checksum(&self) -> Result<()> {
        let checksum_offset = offset_of!(HiveBaseBlock, checksum);

        // Calculate the XOR-32 checksum of all bytes preceding the checksum field.
        let mut calculated_checksum = 0;
        for dword_bytes in self.base_block.bytes()[..checksum_offset].chunks(mem::size_of::<u32>())
        {
            let dword = u32::from_le_bytes(dword_bytes.try_into().unwrap());
            calculated_checksum ^= dword;
        }

        if calculated_checksum == 0 {
            calculated_checksum += 1;
        } else if calculated_checksum == u32::MAX {
            calculated_checksum -= 1;
        }

        // Compare the calculated checksum with the stored one.
        let checksum = self.base_block.checksum.get();
        if checksum == calculated_checksum {
            Ok(())
        } else {
            Err(NtHiveError::InvalidChecksum {
                expected: checksum,
                actual: calculated_checksum,
            })
        }
    }

    fn validate_clustering_factor(&self) -> Result<()> {
        let clustering_factor = self.base_block.clustering_factor.get();
        let expected_clustering_factor = 1;

        if clustering_factor == expected_clustering_factor {
            Ok(())
        } else {
            Err(NtHiveError::UnsupportedClusteringFactor {
                expected: expected_clustering_factor,
                actual: clustering_factor,
            })
        }
    }

    fn validate_data_size(&self) -> Result<()> {
        let data_size = self.base_block.data_size.get() as usize;
        let expected_alignment = 4096;

        // The data size must be a multiple of 4096 bytes
        if data_size % expected_alignment != 0 {
            return Err(NtHiveError::InvalidSizeFieldAlignment {
                offset: self.offset_of_field(&self.base_block.data_size),
                size: data_size,
                expected_alignment,
            });
        }

        // Does the size go beyond our hive data?
        if data_size > self.data.len() {
            return Err(NtHiveError::InvalidSizeField {
                offset: self.offset_of_field(&self.base_block.data_size),
                expected: data_size,
                actual: self.data.len(),
            });
        }

        Ok(())
    }

    fn validate_file_format(&self) -> Result<()> {
        let file_format = self.base_block.file_format.get();
        let expected_file_format = HiveFileFormats::Memory as u32;

        if file_format == expected_file_format {
            Ok(())
        } else {
            Err(NtHiveError::UnsupportedFileFormat {
                expected: expected_file_format,
                actual: file_format,
            })
        }
    }

    fn validate_file_type(&self) -> Result<()> {
        let file_type = self.base_block.file_type.get();
        let expected_file_type = HiveFileTypes::Primary as u32;

        if file_type == expected_file_type {
            Ok(())
        } else {
            Err(NtHiveError::UnsupportedFileType {
                expected: expected_file_type,
                actual: file_type,
            })
        }
    }

    fn validate_sequence_numbers(&self) -> Result<()> {
        let primary_sequence_number = self.base_block.primary_sequence_number.get();
        let secondary_sequence_number = self.base_block.secondary_sequence_number.get();

        if primary_sequence_number == secondary_sequence_number {
            Ok(())
        } else {
            Err(NtHiveError::SequenceNumberMismatch {
                primary: primary_sequence_number,
                secondary: secondary_sequence_number,
            })
        }
    }

    fn validate_signature(&self) -> Result<()> {
        let signature = &self.base_block.signature;
        let expected_signature = b"regf";

        if signature == expected_signature {
            Ok(())
        } else {
            Err(NtHiveError::InvalidFourByteSignature {
                offset: self.offset_of_field(signature),
                expected: expected_signature,
                actual: *signature,
            })
        }
    }

    fn validate_version(&self) -> Result<()> {
        let major = self.major_version();
        let minor = self.minor_version();

        if major == 1 && minor >= HiveMinorVersions::WindowsNT4 as u32 {
            Ok(())
        } else {
            Err(NtHiveError::UnsupportedVersion { major, minor })
        }
    }
}

impl<B> Hive<B>
where
    B: ByteSliceMut,
{
    /// Clear the `volatile_subkey_count` field of all key nodes recursively.
    /// This prepares the hive for being passed to an NT kernel during boot.
    ///
    /// See https://github.com/reactos/reactos/pull/1883 for more information.
    pub fn clear_volatile_subkeys(&mut self) -> Result<()> {
        let mut root_key_node = self.root_key_node_mut()?;
        root_key_node.clear_volatile_subkeys()
    }

    pub(crate) fn root_key_node_mut(&mut self) -> Result<KeyNode<&mut Self, B>> {
        let root_cell_offset = self.base_block.root_cell_offset.get();
        let cell_range = self.cell_range_from_data_offset(root_cell_offset)?;
        KeyNode::from_cell_range(self, cell_range)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_clear_volatile_subkeys() {
        // clear_volatile_subkeys traverses all subkeys, so this test just checks
        // that it doesn't crash during that process.
        let mut testhive = crate::helpers::tests::testhive_vec();
        let mut hive = Hive::new(testhive.as_mut()).unwrap();
        assert!(hive.clear_volatile_subkeys().is_ok());
    }
}
