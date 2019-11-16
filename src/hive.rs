// Copyright 2019 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::key::Key;
use core::convert::TryInto;
use core::{mem, u32};
use memoffset::{offset_of, span_of};

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

#[repr(C, packed)]
struct HiveBaseBlock {
    signature: [u8; 4],
    primary_sequence_number: u32,
    secondary_sequence_number: u32,
    timestamp: u64,
    major_version: u32,
    minor_version: u32,
    file_type: u32,
    file_format: u32,
    root_cell_offset: u32,
    data_size: u32,
    clustering_factor: u32,
    file_name: [u16; 32],
    reserved1: [u8; 396],
    checksum: u32,
    reserved2: [u8; 3576],
    boot_type: u32,
    boot_recover: u32,
}

#[repr(C, packed)]
struct HiveBin {
    signature: [u8; 4],
    offset: u32,
    size: u32,
    reserved: [u8; 8],
    timestamp: u64,
    spare: u32,
}

#[repr(C, packed)]
struct HiveCell {
    size: i32,
}

pub struct Hive {
    pub(crate) hive_data: Vec<u8>,
}

#[derive(Debug)]
pub enum HiveError {
    InvalidBaseBlockSize { actual: usize, expected: usize },
    InvalidChecksum { actual: u32, expected: u32 },
    InvalidDataSize { actual: usize, expected: usize },
    InvalidRootCellOffset,
    InvalidSignature { actual: [u8; 4], expected: [u8; 4] },
    SequenceMismatch { primary: u32, secondary: u32 },
    UnsupportedClusteringFactor { clustering_factor: u32 },
    UnsupportedFileFormat,
    UnsupportedFileType,
    UnsupportedVersion,
}

impl Hive {
    /// Converts a vector of bytes to a `Hive`.
    ///
    /// This function calls [`validate`] on the passed bytes to check the
    /// hive's basic block and rejects any hive that fails validation.
    ///
    /// If you are writing an application to repair a corrupted NT hive, you may
    /// want to use [`from_vec_unchecked`] instead.
    pub fn from_vec(hive_data: Vec<u8>) -> Result<Self, HiveError> {
        let hive = Self {
            hive_data: hive_data,
        };
        hive.validate()?;
        Ok(hive)
    }

    /// Converts a vector of bytes to a `Hive`, without validation.
    ///
    /// This enables you to work on a corrupted NT hive.
    /// Note that due to the skipped validation, subsequent functions may panic
    /// if they try to access data outside the boundary of the passed vector.
    /// You are advised to use [`from_vec`] whenever possible.
    pub fn from_vec_unchecked(hive_data: Vec<u8>) -> Self {
        Self {
            hive_data: hive_data,
        }
    }

    /// Returns the major version of this hive.
    ///
    /// The only known value is `1`.
    pub fn major_version(&self) -> u32 {
        let bytes = &self.hive_data[span_of!(HiveBaseBlock, major_version)];
        u32::from_le_bytes(bytes.try_into().unwrap())
    }

    /// Returns the minor version of this hive.
    ///
    /// Known values can be found in [`HiveMinorVersions`].
    pub fn minor_version(&self) -> u32 {
        let bytes = &self.hive_data[span_of!(HiveBaseBlock, minor_version)];
        u32::from_le_bytes(bytes.try_into().unwrap())
    }

    pub fn root_key(&self) -> Key {
        let hivebin_offset = mem::size_of::<HiveBaseBlock>();
        let root_cell_offset_bytes = &self.hive_data[span_of!(HiveBaseBlock, root_cell_offset)];
        let root_cell_offset = u32::from_le_bytes(root_cell_offset_bytes.try_into().unwrap());
        let cell_offset = hivebin_offset + root_cell_offset as usize;

        Key {
            hive: self,
            hivebin_offset: hivebin_offset,
            cell_offset: cell_offset,
        }
    }

    pub fn validate(&self) -> Result<(), HiveError> {
        self.validate_base_block_size()?;
        self.validate_signature()?;
        self.validate_sequence_numbers()?;
        self.validate_version()?;
        self.validate_file_type()?;
        self.validate_file_format()?;
        self.validate_root_cell_offset()?;
        self.validate_data_size()?;
        self.validate_clustering_factor()?;
        self.validate_checksum()?;
        Ok(())
    }

    pub fn validate_base_block_size(&self) -> Result<(), HiveError> {
        if mem::size_of::<HiveBaseBlock>() <= self.hive_data.len() {
            Ok(())
        } else {
            Err(HiveError::InvalidBaseBlockSize {
                actual: self.hive_data.len(),
                expected: mem::size_of::<HiveBaseBlock>(),
            })
        }
    }

    pub fn validate_checksum(&self) -> Result<(), HiveError> {
        let checksum_offset = offset_of!(HiveBaseBlock, checksum);

        // Calculate the XOR-32 checksum of all bytes preceding the checksum field.
        let mut calculated_checksum = 0;
        for dword_bytes in self.hive_data[..checksum_offset].chunks(mem::size_of::<u32>()) {
            let dword = u32::from_le_bytes(dword_bytes.try_into().unwrap());
            calculated_checksum ^= dword;
        }

        if calculated_checksum == 0 {
            calculated_checksum += 1;
        } else if calculated_checksum == u32::MAX {
            calculated_checksum -= 1;
        }

        // Compare the calculated checksum with the stored one.
        let checksum_bytes = &self.hive_data[span_of!(HiveBaseBlock, checksum)];
        let checksum = u32::from_le_bytes(checksum_bytes.try_into().unwrap());

        if checksum == calculated_checksum {
            Ok(())
        } else {
            Err(HiveError::InvalidChecksum {
                actual: calculated_checksum,
                expected: checksum,
            })
        }
    }

    pub fn validate_clustering_factor(&self) -> Result<(), HiveError> {
        let clustering_factor_bytes = &self.hive_data[span_of!(HiveBaseBlock, clustering_factor)];
        let clustering_factor = u32::from_le_bytes(clustering_factor_bytes.try_into().unwrap());

        if clustering_factor == 1 {
            Ok(())
        } else {
            Err(HiveError::UnsupportedClusteringFactor {
                clustering_factor: clustering_factor,
            })
        }
    }

    pub fn validate_data_size(&self) -> Result<(), HiveError> {
        let data_size_bytes = &self.hive_data[span_of!(HiveBaseBlock, data_size)];
        let data_size = u32::from_le_bytes(data_size_bytes.try_into().unwrap());
        let expected_size = mem::size_of::<HiveBaseBlock>() + data_size as usize;

        if expected_size <= self.hive_data.len() {
            Ok(())
        } else {
            Err(HiveError::InvalidDataSize {
                actual: self.hive_data.len(),
                expected: expected_size,
            })
        }
    }

    pub fn validate_file_format(&self) -> Result<(), HiveError> {
        let file_format_bytes = &self.hive_data[span_of!(HiveBaseBlock, file_format)];
        let file_format = u32::from_le_bytes(file_format_bytes.try_into().unwrap());

        if file_format == HiveFileFormats::Memory as u32 {
            Ok(())
        } else {
            Err(HiveError::UnsupportedFileFormat)
        }
    }

    pub fn validate_file_type(&self) -> Result<(), HiveError> {
        let file_type_bytes = &self.hive_data[span_of!(HiveBaseBlock, file_type)];
        let file_type = u32::from_le_bytes(file_type_bytes.try_into().unwrap());
        if file_type == HiveFileTypes::Primary as u32 {
            Ok(())
        } else {
            Err(HiveError::UnsupportedFileType)
        }
    }

    pub fn validate_root_cell_offset(&self) -> Result<(), HiveError> {
        let root_cell_offset_bytes = &self.hive_data[span_of!(HiveBaseBlock, root_cell_offset)];
        let root_cell_offset = u32::from_le_bytes(root_cell_offset_bytes.try_into().unwrap());

        if mem::size_of::<HiveBaseBlock>() + root_cell_offset as usize <= self.hive_data.len() {
            Ok(())
        } else {
            Err(HiveError::InvalidRootCellOffset)
        }
    }

    pub fn validate_sequence_numbers(&self) -> Result<(), HiveError> {
        let primary_sequence_number_bytes =
            &self.hive_data[span_of!(HiveBaseBlock, primary_sequence_number)];
        let primary_sequence_number =
            u32::from_le_bytes(primary_sequence_number_bytes.try_into().unwrap());

        let secondary_sequence_number_bytes =
            &self.hive_data[span_of!(HiveBaseBlock, secondary_sequence_number)];
        let secondary_sequence_number =
            u32::from_le_bytes(secondary_sequence_number_bytes.try_into().unwrap());

        if primary_sequence_number == secondary_sequence_number {
            Ok(())
        } else {
            Err(HiveError::SequenceMismatch {
                primary: primary_sequence_number,
                secondary: secondary_sequence_number,
            })
        }
    }

    pub fn validate_signature(&self) -> Result<(), HiveError> {
        let signature = &self.hive_data[span_of!(HiveBaseBlock, signature)];
        let expected_signature = b"regf";

        if signature == expected_signature {
            Ok(())
        } else {
            Err(HiveError::InvalidSignature {
                actual: signature.try_into().unwrap(),
                expected: *expected_signature,
            })
        }
    }

    pub fn validate_version(&self) -> Result<(), HiveError> {
        // We only support NT4 hives as a start.
        if self.major_version() == 1 && self.minor_version() == HiveMinorVersions::WindowsNT4 as u32
        {
            Ok(())
        } else {
            Err(HiveError::UnsupportedVersion)
        }
    }
}
