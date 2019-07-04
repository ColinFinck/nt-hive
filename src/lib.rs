// Copyright 2019 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::convert::TryInto;
use core::{mem, u32};

#[allow(dead_code)]
#[repr(u32)]
enum HiveMinorVersions {
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
    hive_data: Vec<u8>,
}

#[derive(Debug)]
pub enum HiveError {
    InvalidChecksum,
    InvalidDataSize,
    InvalidRootCellOffset,
    InvalidSignature,
    SequenceMismatch,
    UnsupportedClusteringFactor,
    UnsupportedFileFormat,
    UnsupportedFileType,
    UnsupportedVersion,
}

impl Hive {
    fn base_block(&self) -> &HiveBaseBlock {
        let base_block_size = mem::size_of::<HiveBaseBlock>();
        let base_block_slice = &self.hive_data[..base_block_size];
        let base_block = unsafe { &*(base_block_slice.as_ptr() as *const HiveBaseBlock) };
        base_block
    }

    pub fn from_vec(hive_data: Vec<u8>) -> Self {
        Self {
            hive_data: hive_data,
        }
    }

    pub fn major_version(&self) -> u32 {
        let base_block = self.base_block();
        u32::from_le(base_block.major_version)
    }

    pub fn minor_version(&self) -> u32 {
        let base_block = self.base_block();
        u32::from_le(base_block.minor_version)
    }

    pub fn validate(&self) -> Result<(), HiveError> {
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

    pub fn validate_checksum(&self) -> Result<(), HiveError> {
        let base_block = self.base_block();

        // TODO: Replace this once Rust has an integrated offset_of function/macro.
        let checksum_offset =
            unsafe { &base_block.checksum as *const _ as usize - base_block as *const _ as usize };

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
        if base_block.checksum == calculated_checksum {
            Ok(())
        } else {
            Err(HiveError::InvalidChecksum)
        }
    }

    pub fn validate_clustering_factor(&self) -> Result<(), HiveError> {
        let base_block = self.base_block();
        let clustering_factor = u32::from_le(base_block.clustering_factor);
        if clustering_factor == 1 {
            Ok(())
        } else {
            Err(HiveError::UnsupportedClusteringFactor)
        }
    }

    pub fn validate_data_size(&self) -> Result<(), HiveError> {
        let base_block = self.base_block();
        let data_size = u32::from_le(base_block.data_size) as usize;
        if mem::size_of::<HiveBaseBlock>() + data_size <= self.hive_data.len() {
            Ok(())
        } else {
            Err(HiveError::InvalidDataSize)
        }
    }

    pub fn validate_file_format(&self) -> Result<(), HiveError> {
        let base_block = self.base_block();
        let file_format = u32::from_le(base_block.file_format);
        if file_format == HiveFileFormats::Memory as u32 {
            Ok(())
        } else {
            Err(HiveError::UnsupportedFileFormat)
        }
    }

    pub fn validate_file_type(&self) -> Result<(), HiveError> {
        let base_block = self.base_block();
        let file_type = u32::from_le(base_block.file_type);
        if file_type == HiveFileTypes::Primary as u32 {
            Ok(())
        } else {
            Err(HiveError::UnsupportedFileType)
        }
    }

    pub fn validate_root_cell_offset(&self) -> Result<(), HiveError> {
        let base_block = self.base_block();
        let root_cell_offset = u32::from_le(base_block.root_cell_offset) as usize;
        if mem::size_of::<HiveBaseBlock>() + root_cell_offset <= self.hive_data.len() {
            Ok(())
        } else {
            Err(HiveError::InvalidRootCellOffset)
        }
    }

    pub fn validate_sequence_numbers(&self) -> Result<(), HiveError> {
        let base_block = self.base_block();
        if base_block.primary_sequence_number == base_block.secondary_sequence_number {
            Ok(())
        } else {
            Err(HiveError::SequenceMismatch)
        }
    }

    pub fn validate_signature(&self) -> Result<(), HiveError> {
        let base_block = self.base_block();
        if &base_block.signature == b"regf" {
            Ok(())
        } else {
            Err(HiveError::InvalidSignature)
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
