// Copyright 2019-2025 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use thiserror::Error;

use crate::key_value::KeyValueDataType;

/// Central result type of nt-hive.
pub type Result<T, E = NtHiveError> = core::result::Result<T, E>;

/// Central error type of nt-hive.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum NtHiveError {
    #[error("The checksum in the base block should be {expected}, but it is {actual}")]
    InvalidChecksum { expected: u32, actual: u32 },
    #[error("The data at offset {offset:#010x} should have a size of {expected} bytes, but it only has {actual} bytes")]
    InvalidDataSize {
        offset: usize,
        expected: usize,
        actual: usize,
    },
    #[error("The 4-byte signature field at offset {offset:#010x} should contain {expected:?}, but it contains {actual:?}")]
    InvalidFourByteSignature {
        offset: usize,
        expected: &'static [u8],
        actual: [u8; 4],
    },
    #[error("The struct at offset {offset:#010x} should have a size of {expected} bytes, but only {actual} bytes are left in the slice")]
    InvalidHeaderSize {
        offset: usize,
        expected: usize,
        actual: usize,
    },
    #[error("Expected one of the key value data types {expected:?}, but found {actual:?}")]
    InvalidKeyValueDataType {
        expected: &'static [KeyValueDataType],
        actual: KeyValueDataType,
    },
    #[error("The size field at offset {offset:#010x} specifies {expected} bytes, but only {actual} bytes are left in the slice")]
    InvalidSizeField {
        offset: usize,
        expected: usize,
        actual: usize,
    },
    #[error("The size field at offset {offset:#010x} specifies {size} bytes, but they are not aligned to the expected {expected_alignment} bytes")]
    InvalidSizeFieldAlignment {
        offset: usize,
        size: usize,
        expected_alignment: usize,
    },
    #[error("The 2-byte signature field at offset {offset:#010x} should contain {expected:?}, but it contains {actual:?}")]
    InvalidTwoByteSignature {
        offset: usize,
        expected: &'static [u8],
        actual: [u8; 2],
    },
    #[error("The sequence numbers in the base block do not match ({primary} != {secondary})")]
    SequenceNumberMismatch { primary: u32, secondary: u32 },
    #[error("The cell at offset {offset:#010x} with a size of {size} bytes is unallocated")]
    UnallocatedCell { offset: usize, size: i32 },
    #[error(
        "The clustering factor in the base block is expected to be {expected}, but it is {actual}"
    )]
    UnsupportedClusteringFactor { expected: u32, actual: u32 },
    #[error("The file format in the base block is expected to be {expected}, but it is {actual}")]
    UnsupportedFileFormat { expected: u32, actual: u32 },
    #[error("The file type in the base block is expected to be {expected}, but it is {actual}")]
    UnsupportedFileType { expected: u32, actual: u32 },
    #[error("The key value data type at offset {offset:#010x} is {actual:#010x}, which is not supported")]
    UnsupportedKeyValueDataType { offset: usize, actual: u32 },
    #[error("The version in the base block ({major}.{minor}) is unsupported")]
    UnsupportedVersion { major: u32, minor: u32 },
}
