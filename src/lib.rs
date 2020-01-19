// Copyright 2019-2020 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-3.0-or-later

mod fast_leaf;
mod hash_leaf;
mod hive;
mod index_leaf;
mod index_root;
mod key;

pub use crate::hive::*;
pub use crate::key::*;

#[derive(Debug)]
pub enum NtHiveError {
    InvalidBaseBlockSize {
        actual: usize,
        expected: usize,
    },
    InvalidChecksum {
        actual: u32,
        expected: u32,
    },
    InvalidDataSize {
        actual: usize,
        expected: usize,
    },
    InvalidRootCellOffset {
        actual_begin: usize,
        maximum_begin: usize,
    },
    InvalidSignature {
        actual: Vec<u8>,
        expected: Vec<u8>,
        offset: usize,
    },
    SequenceMismatch {
        primary: u32,
        secondary: u32,
    },
    UnsupportedClusteringFactor {
        clustering_factor: u32,
    },
    UnsupportedFileFormat,
    UnsupportedFileType,
    UnsupportedVersion,
}
