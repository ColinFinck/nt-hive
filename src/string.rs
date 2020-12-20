// Copyright 2019-2020 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

#[cfg(feature = "alloc")]
use {alloc::string::String, core::char, core::convert::TryInto};

/// Zero-copy representation of a string stored in a hive file.
/// Can be either in ASCII (possibly with extended codepage) or UTF-16 (Little-Endian).
///
/// This allows the caller to interpret the string characters, possibly using additional information
/// about the used ASCII codepage when writing the hive file.
/// If that is not needed and the `alloc` feature is enabled, [`to_string_checked`] and [`to_string_lossy`]
/// can be used to to directly retrieve a `String`.
#[derive(Debug)]
pub enum NtHiveString<'a> {
    AsciiExtended(&'a [u8]),
    Utf16LE(&'a [u8]),
}

impl<'a> NtHiveString<'a> {
    /// Attempts to convert the `NtHiveString` to an owned `String` (assuming UTF-8 if it's an [`AsciiExtended`] string).
    /// Returns `Some(String)` if all characters could be converted successfully or `None` if an error occurred.
    #[cfg(feature = "alloc")]
    pub fn to_string_checked(&self) -> Option<String> {
        match self {
            Self::AsciiExtended(bytes) => String::from_utf8(bytes.to_vec()).ok(),
            Self::Utf16LE(bytes) => {
                let u16_iter = bytes
                    .chunks_exact(2)
                    .map(|two_bytes| u16::from_le_bytes(two_bytes.try_into().unwrap()));
                char::decode_utf16(u16_iter)
                    .map(|x| x.ok())
                    .collect::<Option<String>>()
            }
        }
    }

    /// Converts the `NtHiveString` to an owned `String`, replacing invalid data with the replacement character (U+FFFD).
    /// Just as [`to_string_checked`], this function assumes UTF-8 for [`AsciiExtended`] strings.
    #[cfg(feature = "alloc")]
    pub fn to_string_lossy(&self) -> String {
        match self {
            Self::AsciiExtended(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            Self::Utf16LE(bytes) => {
                let u16_iter = bytes
                    .chunks_exact(2)
                    .map(|two_bytes| u16::from_le_bytes(two_bytes.try_into().unwrap()));
                char::decode_utf16(u16_iter)
                    .map(|x| x.unwrap_or(char::REPLACEMENT_CHARACTER))
                    .collect()
            }
        }
    }
}
