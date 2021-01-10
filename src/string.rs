// Copyright 2019-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use core::char;
use core::convert::TryInto;
use core::fmt;

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Zero-copy representation of a string stored in hive data.
/// Can be either in ASCII or UTF-16 (Little-Endian).
///
/// This allows to work with the string without performing any allocations or conversions.
/// If the `alloc` feature is enabled, [`to_string_checked`](NtHiveString::to_string_checked) and
/// [`to_string_lossy`](NtHiveString::to_string_lossy) can be used to to retrieve a `String`.
#[derive(Debug, Eq, PartialEq)]
pub enum NtHiveString<'a> {
    /// A byte stream where each byte is one of the 128 ASCII characters.
    /// Each byte can simply be casted to a [`prim@char`].
    Ascii(&'a [u8]),
    /// A byte stream where every two bytes make up a UTF-16 code point in little-endian order.
    /// Use [`u16::from_le_bytes`] and [`char::decode_utf16`] if you want to get a stream of [`prim@char`]s.
    Utf16LE(&'a [u8]),
}

impl<'a> NtHiveString<'a> {
    /// Checks that two strings are an ASCII case-insensitive match.
    #[inline]
    pub fn eq_ignore_ascii_case(&self, other: &str) -> bool {
        match self {
            Self::Ascii(bytes) => bytes.eq_ignore_ascii_case(other.as_bytes()),
            Self::Utf16LE(bytes) => {
                let u16_iter = bytes
                    .chunks_exact(2)
                    .map(|two_bytes| u16::from_le_bytes(two_bytes.try_into().unwrap()));
                let mut utf16_iter = char::decode_utf16(u16_iter);
                let mut other_iter = other.chars();

                loop {
                    match (utf16_iter.next(), other_iter.next()) {
                        (Some(Ok(utf16_char)), Some(other_char)) => {
                            // We have two valid characters to compare.
                            if !utf16_char.eq_ignore_ascii_case(&other_char) {
                                return false;
                            }
                        }
                        (None, None) => {
                            // We made it until the end of both strings, so they must be equal.
                            return true;
                        }
                        _ => {
                            // One string is longer than the other or we encountered an UTF-16 decoding error.
                            return false;
                        }
                    }
                }
            }
        }
    }

    #[inline]
    fn eq_str(&self, other: &str) -> bool {
        match self {
            Self::Ascii(bytes) => *bytes == other.as_bytes(),
            Self::Utf16LE(bytes) => {
                let u16_iter = bytes
                    .chunks_exact(2)
                    .map(|two_bytes| u16::from_le_bytes(two_bytes.try_into().unwrap()));
                let mut utf16_iter = char::decode_utf16(u16_iter);
                let mut other_iter = other.chars();

                loop {
                    match (utf16_iter.next(), other_iter.next()) {
                        (Some(Ok(utf16_char)), Some(other_char)) => {
                            // We have two valid characters to compare.
                            if utf16_char != other_char {
                                return false;
                            }
                        }
                        (None, None) => {
                            // We made it until the end of both strings, so they must be equal.
                            return true;
                        }
                        _ => {
                            // One string is longer than the other or we encountered an UTF-16 decoding error.
                            return false;
                        }
                    }
                }
            }
        }
    }

    /// Returns `true` if `self` has a length of zero bytes.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the length of `self`.
    ///
    /// This length is in bytes, not characters! In other words,
    /// it may not be what a human considers the length of the string.
    #[inline]
    pub const fn len(&self) -> usize {
        match self {
            Self::Ascii(bytes) => bytes.len(),
            Self::Utf16LE(bytes) => bytes.len(),
        }
    }

    /// Attempts to convert `self` to an owned `String`.
    /// Returns `Some(String)` if all characters could be converted successfully or `None` if a decoding error occurred.
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn to_string_checked(&self) -> Option<String> {
        match self {
            Self::Ascii(bytes) => String::from_utf8(bytes.to_vec()).ok(),
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

    /// Converts `self` to an owned `String`, replacing invalid data with the replacement character (U+FFFD).
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn to_string_lossy(&self) -> String {
        match self {
            Self::Ascii(bytes) => String::from_utf8_lossy(bytes).into_owned(),
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

impl<'a> fmt::Display for NtHiveString<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ascii(bytes) => {
                for ascii_byte in bytes.iter() {
                    let utf8_char = if ascii_byte.is_ascii() {
                        *ascii_byte as char
                    } else {
                        char::REPLACEMENT_CHARACTER
                    };
                    utf8_char.fmt(f)?;
                }
            }
            Self::Utf16LE(bytes) => {
                let u16_iter = bytes
                    .chunks_exact(2)
                    .map(|two_bytes| u16::from_le_bytes(two_bytes.try_into().unwrap()));
                let utf16_iter =
                    char::decode_utf16(u16_iter).map(|x| x.unwrap_or(char::REPLACEMENT_CHARACTER));

                for utf16_char in utf16_iter {
                    utf16_char.fmt(f)?;
                }
            }
        }

        Ok(())
    }
}

impl<'a> PartialEq<&str> for NtHiveString<'a> {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.eq_str(other)
    }
}

impl<'a> PartialEq<NtHiveString<'a>> for &str {
    #[inline]
    fn eq(&self, other: &NtHiveString<'a>) -> bool {
        other.eq_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eq() {
        assert_eq!(NtHiveString::Ascii(b"Hello"), "Hello");
        assert_eq!(
            NtHiveString::Utf16LE(&[b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0]),
            "Hello"
        );
        assert_ne!(NtHiveString::Ascii(b"Hello"), "hello");
        assert_ne!(
            NtHiveString::Utf16LE(&[b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0]),
            "hello"
        );
        assert_ne!(NtHiveString::Ascii(b"Hello"), "Hell");
        assert_ne!(
            NtHiveString::Utf16LE(&[b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0]),
            "Hell"
        );
    }

    #[test]
    fn test_eq_ignore_ascii_case() {
        assert!(NtHiveString::Ascii(b"Hello").eq_ignore_ascii_case("Hello"));
        assert!(
            NtHiveString::Utf16LE(&[b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0])
                .eq_ignore_ascii_case("Hello")
        );
        assert!(NtHiveString::Ascii(b"Hello").eq_ignore_ascii_case("hello"));
        assert!(
            NtHiveString::Utf16LE(&[b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0])
                .eq_ignore_ascii_case("hello")
        );
        assert!(!NtHiveString::Ascii(b"Hello").eq_ignore_ascii_case("Hell"));
        assert!(
            !NtHiveString::Utf16LE(&[b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0])
                .eq_ignore_ascii_case("Hell")
        );
    }

    #[test]
    fn test_is_empty() {
        assert!(NtHiveString::Ascii(b"").is_empty());
        assert!(NtHiveString::Utf16LE(&[]).is_empty());
        assert!(!NtHiveString::Ascii(b"Hello").is_empty());
        assert!(!NtHiveString::Utf16LE(&[b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0]).is_empty());
    }

    #[test]
    fn test_len() {
        assert_eq!(NtHiveString::Ascii(b"Hello").len(), 5);
        assert_eq!(
            NtHiveString::Utf16LE(&[b'H', 0, b'e', 0, b'l', 0, b'l', 0, b'o', 0]).len(),
            10
        );
    }
}
