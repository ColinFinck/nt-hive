// Copyright 2019-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use core::ops::Range;

macro_rules! iter_try {
    ($e:expr) => {
        match $e {
            Ok(x) => x,
            Err(e) => return Some(Err(e)),
        }
    };
}

/// Return a subrange of the given `Range<usize>` encompassing `byte_count`
/// bytes and starting at the beginning of `range`.
///
/// This function performs all necessary sanity checks to guarantee that `byte_count`
/// bytes are actually available within the boundaries of the given `range`.
/// If that is not the case, `None` is returned.
pub(crate) fn byte_subrange(range: &Range<usize>, byte_count: usize) -> Option<Range<usize>> {
    // Guard against integer overflows.
    let subrange_end = range.start.checked_add(byte_count)?;

    // Guard against exceeding the boundaries of the given range.
    if subrange_end > range.end {
        return None;
    }

    Some(range.start..subrange_end)
}

#[cfg(test)]
pub mod tests {
    use std::fs::File;
    use std::io::Read;

    pub fn testhive_vec() -> Vec<u8> {
        let mut buffer = Vec::new();
        File::open("testdata/testhive")
            .unwrap()
            .read_to_end(&mut buffer)
            .unwrap();
        buffer
    }
}
