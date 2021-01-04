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

/// Return a subrange of the given `Range<usize>` encompassing `bytes_count`
/// bytes and starting at the beginning of `range`.
///
/// This function performs all necessary sanity checks to guarantee that `bytes_count`
/// bytes are actually available within the boundaries of the given `range`.
/// If that is not the case, `None` is returned.
pub(crate) fn bytes_subrange(range: &Range<usize>, bytes_count: usize) -> Option<Range<usize>> {
    // Guard against integer overflows.
    let subrange_end = range.start.checked_add(bytes_count)?;

    // Guard against exceeding the boundaries of the given range.
    if subrange_end > range.end {
        return None;
    }

    Some(range.start..subrange_end)
}
