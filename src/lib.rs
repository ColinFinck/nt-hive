// Copyright 2019-2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

//! # nt-hive
//! The *nt-hive* Rust crate provides a comfortable and safe interface for accessing keys, values, and data stored in *hive* files.
//! Hive files can be found in `C:\Windows\system32\config` and store what is commonly called the *Windows registry*.
//! This crate supports the hive format that is used from Windows NT 4.0 up to the current Windows 10.
//!
//! # Getting started
//! 1. Create a [`Hive`] structure from hive data by calling [`Hive::new`].
//! 2. Retrieve the root [`KeyNode`] via [`Hive::root_key_node`].
//! 3. Move to a subkey via [`KeyNode::subkey`], [`KeyNode::subkeys`] or [`KeyNode::subpath`].
//! 4. Get an interesting value using [`KeyNode::value`] or [`KeyNode::values`].

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

#[macro_use]
mod helpers;

mod big_data;
mod error;
mod hive;
mod index_root;
mod key_node;
mod key_value;
mod key_values_list;
mod leaf;
mod string;
mod subkeys_list;

pub use crate::big_data::*;
pub use crate::error::*;
pub use crate::hive::*;
pub use crate::index_root::*;
pub use crate::key_node::*;
pub use crate::key_value::*;
pub use crate::key_values_list::*;
pub use crate::leaf::*;
pub use crate::string::*;
pub use crate::subkeys_list::*;

#[cfg(feature = "alloc")]
extern crate alloc;
