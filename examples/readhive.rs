// Copyright 2019 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use nt_hive::*;
use std::env;
use std::fs::File;
use std::io::Read;

fn main() -> Result<(), String> {
    // Parse arguments.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: readhive <FILENAME>");
        return Ok(());
    }

    // Read the hive file.
    let filename = &args[1];
    let mut f = File::open(filename).map_err(|e| format!("Error opening hive file: {}", e))?;
    let mut buffer = Vec::<u8>::new();
    f.read_to_end(&mut buffer)
        .map_err(|e| format!("Error reading hive file: {}", e))?;

    // Parse the hive.
    let mut hive =
        Hive::new(buffer.as_mut()).map_err(|e| format!("Error parsing hive file: {}", e))?;

    // Only supported mutable action: Clear the volatile subkeys recursively.
    hive.clear_volatile_subkeys().unwrap();

    // Print the name of the root key node.
    let root_key = hive
        .root_key_node()
        .map_err(|e| format!("Error getting root key: {}", e))?;
    println!("{}", root_key.key_name().unwrap().to_string_lossy());

    // Print the names of subkeys of this node.
    let subkeys = root_key
        .subkeys()
        .unwrap()
        .map_err(|e| format!("Error getting subkeys: {}", e))?;
    let subkey_iter = subkeys
        .iter()
        .map_err(|e| format!("Error creating subkey iterator: {}", e))?;

    for subkey in subkey_iter {
        let key_node = subkey.map_err(|e| format!("Error enumerating key: {}", e))?;
        println!("- {}", key_node.key_name().unwrap().to_string_lossy());
    }

    Ok(())
}
