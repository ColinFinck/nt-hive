// Copyright 2019 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later

use nt_hive::*;
use std::env;
use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use zerocopy::*;

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
    let hive = Hive::new(buffer.as_ref()).map_err(|e| format!("Error parsing hive file: {}", e))?;

    // Print the name of the root key node.
    let root_key = hive
        .root_key_node()
        .map_err(|e| format!("Error getting root key: {}", e))?;
    println!("{}", root_key.name().unwrap().to_string_lossy());

    process_subkey(root_key, 0)?;

    Ok(())
}

fn process_subkey<H, B>(key_node: KeyNode<H, B>, level: usize) -> Result<(), String>
where
    H: Deref<Target = Hive<B>>,
    B: ByteSlice,
{
    // Print the names of subkeys of this node.
    if let Some(subkeys) = key_node.subkeys() {
        let subkeys = subkeys.map_err(|e| format!("Error getting subkeys: {}", e))?;

        for key_node in subkeys {
            let key_node = key_node.map_err(|e| format!("Error enumerating key: {}", e))?;
            let key_name = key_node
                .name()
                .map_err(|e| format!("Error getting key name: {}", e))?;

            for _i in 0..level {
                print!("  ");
            }
            println!("● {}", key_name);

            // Print the names of the values of this node.
            if let Some(value_iter) = key_node.values() {
                let value_iter =
                    value_iter.map_err(|e| format!("Error creating value iterator: {}", e))?;

                for value in value_iter {
                    let value = value.map_err(|e| format!("Error enumerating value: {}", e))?;

                    let mut value_name = value
                        .name()
                        .map_err(|e| format!("Error getting value name: {}", e))?
                        .to_string_lossy();
                    if value_name.is_empty() {
                        value_name.push_str("(Default)");
                    }

                    let value_type = value
                        .data_type()
                        .map_err(|e| format!("Error getting value type: {}", e))?;

                    // First line: Value Name, Data Type, and Data Size
                    for _i in 0..level {
                        print!("  ");
                    }
                    println!(
                        "  ○ {} - {:?} - {}",
                        value_name,
                        value_type,
                        value.data_size()
                    );

                    // Second line: The actual Value Data
                    for _i in 0..level {
                        print!("  ");
                    }
                    print!("    ");

                    match value_type {
                        KeyValueDataType::RegSZ | KeyValueDataType::RegExpandSZ => {
                            let string_data = value
                                .string_data()
                                .map_err(|e| format!("Error getting string data: {}", e))?;
                            println!("{}", string_data)
                        }
                        KeyValueDataType::RegBinary => {
                            let binary_data = value
                                .data()
                                .map_err(|e| format!("Error getting binary data: {}", e))?;
                            match binary_data {
                                KeyValueData::Small(data) => println!("{:?}", data),
                                KeyValueData::Big(_iter) => println!("BIG DATA"),
                            }
                        }
                        KeyValueDataType::RegDWord | KeyValueDataType::RegDWordBigEndian => {
                            let dword_data = value
                                .dword_data()
                                .map_err(|e| format!("Error getting DWORD data: {}", e))?;
                            println!("{}", dword_data)
                        }
                        KeyValueDataType::RegMultiSZ => {
                            let multi_string_data = value
                                .multi_string_data()
                                .map_err(|e| format!("Error getting multi string data: {}", e))?;
                            println!("{:?}", multi_string_data)
                        }
                        KeyValueDataType::RegQWord => {
                            let qword_data = value
                                .qword_data()
                                .map_err(|e| format!("Error getting QWORD data: {}", e))?;
                            println!("{}", qword_data)
                        }
                        _ => println!(),
                    }
                }
            }

            // Process subkeys.
            process_subkey(key_node, level + 1)?;
        }
    }

    Ok(())
}
