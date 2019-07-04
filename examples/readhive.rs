// Copyright 2019 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-3.0-or-later

use nt_hive::*;
use std::env;
use std::fs::File;
use std::io;
use std::io::Read;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: readhive <FILENAME>");
        return Ok(());
    }

    let filename = &args[1];
    let mut f = File::open(filename)?;
    let mut buffer = Vec::<u8>::new();
    f.read_to_end(&mut buffer)?;

    let hive = Hive::from_vec(buffer);
    println!("Validation Result: {:?}", hive.validate());
    Ok(())
}
