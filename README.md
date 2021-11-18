<img align="right" src="img/nt-hive.svg">

# nt-hive

[![crates.io](https://img.shields.io/crates/v/nt-hive)](https://crates.io/crates/nt-hive)
[![docs.rs](https://img.shields.io/docsrs/nt-hive)](https://docs.rs/nt-hive)
[![license: GPL-2.0-or-later](https://img.shields.io/crates/l/nt-hive)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

*by Colin Finck <<colin@reactos.org>>*

The *nt-hive* Rust crate provides a comfortable and safe interface for accessing keys, values, and data stored in *hive* files.
Hive files can be found in `C:\Windows\system32\config` and store what is commonly called the *Windows registry*.
This crate supports the hive format that is used from Windows NT 4.0 up to the current Windows 10.

nt-hive has been developed as part of a Rust bootloader project.
Its current feature set is therefore aligned to the needs of a ReactOS/Windows bootloader.

## Features
* Support for reading keys, values, and data from any byte slice containing hive data (i.e. anything that implements [`zerocopy::ByteSlice`](https://docs.rs/zerocopy/0.3.0/zerocopy/trait.ByteSlice.html)).
* Basic in-memory modifications of hive data (as [required for a bootloader](https://github.com/reactos/reactos/pull/1883)).
* Iterators for keys and values to enable writing idiomatic Rust code.
* Functions to find a specific subkey, subkey path, or value as efficient as possible (taking advantage of binary search for keys).
* Error propagation through a custom `NtHiveError` type that implements `Display`.  
  As a bootloader may hit corrupted hive files at some point, nt-hive outputs precise errors everywhere that refer to the faulty data byte.
* Full functionality even in a `no_std` environment (with `alloc`, some limitations without `alloc`).
* Static borrow checking everywhere. No mutexes or runtime borrowing.
* Zero-copy data representations wherever possible.
* No usage of `unsafe` anywhere. Checked arithmetic where needed.
* Platform and endian independence.

## Non-Goals
Full write support is currently not a goal for nt-hive.
This would require a wholly different architecture, where nt-hive loads a hive into linked in-memory data structures, keeps track of changes, and can write changes back to disk (possibly extending the on-disk file).
The current focus on read-only access allows for a simpler architecture.

## Examples
The following example reads the *List* value from the *ControlSet001\Control\ServiceGroupOrder* subkey of the *SYSTEM* hive, which is a real thing that happens during boot:

```rust,no_run
let mut buffer = Vec::new();
File::open("SYSTEM").unwrap().read_to_end(&mut buffer).unwrap();

let hive = Hive::new(buffer.as_ref()).unwrap();
let root_key_node = hive.root_key_node().unwrap();
let key_node = root_key_node.subpath("ControlSet001\\Control\\ServiceGroupOrder").unwrap().unwrap();
let key_value = key_node.value("List").unwrap().unwrap();

let multi_sz_data = key_value.multi_string_data();
if let Ok(vec) = multi_sz_data {
    println!("Vector of REG_MULTI_SZ lines: {:?}", vec);
}
```

Check out the [docs](https://docs.rs/nt-hive), the tests, and the supplied *readhive* example application for more ideas how to use nt-hive.

## Contributing and License
Contributions are currently preferred in the form of bug reports.
If you encounter a bug, an unexpected panic, or a potentially unsafe calculation, please [file a bug report](https://github.com/ColinFinck/nt-hive/issues).

nt-hive is available under *GNU General Public License 2.0 or (at your option) any later version*.
This license fits well with the projects I'm planning to use nt-hive for, and should allow integration into any open-source project.  
I may however put nt-hive under a more permissive license later if you [give me a good reason](mailto:colin@reactos.org).

As relicensing requires permission from every contributor, I only accept code contributions that are explicitly put under [Creative Commons Zero (CC0)](https://creativecommons.org/publicdomain/zero/1.0/).
If that is not an option for you, you are still very welcome to suggest your change in a bug report.

## Further Resources
* [Windows registry file format specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md) by [Maxim Suhanov](https://dfir.ru/)
* [cmlib library](https://github.com/reactos/reactos/tree/master/sdk/lib/cmlib) by the [ReactOS Project](https://reactos.org)
