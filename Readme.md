# Rust unwind info inspector

This is a simple tool to inspect the unwind info of Rust binaries. It shows a disassembly of a function together with the relevant `.eh_frame` and `.gcc_except_table` entries.

## Usage

```shell
cargo run -- /path/to/executable symbol_name
```

## License

Licensed under either of

  * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
    http://www.apache.org/licenses/LICENSE-2.0)
  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
    http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.
