the main code is in `lib.zig` and contains a few key structs:
- `GeyserWriter`: used to write new accounts 
- `GeyserReader`: used to read new accounts 

both structs have an internal buffer to reuse memory after each read/write

both use linux pipes to stream data out of the validator. this involves
opening a file-based pipe using the `mkfifo` syscall which is then 
written to like any other file. 

currently, data is serialized and written through the pipe using `bincode`

## data

data is organized to be written as `[size, serialized_data]` 

where `size` is the full length of the `serialized_data`

see `GeyserWriter.write()` for an example

this allows for more efficient buffered reads where you can read the first 8 bytes in 
the pipe, cast to a u64, allocate a buffer of that size and then read the rest of 
the data associated with that payload.

see `GeyserReader.read()` for an example

## example usage

an example reader program exists at [https://github.com/0xNineteen/sig-geyser-example/tree/main](https://github.com/0xNineteen/sig-geyser-example/tree/main)

to write data to the pipe you can use the accountsdb fuzzing code. 

building and running `./zig-out/bin/fuzz accountsdb` will generate random 
account data which will also be written to the pipe, currently hardcoded to 
`"test_data/accountsdb_fuzz.pipe"`