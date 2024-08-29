the main code is in `lib.zig` and contains a few key structs:
- `GeyserWriter`: used to write new accounts 
- `GeyserReader`: used to read new accounts 

both use linux pipes to stream data. this involves
opening a file-based pipe using the `mkfifo` syscall which is then 
written to like any other file. the key method used to setup 
the pipes is `openPipe` in `src/geyser/core.zig`.

## data

currently, data is serialized and written through the pipe using `bincode`

data is organized to be written as `[size, serialized_data]` 

where `size` is the full length of the `serialized_data`

this allows for more efficient buffered reads where you can read the first 8 bytes in 
the pipe, cast to a u64, allocate a buffer of that size and then read the rest of 
the data associated with that payload.

the key struct used is `AccountPayload` which uses a versioned system to support different payload types (`VersionedAccountPayload`) while also being backwards compatibility.

## GeyserWriter

![](imgs/2024-08-07-17-27-36.png)

### IO Thread

the writer uses a separate thread to write to the pipe due to expensive i/o operations.
to spawn this thread, use the `spawnIOLoop` method.

it loops, draining the channel for payloads with type (`[]u8`) and then writes the bufs to the pipe and then frees the payload using the `RecycleFBA`

### RecycleFBA 

one of the most common operations when streaming accounts is to allocate a buffer to serialize
the `AccountPayload` into and then free the buffer after the bytes have been written to the pipe.

to write accounts out fast, we preallocate a slice of memory which we re-use for serialization throughout the 
geyser's lifetime. This logic is encapsulated in the `RecycleFBA` struct.

the `RecycleFBA` struct uses a fixed buffer allocation strategy but, for each allocation that occurs, it tracks the buffer and whether it is occupied or free.

```zig
alloc_allocator: std.heap.FixedBufferAllocator,
records: std.ArrayList(struct { is_free: bool, buf: []u8 }),
```

when requesting a new slice of memory from the recycle allocator, it will check for a record
which is free and the buf is large enough. If there is no record that fits these conditions
then it will allocate a new slice using the fixed buffer allocator and track it in the 
records field.

when free is called, we find the buffer in the records and set the record's `is_free = true`.

### usage 

```zig 
// setup writer
var stream_writer = try GeyserWriter.init(
    allocator,
    "test-data/stream_test.pipe",
    exit,
    1 << 18, // 256kb
);
defer stream_writer.deinit();

try stream_writer.spawnIOLoop();

const v_payload = VersionedAccountPayload{
    .AccountPayloadV1 = .{
        .accounts = accounts,
        .pubkeys = pubkeys,
        .slot = 100,
    },
};
// write to the pipe (alloc with recycleFBA + serialize with bincode + send to IO thread)
try stream_writer.writePayloadToPipe(v_payload);
```

## GeyserReader

the reader has two main buffers: 
- `io_buf` : which is used to read from the pipe into this buf
- `bincode_buf` : which is used for bincode allocations 

for example, pseudocode would be: 
```
read(pipe_fd, &io_buf)

// deseriazing with bincode is not zero-copy so to reduce allocations we use
// a fixed buffer allocation strategy
allocator = FixedBufferAllocator.init(&bincode_buf)
payload = bincode.deserialized(&io_buf, allocator, AccountPayload)
```

before reading the io_buf, since we know how much bytes to read for the full payload (see data section), we can resize the io_buf if its not big enough.

if the bincode_buf is not big enough then we double the buffer length and try again since
we dont know exactly how many bytes we will need.

## benchmarking 

we also have benchmarking to measure the throughput of geyser. you can run it using 

```bash 
zig build -Doptimize=ReleaseSafe

./zig-out/bin/benchmark stream_geyser
```

## example usage

to write data to the pipe you can download a testnet and validate it, which will 
stream the accounts out of the validator during startup.