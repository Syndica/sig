const std = @import("std");
const sig = @import("sig");

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const MTU = 1232;

// pub fn main() !void {
//     const orig  = [_]u8{ 11, 0, 0, 0, 63, 139, 18, 199, 19, 121, 52, 228, 82, 161, 37, 91, 147, 175, 186, 112, 30, 212, 9, 62, 146, 29, 121, 181, 22, 207, 38, 101, 6, 186, 51, 114, 132, 142, 133, 195, 201, 51, 89, 162, 251, 182, 130, 74, 6, 0, 214, 106, 3, 1, 8, 93, 144, 88, 111, 56, 37, 155, 96, 6, 1, 0, 0, 0, 0, 195, 3, 221, 71, 12, 0, 0, 192, 62, 10, 0, 1, 11, 0, 1, 5, 0, 1, 6, 0, 1, 9, 0, 1, 12, 0, 1, 8, 0, 3, 7, 0, 1, 4, 0, 2, 1, 0, 1, 13, 0, 4, 0 };
//     const wrote = [_]u8{ 11, 0, 0, 0, 63, 139, 18, 199, 19, 121, 52, 228, 82, 161, 37, 91, 147, 175, 186, 112, 30, 212, 9, 62, 146, 29, 121, 181, 22, 207, 38, 101, 6, 186, 51, 114, 132, 143, 133, 195, 201, 51, 89, 162, 251, 182, 130, 74, 6, 0, 214, 106, 3, 1, 8, 93, 144, 88, 111, 56, 37, 155, 96, 6, 1, 0, 0, 0, 0, 195, 3, 221, 71, 12, 0, 0, 192, 63, 10, 0, 1, 11, 0, 1, 5, 0, 1, 6, 0, 1, 9, 0, 1, 12, 0, 1, 8, 0, 3, 7, 0, 1, 4, 0, 2, 1, 0, 1, 13, 0, 4, 0 };


// }

// pub fn main() !void {
//     const packet = [_]u8{ 1, 0, 0, 0, 105, 49, 113, 151, 238, 124, 61, 195, 101, 27, 106, 86, 216, 32, 51, 229, 85, 152, 199, 162, 140, 230, 126, 255, 78, 28, 144, 5, 140, 96, 70, 167, 3, 0, 0, 0, 0, 0, 0, 0, 162, 134, 120, 174, 60, 91, 60, 0, 161, 95, 237, 127, 59, 202, 12, 224, 223, 141, 104, 195, 140, 148, 148, 1, 62, 227, 213, 178, 26, 210, 206, 77, 57, 4, 29, 145, 6, 68, 217, 60, 120, 80, 253, 241, 109, 4, 74, 24, 175, 235, 156, 138, 174, 144, 167, 217, 226, 41, 195, 251, 83, 224, 250, 8, 1, 0, 0, 0, 3, 17, 77, 4, 60, 50, 55, 179, 166, 50, 17, 197, 71, 207, 111, 147, 108, 133, 100, 102, 116, 73, 136, 79, 203, 2, 149, 107, 173, 71, 159, 133, 169, 1, 228, 69, 134, 59, 117, 78, 227, 222, 86, 73, 40, 127, 140, 207, 11, 150, 103, 181, 168, 209, 181, 23, 54, 17, 194, 195, 5, 25, 253, 93, 128, 179, 31, 62, 179, 100, 197, 145, 149, 7, 198, 131, 130, 77, 84, 233, 227, 240, 100, 40, 120, 27, 240, 251, 107, 86, 110, 226, 216, 208, 149, 50, 200, 9, 1, 0, 1, 3, 17, 77, 4, 60, 50, 55, 179, 166, 50, 17, 197, 71, 207, 111, 147, 108, 133, 100, 102, 116, 73, 136, 79, 203, 2, 149, 107, 173, 71, 159, 133, 169, 135, 76, 235, 34, 118, 45, 228, 179, 63, 92, 133, 8, 192, 95, 94, 253, 3, 222, 101, 99, 87, 198, 173, 159, 57, 60, 203, 32, 204, 39, 51, 26, 7, 97, 72, 29, 53, 116, 116, 187, 124, 77, 118, 36, 235, 211, 189, 179, 216, 53, 94, 115, 209, 16, 67, 252, 13, 163, 83, 128, 0, 0, 0, 0, 184, 201, 31, 60, 23, 86, 115, 74, 203, 233, 170, 166, 212, 112, 123, 172, 179, 146, 193, 197, 172, 193, 13, 248, 235, 182, 220, 140, 39, 114, 165, 92, 1, 2, 2, 1, 0, 148, 1, 14, 0, 0, 0, 77, 253, 78, 23, 0, 0, 0, 0, 31, 1, 31, 1, 30, 1, 29, 1, 28, 1, 27, 1, 26, 1, 25, 1, 24, 1, 23, 1, 22, 1, 21, 1, 20, 1, 19, 1, 18, 1, 17, 1, 16, 1, 15, 1, 14, 1, 13, 1, 12, 1, 11, 1, 10, 1, 9, 1, 8, 1, 7, 1, 6, 1, 5, 1, 4, 1, 3, 1, 2, 1, 1, 108, 66, 144, 246, 195, 182, 56, 196, 127, 37, 247, 19, 105, 29, 181, 8, 68, 214, 55, 118, 4, 79, 67, 223, 71, 241, 212, 54, 35, 205, 19, 44, 1, 90, 215, 159, 105, 0, 0, 0, 0, 165, 33, 199, 132, 86, 117, 47, 39, 190, 127, 101, 152, 26, 76, 127, 71, 50, 224, 168, 160, 7, 254, 123, 121, 216, 6, 160, 159, 219, 9, 43, 223, 12, 59, 97, 152, 156, 1, 0, 0, 71, 192, 60, 107, 255, 62, 72, 217, 93, 54, 150, 83, 186, 82, 169, 127, 84, 184, 52, 61, 34, 30, 61, 49, 241, 125, 188, 87, 151, 189, 154, 86, 28, 188, 250, 114, 204, 190, 113, 156, 7, 244, 0, 68, 207, 181, 79, 114, 141, 90, 32, 68, 138, 72, 48, 21, 129, 157, 164, 94, 37, 94, 125, 15, 1, 0, 0, 0, 9, 112, 115, 75, 179, 68, 10, 119, 20, 188, 145, 142, 162, 9, 26, 73, 249, 103, 241, 233, 117, 70, 73, 231, 220, 102, 241, 15, 102, 26, 221, 84, 109, 1, 210, 67, 127, 114, 216, 116, 77, 228, 250, 94, 247, 50, 99, 194, 222, 98, 213, 160, 133, 107, 30, 150, 217, 104, 104, 254, 185, 50, 153, 145, 227, 70, 82, 28, 89, 202, 103, 227, 193, 202, 169, 149, 224, 250, 69, 63, 151, 40, 75, 107, 88, 216, 77, 167, 172, 236, 89, 65, 111, 52, 55, 105, 204, 7, 1, 0, 1, 3, 112, 115, 75, 179, 68, 10, 119, 20, 188, 145, 142, 162, 9, 26, 73, 249, 103, 241, 233, 117, 70, 73, 231, 220, 102, 241, 15, 102, 26, 221, 84, 109, 185, 73, 210, 214, 186, 171, 113, 169, 124, 199, 136, 255, 9, 188, 140, 76, 214, 68, 188, 182, 201, 202, 23, 188, 46, 171, 171, 131, 253, 91, 164, 3, 7, 97, 72, 29, 53, 116, 116, 187, 124, 77, 118, 36, 235, 211, 189, 179, 216, 53, 94, 115, 209, 16, 67, 252, 13, 163, 83, 128, 0, 0, 0, 0, 128, 217, 114, 239, 105, 36, 83, 20, 71, 4, 103, 126, 183, 194, 44, 246, 161, 252, 126, 180, 33, 160, 146, 152, 202, 62, 213, 130, 88, 35, 10, 5, 1, 2, 2, 1, 0, 148, 1, 14, 0, 0, 0, 80, 253, 78, 23, 0, 0, 0, 0, 31, 1, 31, 1, 30, 1, 29, 1, 28, 1, 27, 1, 26, 1, 25, 1, 24, 1, 23, 1, 22, 1, 21, 1, 20, 1, 19, 1, 18, 1, 17, 1, 16, 1, 15, 1, 14, 1, 13, 1, 12, 1, 11, 1, 10, 1, 9, 1, 8, 1, 7, 1, 6, 1, 5, 1, 4, 1, 3, 1, 2, 1, 1, 3, 202, 165, 90, 148, 74, 57, 126, 46, 136, 64, 137, 204, 189, 182, 117, 192, 145, 222, 40, 154, 56, 92, 89, 140, 184, 249, 90, 32, 231, 153, 15, 1, 91, 215, 159, 105, 0, 0, 0, 0, 229, 55, 152, 212, 14, 127, 64, 221, 3, 123, 23, 46, 197, 219, 249, 61, 104, 139, 142, 9, 245, 51, 201, 1, 145, 140, 103, 182, 160, 242, 243, 134, 49, 63, 97, 152, 156, 1, 0, 0, 86, 53, 89, 118, 216, 143, 133, 2, 205, 217, 174, 178, 15, 93, 164, 38, 177, 71, 237, 194, 202, 37, 130, 148, 161, 65, 206, 125, 97, 251, 125, 212, 25, 26, 232, 142, 123, 193, 76, 147, 195, 65, 15, 80, 27, 202, 116, 71, 121, 247, 18, 36, 24, 19, 134, 111, 17, 1, 187, 92, 72, 3, 163, 13, 11, 0, 0, 0, 63, 139, 18, 199, 19, 121, 52, 228, 82, 161, 37, 91, 147, 175, 186, 112, 30, 212, 9, 62, 146, 29, 121, 181, 22, 207, 38, 101, 6, 186, 51, 114, 132, 142, 133, 195, 201, 51, 89, 162, 251, 182, 130, 74, 6, 0, 214, 106, 3, 1, 8, 93, 144, 88, 111, 56, 37, 155, 96, 6, 1, 0, 0, 0, 0, 195, 3, 221, 71, 12, 0, 0, 192, 62, 10, 0, 1, 11, 0, 1, 5, 0, 1, 6, 0, 1, 9, 0, 1, 12, 0, 1, 8, 0, 3, 7, 0, 1, 4, 0, 2, 1, 0, 1, 13, 0, 4, 0 };


//     var alloc_buf: [8192]u8 = undefined;
//     var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
//     var fbs = std.io.fixedBufferStream(&packet);
    
//     const msg = try bincode.read(fba.allocator(), fbs.reader(), GossipMessage);
//     std.log.debug("{} = {}", .{fbs.getWritten().len, packet.len});

//     for (msg.pull_response.values) |v| {
//         const from = switch (v.data) {
//             inline else => |vv| vv.from,
//         };

//         var buf2: [MTU]u8 = undefined;
//         var fbs2 = std.io.fixedBufferStream(&buf2);
//         try bincode.write(fbs2.writer(), v.data);
//         std.log.debug("{any} => {any}\n", .{v.data, v.signature.verify(from, fbs2.getWritten())});

//         if (!std.mem.eql(u8, v.bytes, fbs2.getWritten())) {
//             std.debug.print("orig : {any}\n", .{v.bytes});
//             std.debug.print("wrote: {any}\n", .{fbs2.getWritten()});
//         }
//     }
// }

pub fn main() !void {
    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer std.debug.assert(gpa_state.deinit() == .ok);
    const gpa = gpa_state.allocator();

    const gossip_port = 8002;
    const keypair: KeyPair = .generate();
    const entrypoints: []const []const u8 = &.{
        "entrypoint.testnet.solana.com:8001",
        // "entrypoint2.testnet.solana.com:8001",
        // "entrypoint3.testnet.solana.com:8001",
    };

    const echo: EchoResponse, const entry_addr: std.net.Address = for (entrypoints) |entrypoint| {
        const split = std.mem.indexOfScalar(u8, entrypoint, ':') orelse continue;
        const port = std.fmt.parseInt(u16, entrypoint[split + 1..], 10) catch continue;

        const addr_list = std.net.getAddressList(gpa, entrypoint[0..split], port) catch continue;
        defer addr_list.deinit();

        break for (addr_list.addrs) |addr| {
            const socket = try std.posix.socket(addr.any.family, std.posix.SOCK.STREAM, 0);
            defer std.posix.close(socket);

            const tv = comptime std.mem.asBytes(&std.posix.timeval{ .sec = 1, .usec = 0 });
            try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, tv);
            std.posix.connect(socket, &addr.any, addr.getOsSockLen()) catch continue;

            const stream = std.net.Stream{ .handle = socket };
            try bincode.write(stream.writer(), EchoMessage{
                .tcp_ports = @splat(0),
                .udp_ports = .{ 0, 0, 0, 0 },
            });

            const echo = 
                try bincode.read(std.testing.failing_allocator, stream.reader(), EchoResponse);
            break .{ echo, addr };
        } else continue;
    } else return error.NoValidEntryPoints;

    const my_contact_info: ContactInfo = .{
        .from = .{ .data = keypair.public_key.bytes },
        .wallclock = undefined, // set during signing
        .created = realtime(),
        .shred_version = echo.shred_version orelse 0,
        .major = .{ .value = 0 },
        .minor = .{ .value = 0 },
        .patch = .{ .value = 0 },
        .commit = 0,
        .feature_set = 0,
        .client_id = .{ .value = 0 },
        .ips = .{ .items = &.{ echo.addr } },
        .sockets = .{ .items = &.{ .{ .key = .gossip, .idx = 0, .port_offset = .{ .value = gossip_port } } } },
        .extensions = .{ .items = &.{} },
    };

    const e_addr = entry_addr;

    // _ = entry_addr;
    // const e_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8001);

    try runGossip(gpa, e_addr, keypair, my_contact_info);
}

fn runGossip(
    gpa: std.mem.Allocator,
    entry_addr: std.net.Address,
    keypair: KeyPair,
    my_ci: ContactInfo,
) !void {
    var prng = std.Random.DefaultPrng.init(0);
    
    // Set addr ip to 0 for binding
    const my_sock_addr = try getGossipAddr(.{ .contact_info = my_ci });
    const my_addr: std.net.Address = switch (my_sock_addr) {
        .v4 => |s| .initIp4(@splat(0), s.port),
        .v6 => |s| .initIp6(@splat(0), s.port, 0, 0),
    };

    const socket = try std.posix.socket(my_addr.any.family, std.posix.SOCK.DGRAM, 0);
    defer std.posix.close(socket);

    // Timeout on socket for recvfrom() to eventually run PullRequest/PushMessages
    const tv = comptime std.mem.asBytes(&std.posix.timeval{ .sec = 1, .usec = 0 });
    try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, tv);
    
    try std.posix.bind(socket, &my_addr.any, my_addr.getOsSockLen());
    std.log.debug(
        "Started gossip on {any} shred_version:{} pubkey:{}",
        .{my_addr, my_ci.shred_version, Pubkey{ .data = keypair.public_key.bytes } },
    );

    // Gossip data structures
    var table: GossipTable = .{};
    try table.ensureTotalCapacity(gpa, 8192);
    defer table.deinit(gpa);

    var hashes: GossipHashes = .{};
    try hashes.ensureTotalCapacity(gpa, table.capacity());
    defer hashes.deinit(gpa);

    var peers: GossipPeers = .{};
    try peers.ensureTotalCapacity(gpa, max_peers);
    defer peers.deinit(gpa);

    const value_buf = try gpa.alloc(u8, 8192 * 256);
    defer gpa.free(value_buf);

    // Initial state
    {
        // add our contact into to table.
        const signed_ci = try signData(keypair, .{ .contact_info = my_ci });
        _ = try tableInsert(&table, &hashes, signed_ci);

        // send out ping so entry responds with pong of their pubkey
        // _ = try sendPing(socket, entry_addr, keypair, prng.random());
        
        try sendGossipMessage(socket, entry_addr, .{ .push_message = .{
            .from = my_ci.from,
            .values = &.{ signed_ci },
        }});

        // try sendGossipMessage(socket, entry_addr, .{ .push_message = .{
        //     .from = my_ci.from,
        //     .values = &.{ try signData(keypair, .{
        //         .version = .{
        //             .from = my_ci.from,
        //             .wallclock = undefined, // set during signData
        //             .version = my_ci.version,
        //             .feature_set = my_ci.feature_set,
        //         } }),
        //     },
        // }});
        // try sendGossipMessage(socket, entry_addr, .{ .push_message = .{
        //     .from = my_ci.from,
        //     .values = &.{ try signData(keypair, .{
        //         .node_instance = .{
        //             .from = my_ci.from,
        //             .wallclock = undefined, // set during signData
        //             .created = my_ci.created,
        //             .token = prng.random().int(u64),
        //         } }), 
        //     },
        // }});
    }
    
    var pull_request_timer: Timestamp = 0;
    var push_message_timer: Timestamp = 0;
    var dump_timer: Timestamp = 0;
    var timer = try std.time.Timer.start();
    while (true) {
        const now = realtime();

        if (dump_timer <= now) {
            dump_timer = now + (1 * 1000); // every 5s

            var file = try std.fs.cwd().createFile("gossip_dump.txt", .{});
            defer file.close();

            var w = std.io.bufferedWriter(file.writer());
            try w.writer().print("Elapsed: {} (peers:{})\n\n", .{std.fmt.fmtDuration(timer.read()), peers.count()});

            for (peers.keys(), peers.values()) |pubkey, peer| {
                try w.writer().print("Contact({}, {})\n", .{pubkey, peer.addr});
                // const v = table.getPtr(.{ .from = pubkey, .tag = .contact_info, .idx = 0 }) orelse continue;
                // var _fbs = std.io.fixedBufferStream(v.value[0..v.len]);
                // var _fba = std.heap.FixedBufferAllocator.init(value_buf);
                // const value = try bincode.read(_fba.allocator(), _fbs.reader(), CrdsValue);
                // const sock_addr = getGossipAddr(value.data) catch continue;
                // const addr
            }
            try w.flush();
        }

        if (push_message_timer <= now) b: {
            push_message_timer = now + (7 * 1000); // every 7s

            if (peers.count() == 0) {
                std.log.err("No peers..", .{});
                break :b;
            }

            // Send contact info.
            std.log.debug("Sending push contact_info", .{});
            const ci_value = try signData(keypair, .{ .contact_info = my_ci });
            _ = try tableInsert(&table, &hashes, ci_value);
            try sendPushes(socket, &peers, prng.random(), keypair, &.{ ci_value }, now);
        }

        if (pull_request_timer <= now) {
            pull_request_timer = now + (2 * 1000); // every 2s

            const num_items = table.count() + hashes.items.len;
            const max_items = comptime blk: {
                const max_keys = 8.0;
                const x = @exp(@log(Bloom.false_rate) / max_keys);
                const n = (-max_keys / @log(@as(f64, 1.0) - x));
                break :blk @ceil(Bloom.max_bloom_bits / n);
            };

            const mask_bits = blk: {
                const x = @max(0, @ceil(@log2(@as(f64, @floatFromInt(num_items)) / max_items)));
                break :blk @as(u6, @intFromFloat(x));
            };
            std.log.debug("Sending pull request: num_items={} mask_bits={}", .{num_items, mask_bits});

            const num_bits = Bloom.numBits(num_items);
            const num_words = Bloom.numWords(num_bits);
            const num_keys = Bloom.numKeys(num_items, num_bits);
            
            var filters: std.ArrayListUnmanaged(struct{
                keys: []u64,
                words: []u64,
            }) = .{};
            defer {
                for (filters.items) |f| {
                    gpa.free(f.keys);
                    gpa.free(f.words);
                }
                filters.deinit(gpa);
            }
            for (0..@as(u64, 1) << mask_bits) |_| {
                const keys = try gpa.alloc(u64, num_keys);
                for (keys) |*k| k.* = prng.random().int(u64);
                const words = try gpa.alloc(u64, num_words);
                @memset(words, 0);
                try filters.append(gpa, .{ .keys = keys, .words = words });
            }

            for (table.values()) |*v| {
                const h = std.mem.readInt(u64, v.hash.data[0..8], .little);
                const i: usize = @intCast(@as(u65, h) >> @intCast(@as(u8, 64) - mask_bits));
                const f = &filters.items[i];
                Bloom.add(f.keys, f.words, &v.hash.data);
            }
            for (hashes.items) |*v| {
                const h = std.mem.readInt(u64, v.hash.data[0..8], .little);
                const i: usize = @intCast(@as(u65, h) >> @intCast(@as(u8, 64) - mask_bits));
                const f = &filters.items[i];
                Bloom.add(f.keys, f.words, &v.hash.data);
            }

            const max_pull_reqs = 256;
            const active_peers = getActivePeers(max_pull_reqs, &peers, my_ci.from, prng.random());
            for (active_peers.constSlice(), 0..) |addr, i| {
                const f = if (i >= filters.items.len) break else &filters.items[i];
                var n_bits: u64 = 0;
                for (f.words) |w| n_bits += @popCount(w);

                const m1 = (@as(u65, i) << @intCast(@as(u8, 64) - mask_bits)) | (~@as(u64, 0) >> mask_bits);
                const mask = std.math.lossyCast(u64, m1);

                sendGossipMessage(socket, addr, .{ .pull_request = .{
                    .filter = .{
                        .keys = f.keys,
                        .words = .{
                            .bits = f.words,
                            .len = num_bits,
                        },
                        .num_bits = n_bits,
                    },
                    .mask = mask,
                    .mask_bits = mask_bits,
                    .contact_info = try signData(keypair, .{ .contact_info = my_ci }),
                }}) catch |e| {
                    std.log.err("Failed to send PullRequest(keys={} words={}, num_bits={}, n_bits={}, mask={}, mask_bits={}): {}", .{
                        f.keys.len, f.words.len, num_bits, n_bits, mask, mask_bits, e,
                    });
                    return e;
                };
            } 
        }
        
        // Expire old hashes
        {
            var i: usize = 0;
            while (i < hashes.items.len) {
                const h = &hashes.items[i];
                // In agave: evicted hashes retained for 75s, while failed pull_req hashes retained for 25s
                if (h.wallclock <= (now -| (60 * 1000))) {
                    _ = hashes.swapRemove(i);
                } else {
                    i += 1;
                }
            }
        }

        // Expire old table values
        // {
        //     var i: usize = 0;
        //     while (i < table.count()) {
        //         const v = &table.values()[i];
        //         if (v.wallclock <= (now -| (30 * 1000))) {
        //             std.log.debug("removing dead table entry: {}", .{table.keys()[i]});
        //             pushHash(&hashes, v.hash, now);
        //             table.swapRemoveAt(i);
        //         } else {
        //             i += 1;
        //         }
        //     }
        // }

        // Ping peers & expire old ones
        {
            var i: usize = 0;
            while (i < peers.values().len) {
                const p: *GossipPeer = &peers.values()[i];
                
                if (p.last_pong <= now -| (30 * 1000)) {
                    std.log.debug("removing dead peer from no Pongs {}:{}", .{peers.keys()[i], p.addr});
                    removePeer(&table, &peers, i);
                    continue;
                }

                if (p.last_contact <= now -| (60 * 1000)) {
                    std.log.debug("removing dead peer from no ContactInfo {}:{}", .{peers.keys()[i], p.addr});
                    removePeer(&table, &peers, i);
                    continue;
                }

                try maybePingPeer(socket, p, keypair, prng.random(), now);
                i += 1;
            }
        }


        var buf: [MTU]u8 = undefined;
        var addr: std.net.Address = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr.in6));
        const n = std.posix.recvfrom(socket, &buf, 0, &addr.any, &addr_len) catch |e| switch (e) {
            error.WouldBlock => continue,
            else => |err| return err,
        };
        
        var fbs = std.io.fixedBufferStream(buf[0..n]);
        var alloc_buf: [16 * 1024]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
        const msg = bincode.read(fba.allocator(), fbs.reader(), GossipMessage) catch |e| {
            if (@errorReturnTrace()) |t| std.debug.dumpStackTrace(t.*);
            std.log.err("Invalid gossip msg: {}", .{e});
            continue;
        };

        if (fbs.pos != fbs.buffer.len) {
            std.log.err("incomplete parsed msg: {}", .{msg});
            continue;
        }

        std.log.debug("msg: {}\n", .{std.meta.activeTag(msg)});
        

        switch (msg) {
            .pull_request => |pr| {
                const from = switch (pr.contact_info.data) {
                    inline .legacy_contact_info, .contact_info => |v| v.from,
                    else => continue, // only contact_info allowed
                };

                std.log.debug("PullRequest({}, {?}) bits={}", .{
                    from, getGossipAddr(pr.contact_info.data) catch null,
                    pr.mask_bits,
                });

                // Try to insert the contact_info
                verifyValue(pr.contact_info, now) catch continue;
                try onNewValue(
                    socket,
                    &table,
                    &peers,
                    &hashes,
                    .{from, addr},
                    pr.contact_info,
                    keypair,
                    prng.random(),
                    now,
                );

                const mask = @as(u64, 1) << (std.math.cast(u6, pr.mask_bits) orelse continue);

                var total_bytes: usize = 0;
                var values: std.BoundedArray(CrdsValue, 256) = .{};
                fba = std.heap.FixedBufferAllocator.init(value_buf);
                
                // Collect values from table that match.
                for (table.values()) |*v| {
                    const h = std.mem.readInt(u64, v.hash.data[0..8], .little);
                    if (h & mask != pr.mask & mask) continue; // check if masks match
                    if (pr.filter.words.bits) |words| { // check if Filter matches, if any.
                        if (!Bloom.contains(pr.filter.keys, words, &v.hash.data)) continue;
                    }

                    // too many values detected
                    if (total_bytes + v.len > (MTU - 4 - 32 - 8)) break; 
                    if (values.len == values.capacity()) break;
                
                    var v_fbs = std.io.fixedBufferStream(v.value[0..v.len]);
                    total_bytes += v.len;

                    const value = try bincode.read(fba.allocator(), v_fbs.reader(), CrdsValue);
                    values.appendAssumeCapacity(value);
                }

                // Pull Response with values
                const p = try getOrCreatePeer(socket, &table, &peers, from, addr, prng.random(), keypair, now);
                try sendGossipMessage(socket, p.addr, .{ .pull_response = .{
                    .from = my_ci.from,
                    .values = values.constSlice(),
                }});
            },
            inline .pull_response, .push_message => |add| {
                const str: []const u8 = if (msg == .pull_response) "PullResponse" else "PushMessage";
                std.log.debug("{s}({}, count={})", .{
                    str,
                    add.from,
                    add.values.len,
                });

                const good = for (add.values) |value| {
                    verifyValue(value, now) catch break false;
                } else true;
                if (!good) {
                    continue;
                }

                for (add.values) |value| {
                    // For push messages only, skip too old/new values
                    if (msg == .push_message) {
                        _, const wallclock = getGossipKey(value.data);
                        if (wallclock <= (now -| (30 * 1000)) or wallclock >= (now +| (30 * 1000)))
                            continue;
                    }

                    try onNewValue(
                        socket,
                        &table,
                        &peers,
                        &hashes,
                        .{add.from, addr},
                        value,
                        keypair,
                        prng.random(),
                        now,
                    );
                }

                if (msg == .push_message) {
                    try sendPushes(socket, &peers, prng.random(), keypair, add.values, now);
                }
            },
            .prune_message => |prune| {
                const from = prune.from;
                if (!prune.data.pubkey.equals(&from)) {
                    std.log.err("invalid prune pubkey", .{});
                    continue;
                }

                if (prune.data.wallclock <= (now -| 30 * 1000)) {
                    std.log.err("prune too old {} < {}", .{prune.data.wallclock, now});
                    continue;
                }

                var prune_buf: [MTU]u8 = undefined;
                fbs = std.io.fixedBufferStream(&prune_buf);
                const prefix: []const u8 = "\xffSOLANA_PRUNE_DATA"; // some are signed with this??
                try fbs.writer().writeAll(prefix); 
                try bincode.write(fbs.writer(), .{
                    .pubkey = prune.data.pubkey,
                    .prunes = prune.data.prunes,
                    .dest = prune.data.dest,
                    .wallclock = prune.data.wallclock,
                });

                prune.data.signature.verify(from, fbs.getWritten()[prefix.len..]) catch {
                    prune.data.signature.verify(from, fbs.getWritten()) catch {
                        std.log.err("invalid prune signature", .{});
                        continue;
                    };
                };

                std.log.debug("PruneMessage(from:{}, prunes:{any})", .{from, prune.data.prunes});

                const p = peers.getPtr(from) orelse {
                    std.log.err("prune to untracked peer: {}", .{from});
                    continue;
                };

                for (prune.data.prunes) |pruned_pubkey| {
                    Bloom.add(&p.pruned.keys, &p.pruned.words, &pruned_pubkey.data);
                }
            },
            .ping_message => |ping| b: {
                ping.signature.verify(ping.from, &ping.token) catch {
                    std.log.err("invalid ping signature", .{});
                    break :b;
                };

                std.log.debug("Ping(from:{})", .{ping.from});

                // Important to add the peer here.
                const p = try getOrCreatePeer(socket, &table, &peers, ping.from, addr, prng.random(), keypair, now);

                const hash = Hash.initMany(&.{ "SOLANA_PING_PONG", &ping.token });
                try sendGossipMessage(socket, p.addr, .{ .pong_message = .{
                    .from = my_ci.from,
                    .hash = hash,
                    .signature = .fromSignature(try keypair.sign(&hash.data, null)),
                }});
            },
            .pong_message => |pong| b: {
                pong.signature.verify(pong.from, &pong.hash.data) catch {
                    std.log.err("invalid pong signature", .{});
                    break :b;
                };

                std.log.debug("Pong(from:{})", .{pong.from});

                const p = try getOrCreatePeer(socket, &table, &peers, pong.from, addr, prng.random(), keypair, now);
                p.last_pong = now;
            },
        }
    }
}

fn verifyValue(value: CrdsValue, now: Timestamp) !void {
    const key, _ = getGossipKey(value.data);
    _ = now;

    {
        var buf: [MTU]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        try bincode.write(fbs.writer(), value.data);
        value.signature.verify(key.from, fbs.getWritten()) catch {
            std.log.err("invalid value signature for {any}", .{value.data});
            if (value.data == .contact_info) {

                var alloc_buf: [8192]u8 = undefined;
                var _fba = std.heap.FixedBufferAllocator.init(&alloc_buf);
                var _fbs = std.io.fixedBufferStream(fbs.getWritten());
                const d = try bincode.read(_fba.allocator(), _fbs.reader(), CrdsData);
                std.log.err("  eql: {}", .{ eql("", d.contact_info, value.data.contact_info) });

                const ci = value.data.contact_info;
                std.log.err("  ips: {any}", .{ci.ips});
                std.log.err("  sockets: {any}", .{ci.sockets});
                std.log.err("  extensions: {any}", .{ci.extensions});
            }
            return error.InvalidValue;
        };
    }
}

fn eql(comptime path: []const u8, a: anytype, b: @TypeOf(a)) bool {
    const T = @TypeOf(a);
    const res = switch (@typeInfo(T)) {
        .int => a == b,
        .array => |info| blk: {
            comptime std.debug.assert(@typeInfo(info.child) == .int);
            break :blk std.mem.eql(u8, std.mem.asBytes(&a), std.mem.asBytes(&b));
        },
        .pointer => |info| blk: {
            comptime std.debug.assert(info.size == .slice);
            if (a.len != b.len) break :blk false;
            for (a, b) |_a, _b| if (!eql(path ++ "." ++ @typeName(T), _a, _b)) break :blk false;
            break :blk true;
        },
        .@"enum" => @intFromEnum(a) == @intFromEnum(b),
        .@"union" => switch (a) {
            inline else => |v1| blk: {
                switch (b) {
                    inline else => |v2| {
                        if (@TypeOf(v1) != @TypeOf(v2)) break :blk false;
                        break :blk eql(path ++ "." ++ @typeName(@TypeOf(v2)), v1, v2);
                    }
                }
            },
        },
        .@"struct" => |info| blk: {
            inline for (info.fields) |f| {
                if (!eql(path ++ "." ++ f.name, @field(a, f.name), @field(b, f.name))) break :blk false;
            }
            break :blk true;
        },
        else => @compileError("invalid type"),
    };
    if (!res) {
        std.log.err("  eql err on ({s}.{s}): ({any}) vs ({any})", .{path, @typeName(T), a, b});
    }
    return res;
}

fn onNewValue(
    socket: std.posix.socket_t,
    table: *GossipTable,
    peers: *GossipPeers,
    hashes: *GossipHashes,
    sender: struct{ Pubkey, std.net.Address },
    value: CrdsValue,
    keypair: KeyPair,
    rng: std.Random,
    now: Timestamp,
) !void {
    const key, const wallclock = getGossipKey(value.data);
    
    // Seems like a lot of the EpochValues would be expired based on this.
    // if (wallclock <= (now -| (30 * 1000))) {
    //     std.log.err("expired value {} ({} < {})", .{std.meta.activeTag(value.data), wallclock, now});
    //     return;
    // }

    const dups = tableInsert(table, hashes, value) catch |e| {
        std.log.err("insert table failed: {} {}", .{std.meta.activeTag(value.data), e});
        return e;
    };

    std.log.debug("Inserted {s} from {}", .{@tagName(std.meta.activeTag(value.data)), key.from});

    if (getGossipAddr(value.data) catch null) |sock_addr| {
        const addr: std.net.Address = switch (sock_addr) {
            .v4 => |s| .initIp4(s.ip, s.port),
            .v6 => |s| .initIp6(s.ip, s.port, 0, 0),
        };

        const p = try getOrCreatePeer(socket, table, peers, key.from, addr, rng, keypair, now);
        p.last_contact = wallclock;
        p.addr = addr;
    }

    // _ = dups;
    // _ = sender;

    const min_dupes_until_prune = 2; // allow dupes before pruning caller (for redundancy)
    if (dups > min_dupes_until_prune) {
        const from, const addr = sender;
        var prune = PruneMessage{
            .from = .{ .data = keypair.public_key.bytes },
            .data = .{
                .pubkey = .{ .data = keypair.public_key.bytes },
                .prunes = &.{ key.from },
                .signature = undefined, // set below
                .dest = from,
                .wallclock = now,
            },
        };

        var prune_buf: [MTU]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&prune_buf);
        try bincode.write(fbs.writer(), .{
            .pubkey = prune.data.pubkey,
            .prunes = prune.data.prunes,
            .dest = prune.data.dest,
            .wallclock = prune.data.wallclock,
        });
        prune.data.signature = .fromSignature(try keypair.sign(fbs.getWritten(), null));

        try sendGossipMessage(socket, addr, .{ .prune_message = prune });
    }
}

const GossipKey = struct {
    from: Pubkey,
    tag: std.meta.Tag(CrdsData),
    idx: u16, 
};

const GossipHashes = std.ArrayListUnmanaged(struct{ 
    hash: Hash,
    wallclock: Timestamp,
});
const GossipTable = std.AutoArrayHashMapUnmanaged(GossipKey, struct {
    hash: Hash,
    dupes: u8,
    wallclock: Timestamp,
    value: [MTU]u8,
    len: u16,
});

fn getGossipKey(data: CrdsData) struct{ GossipKey, Timestamp } {
    const tag = std.meta.activeTag(data);
    const wallclock, const key: GossipKey = switch (data) {
        .contact_info => |ci| .{ ci.wallclock.value, .{ .from = ci.from, .tag = .contact_info, .idx = 0 } },
        inline .vote, .epoch_slots, .duplicate_shred => |v| //
            .{ v.wallclock, .{ .from = v.from, .tag = tag, .idx = v.index } },
        inline else => |v| .{ v.wallclock, .{ .from = v.from, .tag = tag, .idx = 0 } },
    };
    return .{ key, wallclock };
}

fn tableInsert(
    table: *GossipTable,
    hashes: *GossipHashes,
    value: CrdsValue,
) !u32 {
    const key, const wallclock = getGossipKey(value.data);
    const v, const exists = blk: {
        if (table.count() == table.capacity()) {
            if (table.getPtr(key)) |v| break :blk .{ v, true };
            const i = findOldest(table.values(), "wallclock");
            std.log.debug("evicting table value: {any}", .{table.keys()[i]});
            const v = &table.values()[i];
            pushHash(hashes, v.hash, v.wallclock);
            table.swapRemoveAt(i);
        }
        const gop = table.getOrPutAssumeCapacity(key);
        break :blk .{ gop.value_ptr, gop.found_existing };
    };

    var buf: [MTU]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try bincode.write(fbs.writer(), value);
    const hash = Hash.init(fbs.getWritten());

    if (exists and v.hash.eql(hash)) {
        v.dupes +|= 1;
        return v.dupes;
    }

    if (exists and wallclock < v.wallclock) {
        if (wallclock >= (v.wallclock -| (30 * 1000))) 
            pushHash(hashes, hash, wallclock);
        return v.dupes + 1;
    }

    v.* = .{
        .dupes = 0,
        .hash = hash,
        .wallclock = wallclock,
        .len = @intCast(fbs.getWritten().len),
        .value = undefined,
    };
    @memcpy(v.value[0..v.len], fbs.getWritten());
    return v.dupes;
}

fn pushHash(hashes: *GossipHashes, hash: Hash, wallclock: Timestamp) void {
    if (hashes.items.len == hashes.capacity) {
        const j = findOldest(hashes.items, "wallclock");
        _ = hashes.swapRemove(j);
    }
    hashes.appendAssumeCapacity(.{ .hash = hash, .wallclock = wallclock }); // TODO: minheap
}

const max_peers = 65535;
const GossipPeers = std.AutoArrayHashMapUnmanaged(Pubkey, GossipPeer);
const GossipPeer = struct {
    addr: std.net.Address,
    last_ping: struct{ token: [32]u8, expires: Timestamp },
    last_pong: Timestamp,
    last_contact: Timestamp,
    pruned: struct {
        const n_bits = Bloom.numBits(max_peers);
        const n_keys = Bloom.numKeys(max_peers, n_bits);
        keys: [n_keys]u64,
        words: [Bloom.numWords(n_bits)]u64
    },
};

fn findOldest(slice: anytype, comptime ts_field: []const u8) usize {
    var oldest: usize = 0;
    var wallclock: Timestamp = std.math.maxInt(u64);
    for (slice, 0..) |*v, i| {
        const ts: Timestamp = @field(v, ts_field);
        if (ts < wallclock) {
            oldest = i;
            wallclock = ts;
        }
    }
    return oldest;
}

fn getOrCreatePeer(
    socket: std.posix.socket_t,
    table: *GossipTable,
    peers: *GossipPeers,
    pubkey: Pubkey,
    addr: std.net.Address,
    rng: std.Random,
    keypair: KeyPair,
    now: Timestamp,
) !*GossipPeer {
    if (peers.count() == peers.capacity()) {
        if (peers.getPtr(pubkey)) |p| return p;
        const i = findOldest(peers.values(), "last_contact");
        std.log.debug("evicting peer {}:{}", .{peers.keys()[i], peers.values()[i].addr});
        removePeer(table, peers, i);
    }

    const gop = peers.getOrPutAssumeCapacity(pubkey);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{
            .addr = addr,
            .last_contact = now,
            .last_ping = .{ .token = @splat(0), .expires = now },
            .last_pong = now,
            .pruned = undefined,
        };
        rng.bytes(std.mem.asBytes(&gop.value_ptr.pruned.keys));
        @memset(&gop.value_ptr.pruned.words, 0);
    }
        try maybePingPeer(socket, gop.value_ptr, keypair, rng, now);
    return gop.value_ptr;
}

fn removePeer(table: *GossipTable, peers: *GossipPeers, i: usize) void {
    const pubkey = peers.keys()[i];
    peers.swapRemoveAt(i);

    // TODO: remove all all values with its key
    _ = table.swapRemove(.{ .from = pubkey, .tag = .contact_info, .idx = 0 });
}

fn maybePingPeer(
    socket: std.posix.socket_t,
    p: *GossipPeer,
    keypair: KeyPair,
    rng: std.Random,
    now: Timestamp,
) !void {
    if (p.last_ping.expires >= now) return;
    std.log.debug("Pining {} ({} < {})", .{p.addr, p.last_ping.expires, now });

    const token = try sendPing(socket, p.addr, keypair,rng);
    const expires_after =  rng.intRangeLessThan(u64, 2 * 1000, 4 * 1000);
    p.last_ping = .{ .token = token, .expires = now + expires_after };
}


fn sendPushes(
    socket: std.posix.socket_t,
    peers: *const GossipPeers,
    rng: std.Random,
    keypair: KeyPair,
    values: []const CrdsValue,
    now: Timestamp,
) !void {
    const max_push_fanout = 6;
    var active: std.BoundedArray(*const GossipPeer, max_push_fanout) = .{};

    const all_peers = peers.values();
    if (all_peers.len == 0) return;

    var i = rng.uintLessThan(usize, all_peers.len);
    for (0..all_peers.len) |_| {
        const peer = &all_peers[i];
        defer i = (i + 1) % all_peers.len;
        active.append(peer) catch break;
    }

    var pushed: std.BoundedArray(CrdsValue, 256) = .{};
    for (active.constSlice()) |peer| {
        for (values) |value| {
            const key, const wallclock = getGossipKey(value.data);
            if (wallclock <= (now -| (30 * 1000)) or wallclock >= (now +| (30 * 1000)))
                continue;
            if (Bloom.contains(&peer.pruned.keys, &peer.pruned.words, &key.from.data))
                continue;

            pushed.appendAssumeCapacity(value);

            var buf: [MTU]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&buf);
            bincode.write(fbs.writer(), GossipMessage{ .push_message = .{
                .from = .fromPublicKey(&keypair.public_key),
                .values = pushed.constSlice(),
            }}) catch {
                pushed.len -= 1;
                try sendGossipMessage(socket, peer.addr, .{ .push_message = .{
                    .from = .fromPublicKey(&keypair.public_key),
                    .values = pushed.constSlice(),
                }});

                pushed.len = 0;
                pushed.appendAssumeCapacity(value);
            };
        }

        if (pushed.len > 0) {
            try sendGossipMessage(socket, peer.addr, .{ .push_message = .{
                .from = .fromPublicKey(&keypair.public_key),
                .values = pushed.constSlice(),
            }});
        }
    }

    // const from = switch (value.data) {
    //     inline else => |v| v.from,
    // };
    
    

    // for (active_peers.constSlice()) |addr| {
    //     try sendGossipMessage(socket, addr, .{ .push_message = .{
    //         .from = .{ .data = keypair.public_key.bytes },
    //         .values = &.{ value }, // TODO: batch multiple values per peer based on prunes
    //     }});
    // }
}

fn getActivePeers(
    max: comptime_int,
    peers: *const GossipPeers,
    origin: Pubkey,
    rng: std.Random,
) std.BoundedArray(std.net.Address, max) {
    var active: std.BoundedArray(std.net.Address, max) = .{};
    const all_peers = peers.values();
    if (all_peers.len == 0) return active;

    var i = rng.uintLessThan(usize, all_peers.len);
    for (0..all_peers.len) |_| {
        const peer = &all_peers[i];
        defer i = (i + 1) % all_peers.len;
        if (Bloom.contains(&peer.pruned.keys, &peer.pruned.words, &origin.data)) continue;
        active.append(peer.addr) catch break;
    }
    return active;
}

const Bloom = struct {
    const max_bloom_bits = 928 * 8;
    const false_rate = 0.1;

    fn add(keys: []align(1) u64, words: []align(1) u64, bytes: []const u8) void {
        for (keys) |k| {
            var h = std.hash.Fnv1a_64{ .value = k };
            h.update(bytes);
            const bit = h.final() % (words.len * 8);
            words[bit / 64] |= @as(u64, 1) << @intCast(bit % 64);
        }
    }

    fn contains(keys: []align(1) const u64, words: []align(1) const u64, bytes: []const u8) bool {
        for (keys) |k| {
            var h = std.hash.Fnv1a_64{ .value = k };
            h.update(bytes);
            const bit = h.final() % (words.len * 8);
            if ((words[bit / 64] >> @intCast(bit % 64)) & 1 == 0) return false;
        }
        return true;
    }

    fn numWords(num_bits: u64) u64 {
        const i = num_bits;
        const n = std.math.ceilPowerOfTwo(u64, @max(64, i)) catch unreachable;
        return std.math.divCeil(u64, @min(max_bloom_bits, n), 64) catch unreachable;
    }

    fn numBits(num_items: u64) u64 {
        const d = @log(@as(f64, 1) / std.math.pow(f64, 2, @log(@as(f64, 2))));
        const n = std.math.ceil((@as(f64, @floatFromInt(num_items)) * @log(false_rate)) / d);
        return @intFromFloat(@max(1, @min(n, max_bloom_bits)));
    }

    fn numKeys(num_items: u64, num_bits: u64) u64 {
        if (num_items == 0) return 0;
        const n = @as(f64, @floatFromInt(num_bits)) / @as(f64, @floatFromInt(num_items));
        return @intFromFloat(@max(@as(f64, 1), @round(n * @log(@as(f64, 2)))));
    }
};

fn sendPing(socket: std.posix.socket_t, addr: std.net.Address, keypair: KeyPair, rng: std.Random) ![32]u8 {
    var token: [32]u8 = undefined;
    rng.bytes(&token);
    try sendGossipMessage(socket, addr, .{ .ping_message = .{
        .from = .{ .data = keypair.public_key.bytes },
        .token = token,
        .signature = .fromSignature(try keypair.sign(&token, null)),    
    }});
    return token;
}

fn sendGossipMessage(socket: std.posix.socket_t, addr: std.net.Address, msg: GossipMessage) !void {
    std.log.debug("Sending to {}: {}", .{ addr, std.meta.activeTag(msg) });

    var buf: [MTU]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try bincode.write(fbs.writer(), msg);
    const sent = try std.posix.sendto(socket, fbs.getWritten(), 0, &addr.any, addr.getOsSockLen());
    std.debug.assert(sent == fbs.getWritten().len);
}

fn getGossipAddr(contact_info_data: CrdsData) !SocketAddr {
    switch (contact_info_data) {
        .legacy_contact_info => |ci| return ci.gossip,
        .contact_info => |ci| {
            var port: u16 = 0;
            for (ci.sockets.items) |s| {
                port += s.port_offset.value;
                return switch (ci.ips.items[s.idx]) {
                    .v4 => |ip| return .{ .v4 = .{ .ip = ip, .port = port } },
                    .v6 => |ip| return .{ .v6 = .{ .ip = ip, .port = port } },
                };
            }
            return error.InvalidContactInfo;
        },
        else => return error.InvalidContactInfo,
    }
}

fn signData(keypair: KeyPair, data_: CrdsData) !CrdsValue {
    var data = data_;
    switch (std.meta.activeTag(data)) {
        inline else => |tag| {
            @field(data, @tagName(tag)).from = .{ .data = keypair.public_key.bytes };
            switch (@TypeOf(@field(data, @tagName(tag)).wallclock)) {
                VarInt(u64) => @field(data, @tagName(tag)).wallclock = .{ .value = realtime() },
                u64 => @field(data, @tagName(tag)).wallclock = realtime(),
                else => @compileError("invalid wallclock field"),
            }
        }
    }

    var buf: [MTU]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try bincode.write(fbs.writer(), data);

    return .{
        .signature = .fromSignature(try keypair.sign(fbs.getWritten(), null)),
        .data = data,
        .bytes = &.{},
    };
}

fn realtime() u64 {
    return @intCast(std.time.milliTimestamp());
}

const bincode = struct {
    fn read(gpa: std.mem.Allocator, reader: anytype, comptime T: type) !T {
        // std.debug.print(" reading {s}\n", .{@typeName(T)});
        switch (@typeInfo(T)) {
            .int => return reader.readInt(T, .little),
            .array => |info| {
                comptime std.debug.assert(@typeInfo(info.child) == .int);
                var v: T = undefined;
                _ = try reader.readAll(std.mem.asBytes(&v));
                return v;
            },
            .pointer => |info| {
                comptime std.debug.assert(info.size == .slice);
                const n = try reader.readInt(u64, .little);
                const slice = try gpa.alloc(info.child, n);
                switch (@typeInfo(info.child)) {
                    .int => _ = try reader.readAll(std.mem.sliceAsBytes(slice)),
                    else => {
                        for (0..n) |i| slice[i] = try read(gpa, reader, info.child);
                    },
                }
                return slice;
            },
            .optional => |info| switch (try reader.readByte()) {
                0 => return null,
                1 => return try read(gpa, reader, info.child),
                else => return error.InvalidOptional,
            },
            .@"enum" => |info| {
                return try std.meta.intToEnum(T, try read(gpa, reader, info.tag_type));
            },
            .@"union" => |info| switch (try read(gpa, reader, info.tag_type.?)) {
                inline else => |tag| {
                    const Variant = @TypeOf(@field(@as(T, undefined), @tagName(tag)));
                    return @unionInit(T, @tagName(tag), try read(gpa, reader, Variant));
                },
            },
            .@"struct" => |info| {
                if (@hasDecl(T, "bincodeRead")) return T.bincodeRead(gpa, reader);
                var v: T = undefined;
                inline for (info.fields) |f| @field(v, f.name) = try read(gpa, reader, f.type);
                return v;
            },
            else => @compileError("invalid bincode type"),
        }
    }

    fn write(writer: anytype, value: anytype) !void {
        const T = @TypeOf(value);
        switch (@typeInfo(T)) {
            .int => try writer.writeInt(T, value, .little),
            .array => {
                comptime std.debug.assert(@typeInfo(@TypeOf(value[0])) == .int);
                try writer.writeAll(std.mem.asBytes(&value));
            },
            .pointer => |info| {
                comptime std.debug.assert(info.size == .slice);
                try write(writer, @as(u64, value.len));
                for (value) |v| try write(writer, v);
            },
            .optional => {
                try writer.writeByte(@intFromBool(value != null));
                if (value) |v| try write(writer, v);
            },
            .@"enum" => try write(writer, @intFromEnum(value)),
            .@"union" => switch (value) {
                inline else => |v| {
                    try write(writer, std.meta.activeTag(value));
                    try write(writer, v);
                },
            },
            .@"struct" => |info| {
                if (@hasDecl(T, "bincodeWrite")) return value.bincodeWrite(writer);
                inline for (info.fields) |f| try write(writer, @field(value, f.name));
            },
            else => @compileError("invalid bincode type"),
        }
    }
};

fn VarInt(comptime T: type) type {
    return struct {
        value: T,

        pub fn bincodeRead(_: std.mem.Allocator, reader: anytype) !@This() {
            var v: T = 0;
            var i: std.math.Log2Int(T) = 0;
            while (true) : (i += 7) {
                const b = try reader.readByte();
                v |= @as(T, b & 0x7f) << i;
                if (b & 0x80 == 0) return .{ .value = v };
            }
        }

        pub fn bincodeWrite(self: @This(), writer: anytype) !void {
            var v = self.value;
            while (v > 0x7f) : (v >>= 7)
                try writer.writeByte(@intCast((v & 0x7f) | 0x80));
            try writer.writeByte(@as(u8, @intCast(v)));
        }
    };
}

const Timestamp = u64;
const ShredVersion = u16;

const EchoMessage = struct {
    _hidden_http_header: u32 = 0,
    tcp_ports: [4]u16,
    udp_ports: [4]u16,
    _hidden_trailer: u8 = '\n',
};

const EchoResponse = struct {
    _hidden_header: u32,
    addr: IpAddr,
    shred_version: ?ShredVersion,
};

const IpAddr = union(enum(u32)) {
    v4: [4]u8,
    v6: [16]u8,
};

const GossipMessage = union(enum(u32)) {
    pull_request: PullRequest,
    pull_response: PullResponse,
    push_message: PushMessage,
    prune_message: PruneMessage,
    ping_message: struct {
        from: Pubkey,
        token: [32]u8,
        signature: Signature,
    },
    pong_message: struct {
        from: Pubkey,
        hash: Hash,
        signature: Signature,
    },
};

const PruneMessage = struct {
    from: Pubkey,
    data: struct {
        pubkey: Pubkey,
        prunes: []const Pubkey,
        signature: Signature,
        dest: Pubkey,
        wallclock: Timestamp,
    },
};

const PullResponse = struct {
    from: Pubkey,
    values: []const CrdsValue,
};

const PushMessage = struct {
    from: Pubkey,
    values: []const CrdsValue,
};

const PullRequest = struct {
    filter: struct {
        keys: []const u64,
        words: BitVec(u64),
        num_bits: u64,
    },
    mask: u64,
    mask_bits: u32,
    contact_info: CrdsValue,
};

const CrdsValue = struct {
    signature: Signature,
    data: CrdsData,
    bytes: []const u8,

    pub fn bincodeRead(gpa: std.mem.Allocator, reader: anytype) !@This() {
        const signature = try bincode.read(gpa, reader, Signature);
        const start = reader.context.pos;
        const data = try bincode.read(gpa, reader, CrdsData);
        const end = reader.context.pos;
        return .{ .signature = signature, .data = data, .bytes = reader.context.buffer[start..end] };
    }

    pub fn bincodeWrite(self: @This(), writer: anytype) !void {
        try bincode.write(writer, self.signature);
        try bincode.write(writer, self.data);
    }
};

const LegacyContactInfo = struct {
    from: Pubkey,
    gossip: SocketAddr,
    tvu: SocketAddr,
    tvu_quic: SocketAddr,
    serve_repair_quic: SocketAddr,
    tpu: SocketAddr,
    tpu_forwards: SocketAddr,
    tpu_vote: SocketAddr,
    rpc: SocketAddr,
    rpc_pubsub: SocketAddr,
    serve_repair: SocketAddr,
    wallclock: Timestamp,
    shred_version: ShredVersion,
};

const Vote = struct {
    index: u8,
    from: Pubkey,
    transaction: struct {
        signatures: ShortVec(Signature),
        message: struct {
            num_signatures: u8,
            num_readonly_signed: u8,
            num_readonly_unsigned: u8,
            accounts: ShortVec(Pubkey),
            recent_blockhash: Hash,
            instructions: ShortVec(struct {
                program_id: u8,
                accounts: ShortVec(u8),
                data: ShortVec(u8),
            }),
        },
    },
    wallclock: Timestamp,
    // slot: Slot,
};

const LowestSlot = struct {
    index: u8,
    from: Pubkey,
    _root: Slot, // deprecated
    lowest: Slot,
    _slots: []const Slot, // deprecated
    _stashes: []const struct { // deprecated
        first_slot: Slot,
        compression: enum(u32) {
            uncompressed,
            gzip,
            bzip2,
        },
        bytes: []const u8,
    },
    wallclock: Timestamp,
};

const EpochSlots = struct {
    index: u8,
    from: Pubkey,
    slots: []const union(enum(u32)) {
        flate2: Flate2,
        uncompressed: Uncompressed,
    },
    wallclock: Timestamp,
};

const Flate2 = struct {
    first_slot: Slot,
    num_slots: u64,
    compressed: []const u8,
};

const Uncompressed = struct {
    first_slot: Slot,
    num_slots: u64,
    slots: BitVec(u8),
};

const LegacyVersion = struct {
    from: Pubkey,
    wallclock: Timestamp,
    version: Version,
};

const LegacyVersion2 = struct {
    from: Pubkey,
    wallclock: Timestamp,
    version: Version,
    feature_set: u32,
}; 

const NodeInstance = struct {
    from: Pubkey,
    wallclock: Timestamp,
    created: Timestamp,
    token: u64,
};

const DuplicateShred = struct {
    index: u16,
    from: Pubkey,
    wallclock: Timestamp,
    slot: Slot,
    _unused: u32,
    _shred_type: enum(u8) {
        data = 0b10100101,
        code = 0b01011010,
    },
    num_chunks: u8,
    chunk_idx: u8,
    chunk: []const u8,
};

const SnapshotHashes = struct {
    from: Pubkey,
    full: SlotAndHash,
    incremental: []const SlotAndHash,
    wallclock: Timestamp,
};

const RestartLast = struct {
    from: Pubkey,
    wallclock: Timestamp,
    offsets: []const union(enum(u32)) {
        rle: []const VarInt(u16),
        raw: BitVec(u8),
    },
    last_voted: SlotAndHash,
    shred_version: ShredVersion,
};

const RestartHeaviest = struct {
    from: Pubkey,
    wallclock: Timestamp,
    last_slot: SlotAndHash,
    observed_stake: u64,
    shred_version: ShredVersion,
};

const CrdsData = union(enum(u32)) {
    legacy_contact_info: LegacyContactInfo,
    vote: Vote,
    lowest_slot: LowestSlot,
    legacy_snapshot_hashes: AccountHashes,
    account_hashes: AccountHashes,
    epoch_slots: EpochSlots,
    legacy_version: LegacyVersion,
    version: LegacyVersion2,
    node_instance: NodeInstance,
    duplicate_shred: DuplicateShred,
    snapshot_hashes: SnapshotHashes,
    contact_info: ContactInfo,
    restart_last_voted_fork_slots: RestartLast,
    restart_heaviest_fork: RestartHeaviest,
};

fn BitVec(comptime T: type) type {
    return struct {
        bits: ?[]const T,
        len: u64,
    };
}

fn ShortVec(comptime T: type) type {
    return struct {
        items: []const T,

        pub fn bincodeRead(gpa: std.mem.Allocator, reader: anytype) !@This() {
            const len = try bincode.read(gpa, reader, VarInt(u16));
            const items = try gpa.alloc(T, len.value);
            for (items) |*v| v.* = try bincode.read(gpa, reader, T);
            return .{ .items = items };
        }

        pub fn bincodeWrite(self: @This(), writer: anytype) !void {
            try bincode.write(writer, VarInt(u16){ .value = @intCast(self.items.len) });
            for (self.items) |v| try bincode.write(writer, v); 
        }
    };
}

const ContactInfo = struct {
    from: Pubkey,
    wallclock: VarInt(Timestamp),
    created: Timestamp,
    shred_version: ShredVersion,
    major: VarInt(u16),
    minor: VarInt(u16),
    patch: VarInt(u16),
    commit: u32,
    feature_set: u32,
    client_id: VarInt(u16),
    ips: ShortVec(IpAddr),
    sockets: ShortVec(struct {
        key: enum(u8) {
            gossip,
            serve_repair_quic,
            rpc,
            rpc_pubsub,
            serve_repair,
            tpu,
            tpu_forwards,
            tpu_forwards_quic,
            tpu_quic,
            tpu_vote,
            tvu,
            tvu_quic,
            tpu_vote_quic,
            alpenglow,
            _,
        },
        idx: u8,
        port_offset: VarInt(u16),
    }),
    extensions: ShortVec(struct{
        typ: u8,
        bytes: ShortVec(u8),
    }),
};

const SocketAddr = union(enum(u32)) {
    v4: struct {
        ip: [4]u8,
        port: u16,
    },
    v6: struct {
        ip: [16]u8,
        port: u16,
    },
};

const AccountHashes = struct {
    from: Pubkey,
    slot_hashes: []const SlotAndHash,
    wallclock: Timestamp,
};

const SlotAndHash = struct {
    slot: Slot,
    hash: Hash,
};

const Version = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: ?u16,
};

