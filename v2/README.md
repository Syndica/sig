# Running Shred Receive

1. Advertise yourself on gossip. This can be done with starting up v1 gossip, with a patch to 
advertise a turbine receive port.

```diff
--- a/src/cmd.zig
+++ b/src/cmd.zig
@@ -1058,13 +1058,16 @@ fn gossip(
         app_base.shutdown();
         app_base.deinit();
     }
 
     const gossip_service = try startGossip(
         allocator,
         gossip_value_allocator,
         cfg,
         &app_base,
-        &.{},
+        &.{.{ .tag = .turbine_recv, .port = 8002 }},
         .{},
     );
     defer {
```

`sig gossip -c testnet`

2. Use Agave to create a leader schedule text file, e.g.

`solana leader-schedule > schedule.txt`

3. Start up v2

`zig build run -- config/testnet.zig.zon `

# Running with tracy

1. Build with `-Denable-tracy`

2. Use `.sandboxing_mode = .threaded` in your config