const lib = @import("../lib.zig");
const tel = lib.telemetry;

const Metrics = @This();
discoveries: tel.Variant(lib.gossip.GossipData),

valid_packets: tel.Counter,
invalid_packets: tel.Counter,

processed_messages: tel.Variant(lib.gossip.GossipMessage),
invalid_messages: tel.Variant(InvalidMessage),

pushed_messages: tel.Variant(lib.gossip.GossipMessage),
pushed_values: tel.Variant(lib.gossip.GossipData),

table_entry_count: tel.Variant(lib.gossip.GossipData),

pub const InvalidMessage = error{
    InvalidSignature,
    InvalidMessage,
    InvalidPubkey,
    UntrackedPeer,
    UnverifiedPeer,
    ExpiredPeer,
    InvalidContactInfo,
    InsertSigverifyFail,
    InvalidTableValue,
};

pub const config: tel.metric.FieldsConfig(Metrics) = .{
    .prefix = "gossip",
    .fields = .{
        .packets = .{},
    },
};
