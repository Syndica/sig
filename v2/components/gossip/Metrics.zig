const lib = @import("lib");
const api = @import("api");
const tel = lib.telemetry;

const Metrics = @This();
discoveries: tel.Variant(api.GossipData),

valid_packets: tel.Counter,
invalid_packets: tel.Counter,

processed_messages: tel.Variant(api.GossipMessage),
invalid_messages: tel.Variant(InvalidMessage),

pushed_messages: tel.Variant(api.GossipMessage),
pushed_values: tel.Variant(api.GossipData),

table_entry_count: tel.Variant(api.GossipData),

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
