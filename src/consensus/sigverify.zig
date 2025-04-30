//! Subset of code based on: https://github.com/anza-xyz/agave/blob/cb32984a9b0d5c2c6f7775bed39b66d3a22e3c46/perf/src/sigverify.rs

const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const Ed25519 = std.crypto.sign.Ed25519;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const Packet = sig.net.Packet;

pub const solana_message = struct {
    /// Bit mask that indicates whether a serialized message is versioned.
    pub const MESSAGE_VERSION_PREFIX: u8 = 0x80;

    /// The length of a message header in bytes.
    pub const MESSAGE_HEADER_LENGTH: usize = 3;
};

/// #[derive(Debug, PartialEq, Eq)]
const PacketOffsets = struct {
    sig_len: u32,
    sig_start: u32,
    msg_start: u32,
    pubkey_start: u32,
    pubkey_len: u32,
};

// fn get_packet_offsets(
//     packet: *Packet,
//     current_offset: usize,
//     reject_non_vote: bool,
// ) PacketOffsets {
//     const unsanitized_packet_offsets = do_get_packet_offsets(packet, current_offset);
//     if (unsanitized_packet_offsets) |offsets| {
//         check_for_simple_vote_transaction(packet, &offsets, current_offset).ok();
//         if (!reject_non_vote || packet.meta().is_simple_vote_tx()) {
//             return offsets;
//         }
//     }
//     // force sigverify to fail by returning zeros
//     return .{ 0, 0, 0, 0, 0 };
// }

const PacketError = error{
    InvalidLen,
    InvalidPubkeyLen,
    InvalidShortVec,
    InvalidSignatureLen,
    MismatchSignatureLen,
    PayerNotWritable,
    InvalidProgramIdIndex,
    InvalidProgramLen,
    UnsupportedVersion,
};

// internal function to be unit-tested; should be used only by get_packet_offsets
fn do_get_packet_offsets(
    packet: *const Packet,
    current_offset: usize,
) PacketError!PacketOffsets {
    // should have at least 1 signature and sig lengths
    if (1 + Signature.SIZE > packet.size) {
        return error.InvalidLen;
    }

    // read the length of Transaction.signatures (serialized with short_vec)
    const sig_len_untrusted, const sig_size = blk: {
        var fbs = std.io.fixedBufferStream(packet.data());
        const deserializeShortU16 = sig.bincode.varint.deserializeShortU16;
        break :blk deserializeShortU16(fbs.reader()) catch return error.InvalidShortVec;
    };

    // Using msg_start_offset which is based on sig_len_untrusted introduces uncertainty.
    // Ultimately, the actual sigverify will determine the uncertainty.
    const MSG_START_OFFSET_MAX =
        Signature.SIZE *
        std.math.maxInt(@TypeOf(sig_len_untrusted)) +
        std.math.maxInt(@TypeOf(sig_size));
    const MsgStartOffset = std.math.IntFittingRange(0, MSG_START_OFFSET_MAX);
    const msg_start_offset: u21 =
        @as(MsgStartOffset, sig_len_untrusted) * Signature.SIZE + sig_size;

    const MSG_HEADER_OFFSET_MAX = MSG_START_OFFSET_MAX + 1;
    const MsgHeaderOffset = std.math.IntFittingRange(0, MSG_HEADER_OFFSET_MAX);
    // Determine the start of the message header by checking the message prefix bit.
    const msg_header_offset: u21 = blk: {
        // Packet should have data for prefix bit
        if (msg_start_offset >= packet.size) {
            return error.InvalidSignatureLen;
        }

        // next byte indicates if the transaction is versioned. If the top bit
        // is set, the remaining bits encode a version number. If the top bit is
        // not set, this byte is the first byte of the message header.

        const message_prefix = packet.data()[msg_start_offset];
        if (message_prefix & solana_message.MESSAGE_VERSION_PREFIX == 0) {
            break :blk msg_start_offset;
        }

        const version = message_prefix & ~solana_message.MESSAGE_VERSION_PREFIX;
        break :blk switch (version) {
            // currently only v0 is supported
            _ => return error.UnsupportedVersion,

            // NOTE: here in the equivalent agave code, it checked if `msg_start_offset + 1`
            // overflowed as a usize, but `msg_start_offset` can't be greater than a much
            // lower value logically, and that is reflected in its narrower type in this code,
            // and the absence of that redundant check.
            // HOWEVER: it's possible that's a bug in the agave implementation and it's supposed
            // to be checking overflow as a u16 - this is not clear.
            0 => @as(MsgHeaderOffset, msg_start_offset) + 1,
        };
    };

    const MSG_HEADER_OFFSET_PLUS_ONE_MAX = MSG_HEADER_OFFSET_MAX + 1;
    const MsgHeaderOffsetPlusOne = std.math.IntFittingRange(0, MSG_HEADER_OFFSET_PLUS_ONE_MAX);
    const msg_header_offset_plus_one: u21 = @as(MsgHeaderOffsetPlusOne, msg_header_offset) + 1;

    { // Packet should have data at least for MessageHeader and 1 byte for Message.account_keys.len
        const value = std.math.add(
            usize,
            msg_header_offset_plus_one,
            solana_message.MESSAGE_HEADER_LENGTH,
        ) catch return error.InvalidSignatureLen;
        if (value > packet.size) return error.InvalidSignatureLen;
    }

    // read MessageHeader.num_required_signatures (serialized with u8)
    if (msg_header_offset >= packet.size) return error.InvalidSignatureLen;
    const sig_len_maybe_trusted = packet.data()[msg_header_offset];
    const message_account_keys_len_offset = std.math.add(
        usize,
        msg_header_offset,
        solana_message.MESSAGE_HEADER_LENGTH,
    ) catch return error.InvalidSignatureLen;

    // This reads and compares the MessageHeader num_required_signatures and
    // num_readonly_signed_accounts bytes. If num_required_signatures is not larger than
    // num_readonly_signed_accounts, the first account is not debitable, and cannot be charged
    // required transaction fees.
    const readonly_signer_offset = msg_header_offset_plus_one;
    if (readonly_signer_offset >= packet.size) return error.InvalidSignatureLen;
    if (sig_len_maybe_trusted <= packet.data()[readonly_signer_offset]) {
        return error.PayerNotWritable;
    }

    if (sig_len_maybe_trusted != sig_len_untrusted) {
        return error.MismatchSignatureLen;
    }

    // read the length of Message.account_keys (serialized with short_vec)
    const pubkey_len, const pubkey_len_size = blk: {
        var fbs = std.io.fixedBufferStream(packet.data()[message_account_keys_len_offset..]);
        const deserializeShortU16 = sig.bincode.varint.deserializeShortU16;
        break :blk deserializeShortU16(fbs.reader()) catch return error.InvalidShortVec;
    };

    const pubkey_start_offset = std.math.add(
        usize,
        message_account_keys_len_offset,
        pubkey_len_size,
    ) catch return error.InvalidPubkeyLen;

    {
        var v = std.math.mul(usize, pubkey_len, Pubkey.SIZE) catch return error.InvalidPubkeyLen;
        v = std.math.add(usize, v, pubkey_start_offset) catch return error.InvalidPubkeyLen;
        if (v > packet.size) return error.InvalidPubkeyLen;
    }

    if (pubkey_len < sig_len_untrusted) {
        return error.InvalidPubkeyLen;
    }

    const sig_start = std.math.add(
        usize,
        current_offset,
        sig_size,
    ) catch return error.InvalidLen;
    const msg_start = std.math.add(
        usize,
        current_offset,
        msg_start_offset,
    ) catch return error.InvalidLen;
    const pubkey_start = std.math.add(
        usize,
        current_offset,
        pubkey_start_offset,
    ) catch return error.InvalidLen;

    return .{
        .sig_len = sig_len_untrusted,
        .sig_start = sig_start,
        .msg_start = msg_start,
        .pubkey_start = pubkey_start,
        .pubkey_len = pubkey_len,
    };
}

fn packetFromNumSigs(required_num_sigs: u8, comptime actual_num_sigs: usize) Packet {
    const message: sig.core.transaction.TransactionMessage = .{
        .signature_count = required_num_sigs,
        .readonly_signed_count = 12,
        .readonly_unsigned_count = 11,

        .account_keys = &.{},
        .recent_blockhash = Hash.ZEROES,
        .instructions = &.{},
    };
    const tx: sig.core.Transaction = .{
        .signatures = comptime &[_]Signature{Signature.ZEROES} ** actual_num_sigs,
        .version = .legacy,
        .msg = message,
    };
    return Packet.initFromData(null, tx);
}

test "untrustworthy_sigs" {
    const required_num_sigs = 14;
    const actual_num_sigs = 5;

    const packet = packetFromNumSigs(required_num_sigs, actual_num_sigs);

    const unsanitized_packet_offsets = do_get_packet_offsets(&packet, 0);

    try std.testing.expectError(
        error.MismatchSignatureLen,
        unsanitized_packet_offsets,
    );
    return error.foo;
}

test "small_packet" {
    // let tx = test_tx();
    // let mut packet = Packet::from_data(None, tx).unwrap();

    // packet.buffer_mut()[0] = 0xff;
    // packet.buffer_mut()[1] = 0xff;
    // packet.meta_mut().size = 2;

    // let res = sigverify::do_get_packet_offsets(&packet, 0);
    // assert_eq!(res, Err(PacketError::InvalidLen));
}

test "pubkey_too_small" {
    // solana_logger::setup();
    // let mut tx = test_tx();
    // let sig = tx.signatures[0];
    // const NUM_SIG: usize = 18;
    // tx.signatures = vec![sig; NUM_SIG];
    // tx.message.account_keys = vec![];
    // tx.message.header.num_required_signatures = NUM_SIG as u8;
    // let mut packet = Packet::from_data(None, tx).unwrap();

    // let res = sigverify::do_get_packet_offsets(&packet, 0);
    // assert_eq!(res, Err(PacketError::InvalidPubkeyLen));

    // assert!(!verify_packet(&mut packet, false));

    // packet.meta_mut().set_discard(false);
    // let mut batches = generate_packet_batches(&packet, 1, 1);
    // ed25519_verify(&mut batches);
    // assert!(batches[0][0].meta().discard());
}

test "pubkey_len" {
    // // See that the verify cannot walk off the end of the packet
    // // trying to index into the account_keys to access pubkey.
    // solana_logger::setup();

    // const NUM_SIG: usize = 17;
    // let keypair1 = Keypair::new();
    // let pubkey1 = keypair1.pubkey();
    // let mut message = Message::new(&[], Some(&pubkey1));
    // message.account_keys.push(pubkey1);
    // message.account_keys.push(pubkey1);
    // message.header.num_required_signatures = NUM_SIG as u8;
    // message.recent_blockhash = Hash::new_from_array(pubkey1.to_bytes());
    // let mut tx = Transaction::new_unsigned(message);

    // info!("message: {:?}", tx.message_data());
    // info!("tx: {:?}", tx);
    // let sig = keypair1.try_sign_message(&tx.message_data()).unwrap();
    // tx.signatures = vec![sig; NUM_SIG];

    // let mut packet = Packet::from_data(None, tx).unwrap();

    // let res = sigverify::do_get_packet_offsets(&packet, 0);
    // assert_eq!(res, Err(PacketError::InvalidPubkeyLen));

    // assert!(!verify_packet(&mut packet, false));

    // packet.meta_mut().set_discard(false);
    // let mut batches = generate_packet_batches(&packet, 1, 1);
    // ed25519_verify(&mut batches);
    // assert!(batches[0][0].meta().discard());
}

test "large_sig_len" {
    // let tx = test_tx();
    // let mut packet = Packet::from_data(None, tx).unwrap();

    // // Make the signatures len huge
    // packet.buffer_mut()[0] = 0x7f;

    // let res = sigverify::do_get_packet_offsets(&packet, 0);
    // assert_eq!(res, Err(PacketError::InvalidSignatureLen));
}

test "really_large_sig_len" {
    // let tx = test_tx();
    // let mut packet = Packet::from_data(None, tx).unwrap();

    // // Make the signatures len huge
    // packet.buffer_mut()[0] = 0xff;
    // packet.buffer_mut()[1] = 0xff;
    // packet.buffer_mut()[2] = 0xff;
    // packet.buffer_mut()[3] = 0xff;

    // let res = sigverify::do_get_packet_offsets(&packet, 0);
    // assert_eq!(res, Err(PacketError::InvalidShortVec));
}

test "invalid_pubkey_len" {
    // let tx = test_tx();
    // let mut packet = Packet::from_data(None, tx).unwrap();

    // let res = sigverify::do_get_packet_offsets(&packet, 0);

    // // make pubkey len huge
    // packet.buffer_mut()[res.unwrap().pubkey_start as usize - 1] = 0x7f;

    // let res = sigverify::do_get_packet_offsets(&packet, 0);
    // assert_eq!(res, Err(PacketError::InvalidPubkeyLen));
}

test "fee_payer_is_debitable" {
    // let message = Message {
    //     header: MessageHeader {
    //         num_required_signatures: 1,
    //         num_readonly_signed_accounts: 1,
    //         num_readonly_unsigned_accounts: 1,
    //     },
    //     account_keys: vec![],
    //     recent_blockhash: Hash::default(),
    //     instructions: vec![],
    // };
    // let mut tx = Transaction::new_unsigned(message);
    // tx.signatures = vec![Signature::default()];
    // let packet = Packet::from_data(None, tx).unwrap();
    // let res = sigverify::do_get_packet_offsets(&packet, 0);

    // assert_eq!(res, Err(PacketError::PayerNotWritable));
}

test "unsupported_version" {
    // let tx = test_tx();
    // let mut packet = Packet::from_data(None, tx).unwrap();

    // let res = sigverify::do_get_packet_offsets(&packet, 0);

    // // set message version to 1
    // packet.buffer_mut()[res.unwrap().msg_start as usize] = MESSAGE_VERSION_PREFIX + 1;

    // let res = sigverify::do_get_packet_offsets(&packet, 0);
    // assert_eq!(res, Err(PacketError::UnsupportedVersion));
}

test "versioned_message" {
    // let tx = test_tx();
    // let mut packet = Packet::from_data(None, tx).unwrap();

    // let mut legacy_offsets = sigverify::do_get_packet_offsets(&packet, 0).unwrap();

    // // set message version to 0
    // let msg_start = legacy_offsets.msg_start as usize;
    // let msg_bytes = packet.data(msg_start..).unwrap().to_vec();
    // packet.buffer_mut()[msg_start] = MESSAGE_VERSION_PREFIX;
    // packet.meta_mut().size += 1;
    // let msg_end = packet.meta().size;
    // packet.buffer_mut()[msg_start + 1..msg_end].copy_from_slice(&msg_bytes);

    // let offsets = sigverify::do_get_packet_offsets(&packet, 0).unwrap();
    // let expected_offsets = {
    //     legacy_offsets.pubkey_start += 1;
    //     legacy_offsets
    // };

    // assert_eq!(expected_offsets, offsets);
}

test "is_simple_vote_transaction" {
    // solana_logger::setup();
    // let mut rng = rand::thread_rng();

    // // tansfer tx is not
    // {
    //     let mut tx = test_tx();
    //     tx.message.instructions[0].data = vec![1, 2, 3];
    //     let mut packet = Packet::from_data(None, tx).unwrap();
    //     let packet_offsets = do_get_packet_offsets(&packet, 0).unwrap();
    //     check_for_simple_vote_transaction(&mut packet, &packet_offsets, 0).ok();
    //     assert!(!packet.meta().is_simple_vote_tx());
    // }

    // // single legacy vote tx is
    // {
    //     let mut tx = new_test_vote_tx(&mut rng);
    //     tx.message.instructions[0].data = vec![1, 2, 3];
    //     let mut packet = Packet::from_data(None, tx).unwrap();
    //     let packet_offsets = do_get_packet_offsets(&packet, 0).unwrap();
    //     check_for_simple_vote_transaction(&mut packet, &packet_offsets, 0).ok();
    //     assert!(packet.meta().is_simple_vote_tx());
    // }

    // // single versioned vote tx is not
    // {
    //     let mut tx = new_test_vote_tx(&mut rng);
    //     tx.message.instructions[0].data = vec![1, 2, 3];
    //     let mut packet = Packet::from_data(None, tx).unwrap();

    //     // set messager version to v0
    //     let mut packet_offsets = do_get_packet_offsets(&packet, 0).unwrap();
    //     let msg_start = packet_offsets.msg_start as usize;
    //     let msg_bytes = packet.data(msg_start..).unwrap().to_vec();
    //     packet.buffer_mut()[msg_start] = MESSAGE_VERSION_PREFIX;
    //     packet.meta_mut().size += 1;
    //     let msg_end = packet.meta().size;
    //     packet.buffer_mut()[msg_start + 1..msg_end].copy_from_slice(&msg_bytes);

    //     packet_offsets = do_get_packet_offsets(&packet, 0).unwrap();
    //     check_for_simple_vote_transaction(&mut packet, &packet_offsets, 0).ok();
    //     assert!(!packet.meta().is_simple_vote_tx());
    // }

    // // multiple mixed tx is not
    // {
    //     let key = Keypair::new();
    //     let key1 = Pubkey::new_unique();
    //     let key2 = Pubkey::new_unique();
    //     let tx = Transaction::new_with_compiled_instructions(
    //         &[&key],
    //         &[key1, key2],
    //         Hash::default(),
    //         vec![solana_vote_program::id(), Pubkey::new_unique()],
    //         vec![
    //             CompiledInstruction::new(3, &(), vec![0, 1]),
    //             CompiledInstruction::new(4, &(), vec![0, 2]),
    //         ],
    //     );
    //     let mut packet = Packet::from_data(None, tx).unwrap();
    //     let packet_offsets = do_get_packet_offsets(&packet, 0).unwrap();
    //     check_for_simple_vote_transaction(&mut packet, &packet_offsets, 0).ok();
    //     assert!(!packet.meta().is_simple_vote_tx());
    // }

    // // single legacy vote tx with extra (invalid) signature is not
    // {
    //     let mut tx = new_test_vote_tx(&mut rng);
    //     tx.signatures.push(Signature::default());
    //     tx.message.header.num_required_signatures = 3;
    //     tx.message.instructions[0].data = vec![1, 2, 3];
    //     let mut packet = Packet::from_data(None, tx).unwrap();
    //     let packet_offsets = do_get_packet_offsets(&packet, 0).unwrap();
    //     assert_eq!(
    //         Err(PacketError::InvalidSignatureLen),
    //         check_for_simple_vote_transaction(&mut packet, &packet_offsets, 0)
    //     );
    //     assert!(!packet.meta().is_simple_vote_tx());
    // }
}

test "is_simple_vote_transaction_with_offsets" {
    // solana_logger::setup();
    // let mut rng = rand::thread_rng();

    // // batch of legacy messages
    // {
    //     let mut current_offset = 0usize;
    //     let mut batch = PacketBatch::default();
    //     batch.push(Packet::from_data(None, test_tx()).unwrap());
    //     let tx = new_test_vote_tx(&mut rng);
    //     batch.push(Packet::from_data(None, tx).unwrap());
    //     batch.iter_mut().enumerate().for_each(|(index, packet)| {
    //         let packet_offsets = do_get_packet_offsets(packet, current_offset).unwrap();
    //         check_for_simple_vote_transaction(packet, &packet_offsets, current_offset).ok();
    //         if index == 1 {
    //             assert!(packet.meta().is_simple_vote_tx());
    //         } else {
    //             assert!(!packet.meta().is_simple_vote_tx());
    //         }

    //         current_offset = current_offset.saturating_add(size_of::<Packet>());
    //     });
    // }

    // // batch of mixed legacy messages and versioned vote tx, which won't be flagged as
    // // simple_vote_tx
    // {
    //     let mut current_offset = 0usize;
    //     let mut batch = PacketBatch::default();
    //     batch.push(Packet::from_data(None, test_tx()).unwrap());
    //     // versioned vote tx
    //     let tx = new_test_vote_tx(&mut rng);
    //     let mut packet = Packet::from_data(None, tx).unwrap();
    //     let packet_offsets = do_get_packet_offsets(&packet, 0).unwrap();
    //     let msg_start = packet_offsets.msg_start as usize;
    //     let msg_bytes = packet.data(msg_start..).unwrap().to_vec();
    //     packet.buffer_mut()[msg_start] = MESSAGE_VERSION_PREFIX;
    //     packet.meta_mut().size += 1;
    //     let msg_end = packet.meta().size;
    //     packet.buffer_mut()[msg_start + 1..msg_end].copy_from_slice(&msg_bytes);
    //     batch.push(packet);

    //     batch.iter_mut().for_each(|packet| {
    //         let packet_offsets = do_get_packet_offsets(packet, current_offset).unwrap();
    //         check_for_simple_vote_transaction(packet, &packet_offsets, current_offset).ok();
    //         assert!(!packet.meta().is_simple_vote_tx());

    //         current_offset = current_offset.saturating_add(size_of::<Packet>());
    //     });
    // }
}

// /// Returns true if the signatrue on the packet verifies.
// /// Caller must do packet.set_discard(true) if this returns false.
// fn verify_packet(packet: *Packet, reject_non_vote: bool) bool {
//     const packet_offsets = get_packet_offsets(packet, 0, reject_non_vote);
//     var sig_start: usize = packet_offsets.sig_start;
//     var pubkey_start: usize = packet_offsets.pubkey_start;
//     const msg_start: usize = packet_offsets.msg_start;

//     if (packet_offsets.sig_len == 0) {
//         return false;
//     }

//     if (packet.size <= msg_start) {
//         return false;
//     }

//     for (0..packet_offsets.sig_len) |_| {
//         const pubkey_end = pubkey_start +| Pubkey.SIZE;
//         const sig_end = std.math.add(usize, sig_start, sig.core.Signature.SIZE) catch {
//             return false;
//         };
//         // let Some(Ok(signature)) = packet.data(sig_start..sig_end).map(Signature::try_from) else {
//         //     return false;
//         // };
//         // let Some(pubkey) = packet.data(pubkey_start..pubkey_end) else {
//         //     return false;
//         // };
//         // let Some(message) = packet.data(msg_start..) else {
//         //     return false;
//         // };
//         // if !signature.verify(pubkey, message) {
//         //     return false;
//         // }
//         pubkey_start = pubkey_end;
//         sig_start = sig_end;
//     }
//     return true;
// }

// pub fn ed25519_verify_cpu(
//     packets: []Packet,
//     reject_non_vote: bool,
//     packet_count: usize,
// ) void {
//     for (packets) |*packet| {
//         verify_packet(packet, reject_non_vote);
//     }
// }
