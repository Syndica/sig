const std = @import("std");
const sig = @import("../../../sig.zig");

const program = sig.runtime.program;
const svm = sig.svm;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

const Region = sig.svm.memory.Region;

// pub fn serializeAligned(allocator: std.mem.Allocator, ic: *InstructionContext, )
