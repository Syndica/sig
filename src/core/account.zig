const std = @import("std");
const sig = @import("../sig.zig");

const Blake3 = std.crypto.hash.Blake3;

const Hash = sig.core.Hash;
const LtHash = sig.core.LtHash;
const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;

const AccountInFile = sig.accounts_db.accounts_file.AccountInFile;
const AccountDataHandle = sig.accounts_db.buffer_pool.AccountDataHandle;

pub const Account = struct {
    lamports: u64,
    data: AccountDataHandle,
    owner: Pubkey,
    executable: bool,
    rent_epoch: Epoch,

    pub fn deinit(self: Account, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
    }

    pub fn initRandom(allocator: std.mem.Allocator, random: std.Random, data_len: usize) !Account {
        const data_buf = try allocator.alloc(u8, data_len);
        errdefer allocator.free(data_buf);

        random.bytes(data_buf);
        const data = AccountDataHandle.initAllocatedOwned(data_buf);

        return .{
            .lamports = random.int(u64),
            .data = data,
            .owner = Pubkey.initRandom(random),
            .executable = random.boolean(),
            .rent_epoch = random.int(Epoch),
        };
    }

    // creates a copy of the account. most important is the copy of the data slice.
    pub fn cloneOwned(self: *const Account, allocator: std.mem.Allocator) !Account {
        return .{
            .lamports = self.lamports,
            .data = try self.data.dupeAllocatedOwned(allocator),
            .owner = self.owner,
            .executable = self.executable,
            .rent_epoch = self.rent_epoch,
        };
    }

    // creates a cheap borrow of an already-cached account
    pub fn cloneCached(self: *const Account, allocator: std.mem.Allocator) !Account {
        return .{
            .lamports = self.lamports,
            .data = try self.data.duplicateBufferPoolRead(allocator),
            .owner = self.owner,
            .executable = self.executable,
            .rent_epoch = self.rent_epoch,
        };
    }

    pub fn equals(self: *const Account, other: *const Account) bool {
        return self.data.eql(other.data) and
            self.lamports == other.lamports and
            self.owner.equals(&other.owner) and
            self.executable == other.executable and
            self.rent_epoch == other.rent_epoch;
    }

    /// gets the snapshot size of the account (when serialized)
    pub fn getSizeInFile(self: *const Account) usize {
        return std.mem.alignForward(
            usize,
            AccountInFile.STATIC_SIZE + self.data.len(),
            @sizeOf(u64),
        );
    }

    pub fn ltHash(self: *const Account, pubkey: Pubkey) LtHash {
        return self.doHash(LtHash, pubkey, false);
    }

    pub fn hash(self: *const Account, pubkey: Pubkey) Hash {
        return self.doHash(Hash, pubkey, true);
    }

    /// computes the blake3 hash of the account
    fn doHash(
        self: *const Account,
        HashType: type,
        pubkey: Pubkey,
        include_rent_epoch: bool,
    ) HashType {
        var the_hash: HashType = .{ .data = undefined };

        var iter = self.data.iterator();
        hashAccount(
            self.lamports,
            &iter,
            &self.owner.data,
            self.executable,
            if (include_rent_epoch) self.rent_epoch else null,
            &pubkey.data,
            the_hash.bytes(),
        );

        return the_hash;
    }

    /// writes account to buf in snapshot format
    pub fn writeToBuf(self: *const Account, pubkey: *const Pubkey, buf: []u8) usize {
        var offset: usize = 0;

        const storage_info = AccountInFile.StorageInfo{
            .write_version_obsolete = 0,
            .data_len = self.data.len(),
            .pubkey = pubkey.*,
        };
        offset += storage_info.writeToBuf(buf[offset..]);

        const account_info = AccountInFile.AccountInfo{
            .lamports = self.lamports,
            .rent_epoch = self.rent_epoch,
            .owner = self.owner,
            .executable = self.executable,
        };
        offset += account_info.writeToBuf(buf[offset..]);

        const account_hash = self.hash(pubkey.*);
        @memcpy(buf[offset..(offset + 32)], &account_hash.data);
        offset += 32;
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        self.data.readAll(buf[offset..][0..self.data.len()]);

        offset += self.data.len();
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        return offset;
    }
};

/// helper function for writing to memory
pub fn writeIntLittleMem(
    x: anytype,
    memory: []u8,
) usize {
    const Tx = @TypeOf(x);
    const x_size: usize = @bitSizeOf(Tx) / 8;
    std.mem.writeInt(Tx, memory[0..x_size], x, .little);
    return x_size;
}

pub fn hashAccount(
    lamports: u64,
    data: *AccountDataHandle.Iterator,
    owner_pubkey_data: []const u8,
    executable: bool,
    maybe_rent_epoch: ?u64,
    address_pubkey_data: []const u8,
    out_slice: []u8,
) void {
    var hasher = Blake3.init(.{});

    var int_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &int_buf, lamports, .little);
    hasher.update(&int_buf);

    if (maybe_rent_epoch) |rent_epoch| {
        std.mem.writeInt(u64, &int_buf, rent_epoch, .little);
        hasher.update(&int_buf);
    }

    while (data.nextFrame()) |frame_slice| {
        hasher.update(frame_slice);
    }

    if (executable) {
        hasher.update(&[_]u8{1});
    } else {
        hasher.update(&[_]u8{0});
    }

    hasher.update(owner_pubkey_data);
    hasher.update(address_pubkey_data);

    hasher.final(out_slice);
}

test "account hashes match agave" {
    var data: [3]u8 = .{ 1, 2, 3 };
    var account: Account = .{
        .lamports = 10,
        .data = AccountDataHandle.initAllocated(&data),
        .owner = Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 20,
    };
    const pubkey = Pubkey.ZEROES;

    const hash = account.hash(pubkey);
    const lt_hash = account.ltHash(pubkey);

    // sig fmt: off
    const expected_hash: [32]u8 = .{ 170, 75, 87, 73, 60, 156, 174, 14, 105, 6, 129, 108, 167, 156, 166, 213, 28, 4, 163, 187, 252, 155, 24, 253, 158, 13, 86, 100, 103, 89, 232, 28 };
    const expected_lt_hash: [1024]u16 = .{ 9303, 16250, 20633, 13770, 14411, 54090, 50287, 62816, 9907, 33548, 36293, 51944, 56404, 41969, 9848, 55108, 18690, 9078, 40235, 10254, 21538, 3775, 4358, 45967, 16269, 51244, 34128, 41448, 10100, 15292, 38409, 42651, 25423, 20258, 12929, 38402, 44031, 53836, 30233, 61367, 23883, 28410, 2258, 43562, 52758, 43807, 57172, 62796, 54036, 17181, 55380, 41071, 10662, 3101, 28954, 50907, 47054, 30514, 6721, 59560, 30847, 12282, 61805, 60666, 18602, 11608, 40931, 38963, 49831, 31835, 45602, 36702, 15049, 60691, 21900, 45759, 56980, 53748, 21281, 324, 49543, 10052, 51370, 49048, 50569, 41757, 55189, 60901, 12127, 29394, 14699, 2439, 22520, 32713, 39822, 1787, 56510, 33423, 47206, 49601, 11732, 4117, 24697, 21057, 32162, 56008, 55752, 28556, 55970, 63094, 36371, 53373, 10333, 16454, 20698, 40624, 2896, 623, 61179, 47653, 14567, 23489, 55424, 51327, 34728, 60371, 62162, 14476, 11760, 63360, 52351, 25640, 62149, 18676, 12829, 1805, 39688, 38941, 21359, 22051, 34349, 31928, 47487, 16289, 22266, 61914, 7449, 16561, 35628, 60205, 38902, 31136, 10932, 19098, 64276, 24233, 12547, 10033, 39002, 61093, 3393, 59381, 33205, 26163, 25545, 34332, 40304, 47771, 27169, 8259, 10690, 42378, 24328, 38944, 511, 30105, 11798, 34646, 31069, 41578, 11231, 24180, 539, 13817, 35342, 44477, 3025, 33521, 14490, 25681, 2431, 25210, 34571, 57691, 61480, 11755, 14513, 32983, 61778, 40460, 16127, 48331, 1233, 57119, 37143, 439, 43428, 49581, 62516, 3246, 43937, 45171, 2139, 42736, 60977, 15047, 34425, 23860, 50698, 65098, 51157, 654, 7783, 57191, 8505, 20600, 54669, 23184, 18762, 56870, 33526, 28978, 6025, 13003, 218, 52862, 16243, 35133, 48500, 30405, 34315, 11570, 48987, 25662, 29906, 14084, 4313, 48162, 26735, 47144, 50388, 626, 7385, 47513, 55476, 50547, 38819, 5493, 44658, 56519, 8665, 24651, 1251, 40644, 31219, 61573, 36065, 42737, 4701, 31875, 12355, 29132, 29238, 51715, 11511, 60330, 17362, 62887, 31448, 9637, 27584, 25180, 63452, 49228, 17320, 7880, 29959, 1974, 2268, 54881, 39903, 22071, 34239, 46585, 16708, 49666, 38591, 14566, 19559, 20156, 58647, 22544, 25523, 60987, 27094, 32391, 19983, 56574, 55358, 5566, 10197, 40624, 40044, 15617, 47937, 65429, 16287, 38317, 31094, 16060, 57927, 14355, 38637, 51514, 59493, 31456, 48897, 62988, 7817, 33105, 11029, 6891, 56438, 22908, 19774, 41480, 36503, 46693, 21958, 59460, 62408, 46775, 47041, 52688, 40055, 27861, 56184, 55575, 47715, 29005, 17102, 60058, 25829, 44495, 47737, 11733, 21770, 30796, 58741, 37452, 15527, 56620, 28862, 53234, 8098, 30112, 3203, 20295, 56440, 15192, 65522, 55251, 33328, 48055, 61216, 40439, 44432, 49192, 11427, 33627, 42795, 12724, 60435, 39003, 34976, 33644, 18692, 21429, 52290, 25263, 11492, 64410, 57287, 45481, 33342, 39347, 35657, 52791, 38070, 3965, 1325, 4363, 7017, 51320, 1503, 49622, 63090, 23508, 10734, 10293, 51245, 44453, 3585, 7210, 28368, 2556, 23157, 39486, 38239, 40460, 13587, 5343, 46336, 59044, 59916, 24776, 53132, 5670, 44114, 29960, 6081, 41350, 50540, 61337, 58873, 13678, 40922, 20636, 3697, 41086, 53143, 59405, 13176, 6172, 55216, 60979, 50520, 46218, 5216, 33554, 40630, 50274, 119, 30129, 2060, 30545, 64778, 12336, 55069, 6054, 21260, 58634, 2534, 41464, 13074, 16581, 19121, 36747, 13802, 8692, 9175, 1521, 39040, 22658, 58379, 49561, 27199, 57530, 4265, 18822, 5070, 30471, 26143, 14624, 16828, 46042, 52480, 62579, 4602, 28165, 25382, 64600, 5276, 27061, 25748, 35362, 15364, 12825, 26202, 32404, 21245, 68, 46056, 20641, 57140, 60484, 58583, 32125, 64852, 19752, 20292, 16165, 22671, 12925, 45465, 47131, 3134, 48730, 39980, 1695, 20133, 50098, 11928, 60457, 17687, 8823, 52709, 25455, 19352, 16390, 48387, 63010, 1600, 61682, 50497, 28018, 12635, 61428, 21707, 7637, 27507, 11120, 40790, 62319, 926, 35112, 38631, 31488, 52840, 42189, 8734, 55262, 54998, 37009, 13938, 1307, 2079, 63006, 16351, 18300, 57204, 30650, 35540, 12094, 21931, 37025, 12364, 56486, 18968, 27142, 21295, 54572, 40082, 46283, 60056, 42001, 38123, 22460, 9872, 21076, 52678, 28127, 3103, 23127, 53766, 45854, 63286, 39710, 43579, 42469, 40969, 3422, 2706, 30500, 6021, 37917, 31858, 9295, 54960, 14742, 15416, 50186, 13222, 56337, 52530, 64060, 51947, 44404, 50924, 6691, 16076, 39659, 231, 61512, 3760, 6610, 16752, 57223, 43368, 57735, 14586, 47311, 21610, 7251, 28190, 4494, 6161, 55413, 31112, 47296, 48108, 58867, 8597, 25856, 59480, 53483, 21209, 27957, 2831, 30389, 60273, 4785, 39526, 36889, 20026, 33718, 15497, 46575, 41882, 16380, 29183, 47019, 57022, 11636, 60806, 61245, 23367, 35894, 15957, 32759, 13982, 33240, 64390, 9908, 17606, 41937, 56868, 32683, 49594, 6553, 50988, 21737, 9749, 26743, 34889, 29097, 47751, 59500, 4226, 50709, 30396, 12221, 39138, 43439, 10349, 60080, 27836, 22311, 46165, 49196, 50230, 31835, 21483, 217, 60786, 22805, 26225, 46239, 34157, 7995, 28297, 9614, 45703, 2208, 49194, 25870, 7699, 3207, 61543, 55381, 30726, 34050, 37111, 51016, 22664, 50007, 19498, 11353, 23084, 15999, 59343, 26973, 11827, 8262, 12476, 46629, 9904, 30326, 57394, 17400, 18399, 8301, 9904, 52204, 16244, 21158, 28564, 5362, 6711, 8990, 45699, 17058, 40672, 51481, 19390, 38177, 1996, 16541, 2405, 57144, 38194, 53074, 12953, 28708, 12404, 57084, 35476, 8626, 31701, 25143, 47333, 50568, 21592, 28687, 19501, 52343, 12808, 25634, 12522, 37060, 57222, 57722, 58057, 28703, 27918, 36355, 30797, 47749, 26663, 33403, 27001, 12182, 10578, 49918, 12506, 33938, 22039, 57400, 51464, 44485, 39569, 52857, 39265, 55106, 63508, 29712, 2405, 33483, 60599, 34455, 45437, 23300, 52906, 58595, 48004, 22914, 53424, 29655, 28190, 22080, 35840, 42818, 20909, 35352, 4306, 14919, 7845, 58409, 22372, 9685, 24973, 63073, 4139, 49594, 40542, 24655, 39070, 59380, 28093, 14347, 10675, 61233, 22322, 12326, 30731, 41146, 26590, 62478, 12701, 26339, 29558, 44412, 48188, 1732, 17946, 13941, 15802, 16698, 3789, 21079, 63066, 24926, 63879, 17343, 4001, 7479, 29341, 31500, 6514, 51061, 60047, 7152, 4401, 28165, 26642, 43347, 2365, 16892, 9314, 59845, 36020, 29408, 11900, 10466, 16848, 50140, 58156, 8947, 870, 3325, 47912, 54341, 58680, 34301, 17143, 6975, 13208, 35615, 28694, 1883, 23680, 51196, 17525, 23260, 26489, 41059, 16087, 10782, 38557, 39983, 12665, 64696, 52513, 26235, 17955, 59109, 34070, 46511, 15574, 21711, 18291, 53129, 2414, 44983, 19928, 994, 20515, 46388, 28618, 62136, 53318, 41258, 60189, 7465, 54492, 60506, 43353, 31080, 27124, 12610, 9001, 35183, 29220, 37217, 21160, 26240, 64030, 49389, 58404, 41384, 33751, 1670, 44024, 56674, 45242, 5553, 48371, 33246, 18461, 55272, 61137, 1402, 45206, 50707, 53598, 50930, 52586, 60275, 4540, 23467, 51029, 63781, 33006, 49004, 36525, 15331, 10813, 62629, 1929, 27124, 43948, 3686, 61203, 16639, 16926, 12356, 23755, 25075, 10436, 55123, 63004, 40434, 474, 49681, 40090, 60063, 55906, 40213, 50583, 28102, 22775, 39869, 33545, 63821, 26400, 53007, 50565, 35165, 9761, 36146, 16110, 63645, 38822, 34639, 48570, 34671, 61984, 44760, 49585, 53187, 41054, 21927, 3017, 7614, 32693, 4732, 54128, 13422, 18075, 37253, 49016, 43786, 10084, 56584 };
    // sig fmt: on

    try std.testing.expectEqualSlices(u8, &expected_hash, &hash.data);
    try std.testing.expectEqualSlices(u16, &expected_lt_hash, &lt_hash.data);
}
