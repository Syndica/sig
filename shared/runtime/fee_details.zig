pub const FeeDetails = struct {
    transaction_fee: u64,
    prioritization_fee: u64,
    compute_unit_price: u64,

    pub const DEFAULT: FeeDetails = .{
        .transaction_fee = 0,
        .prioritization_fee = 0,
        .compute_unit_price = 0,
    };

    pub fn total(self: FeeDetails) u64 {
        return self.transaction_fee + self.prioritization_fee;
    }

    pub fn init(
        sig_counts: anytype,
        lamports_per_signature: u64,
        enable_secp256r1: bool,
        prioritization_fee: u64,
        compute_unit_price: u64,
    ) FeeDetails {
        return .{
            .transaction_fee = calculateSignatureFee(
                lamports_per_signature,
                enable_secp256r1,
                sig_counts.num_transaction_signatures,
                sig_counts.num_ed25519_signatures,
                sig_counts.num_secp256k1_signatures,
                sig_counts.num_secp256r1_signatures,
            ),
            .prioritization_fee = prioritization_fee,
            .compute_unit_price = compute_unit_price,
        };
    }

    fn calculateSignatureFee(
        lamports_per_signature: u64,
        enable_secp256r1: bool,
        num_transaction_signatures: u64,
        num_ed25519_signatures: u64,
        num_secp256k1_signatures: u64,
        num_secp256r1_signatures: u64,
    ) u64 {
        const sig_count = num_transaction_signatures +|
            num_ed25519_signatures +|
            num_secp256k1_signatures +|
            if (enable_secp256r1) num_secp256r1_signatures else 0;

        return sig_count *| lamports_per_signature;
    }
};
