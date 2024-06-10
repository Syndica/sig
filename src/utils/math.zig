pub fn checkedAdd(a: anytype, b: anytype) error{IntegerOverflow}!@TypeOf(a) {
    const sum = a + b;
    if (@typeInfo(@TypeOf(a)).Int.signedness == .unsigned) {
        return if (sum < a or sum < b) error.IntegerOverflow else sum;
    } else {
        return if (checkSignedSum(a, b, sum)) sum else error.IntegerOverflow;
    }
}

pub fn checkedSub(a: anytype, b: anytype) error{IntegerOverflow}!@TypeOf(a) {
    if (@typeInfo(@TypeOf(a)).Int.signedness == .unsigned) {
        return if (b > a) error.IntegerOverflow else a - b;
    } else {
        const diff = a - b;
        return if (checkSignedSum(a, -b, diff)) diff else error.IntegerOverflow;
    }
}

fn checkSignedSum(a: anytype, b: anytype, sum: anytype) bool {
    return a == 0 or
        b == 0 or
        a > 0 and b < 0 or
        a < 0 and b > 0 or
        a > 0 and sum > 0 or
        a < 0 and sum < 0;
}
