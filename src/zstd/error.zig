const c = @import("c.zig");

pub const Error = error{
    Generic,
    UnknownPrefix,
    UnsupportedVersion,
    UnsupportedFrameParameter,
    TooLargeFrameParameterWindow,
    CorruptionDetected,
    WrongChecksum,
    CorruptedDictionary,
    WrongDictionary,
    DictionaryCreationFailed,
    UnsupportedParameter,
    OutOfBoundsParameter,
    TooLargeTableLog,
    TooLargeMaxSymbolValue,
    TooSmallMaxSymbolValue,
    WrongStage,
    InitMissing,
    OutOfMemory,
    TooSmallWorkspace,
    TooSmallDestSize,
    WrongSrcSize,
    NullDestBuffer,
    TooLargeFrameIndex,
    SeekableIO,
    WrongDestBuffer,
    WrongSrcBuffer,
};

/// tells if a `usize` function result is an error code
pub fn isError(code: usize) bool {
    return c.ZSTD_isError(code) > 0;
}

pub fn checkError(maybe_error: usize) Error!usize {
    return if (isError(maybe_error))
        switch (c.ZSTD_getErrorCode(maybe_error)) {
            1 => error.Generic,
            10 => error.UnknownPrefix,
            12 => error.UnsupportedVersion,
            14 => error.UnsupportedFrameParameter,
            16 => error.TooLargeFrameParameterWindow,
            20 => error.CorruptionDetected,
            22 => error.WrongChecksum,
            30 => error.CorruptedDictionary,
            32 => error.WrongDictionary,
            34 => error.DictionaryCreationFailed,
            40 => error.UnsupportedParameter,
            42 => error.OutOfBoundsParameter,
            44 => error.TooLargeTableLog,
            46 => error.TooLargeMaxSymbolValue,
            48 => error.TooSmallMaxSymbolValue,
            60 => error.WrongStage,
            62 => error.InitMissing,
            64 => error.OutOfMemory,
            66 => error.TooSmallWorkspace,
            70 => error.TooSmallDestSize,
            72 => error.WrongSrcSize,
            74 => error.NullDestBuffer, // unreachable
            // unstable > 100
            100 => error.TooLargeFrameIndex,
            102 => error.SeekableIO,
            104 => error.WrongDestBuffer,
            105 => error.WrongSrcBuffer,
            else => unreachable,
        }
    else
        maybe_error;
}
