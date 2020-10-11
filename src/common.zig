usingnamespace @import("flags.zig");

pub const MapUpdateType = enum(u64) {
    any = ANY,
    noexist = NOEXIST,
    exist = EXIST,
};
