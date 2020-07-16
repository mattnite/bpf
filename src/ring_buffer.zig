const std = @import("std");
const os = std.os;
const bpf = @import("user.zig");

usingnamespace std.c;
const fd_t = std.os.fd_t;
const page_size = std.mem.page_size;

map_fd: fd_t,
offset: usize,
// ctx
consumer: []u8,
producer: []u8,
// mask

const Self = @This();

pub fn init(map: fd_t) !Self {
    var info: bpf.MapInfo = undefined;

    try bpf.obj_get_info_by_fd(map, &info, @sizeOf(bpf.MapInfo));
    if (info.typ != .RingBuf) {
        return error.WrongMapType;
    }

    const consumer = try os.mmap(null, page_size, (PROT_READ | PROT_WRITE), MAP_SHARED, map, 0);
    errdefer os.munmap(consumer);

    const prod_len = page_size + (2 * info.max_entries);
    const producer = try mmap(null, prod_len, PROT_READ, MAP_SHARED, map, page_size);
    errdefer os.munmap(producer);

    return Self{
        .map_fd = map,
        .consumer = consumer,
        .producer = producer,
        .offset = page_size,
    };
}

pub fn deinit(self: *Self) void {
    os.munmap(self.consumer);
    os.munmap(self.producer);
}
