//! SRV4 format

const std = @import("std");

// hexadecimal strings
pub const Header = extern struct {
    magic: [6]u8 = "070701".*,
    ino: [8]u8 = "00000000".*,
    mode: [8]u8,
    uid: [8]u8 = "00000000".*,
    gid: [8]u8 = "00000000".*,
    nlink: [8]u8 = "00000000".*,
    mtime: [8]u8 = "00000000".*,
    filesize: [8]u8,
    devmajor: [8]u8 = "00000000".*,
    devminor: [8]u8 = "00000000".*,
    rdevmajor: [8]u8 = "00000000".*,
    rdevminor: [8]u8 = "00000000".*,
    namesize: [8]u8,
    check: [8]u8 = "00000000".*,
};

pub const Archive = struct {
    allocator: std.mem.Allocator,
    files: std.StringHashMapUnmanaged([]const u8) = .{},

    pub fn init(allocator: std.mem.Allocator) Archive {
        return Archive{
            .allocator = allocator,
        };
    }

    pub fn deinit(archive: *Archive) void {
        var it = archive.files.iterator();
        while (it.next()) |entry| {
            archive.allocator.free(entry.key_ptr.*);
            archive.allocator.free(entry.value_ptr.*);
        }

        archive.files.deinit(archive.allocator);
    }

    /// path must be relative
    pub fn addFile(archive: *Archive, path: []const u8, text: []const u8) !void {
        if (std.fs.path.isAbsolute(path))
            return error.AbsolutePath;

        try archive.files.put(
            archive.allocator,
            try archive.allocator.dupe(u8, path),
            try archive.allocator.dupe(u8, text),
        );
    }

    fn writePadding(writer: anytype, count: usize) !void {
        const mod = count % 4;
        const padding = if (mod > 0) 4 - mod else 0;
        try writer.writeByteNTimes(0, padding);
    }

    fn writeTerminator(writer: anytype) !void {
        const path = "TRAILER!!!";
        const header = Header{
            .mode = "00000000".*,
            .filesize = "00000000".*,
            .namesize = "0000000b".*,
        };

        try writer.writeStruct(header);
        try writer.writeAll(path);
        try writer.writeByte(0);
        try writePadding(writer, path.len + 1);
    }

    fn writeDirectory(writer: anytype, path: []const u8) !void {
        var header = Header{
            .mode = "000003b6".*,
            .filesize = "00000000".*,
            .namesize = undefined,
        };

        const namesize = @intCast(u32, path.len + 1);
        _ = try std.fmt.bufPrint(&header.namesize, "{x:0>8}", .{namesize});

        try writer.writeStruct(header);
        try writer.writeAll(path);
        try writer.writeByte(0);
        try writePadding(writer, path.len + 1);
    }

    fn writeFile(writer: anytype, path: []const u8, text: []const u8) !void {
        var header = Header{
            .mode = "000001b6".*,
            .filesize = undefined,
            .namesize = undefined,
        };

        const filesize = @intCast(u32, text.len);
        const namesize = @intCast(u32, path.len + 1);
        _ = try std.fmt.bufPrint(&header.filesize, "{x:0>8}", .{filesize});
        _ = try std.fmt.bufPrint(&header.namesize, "{x:0>8}", .{namesize});

        try writer.writeStruct(header);

        try writer.writeAll(path);
        try writer.writeByte(0);
        try writePadding(writer, path.len + 1);

        try writer.writeAll(text);
        try writePadding(writer, text.len);
    }

    pub fn write(archive: Archive, writer: anytype) !void {
        var directories = std.StringHashMap(void).init(archive.allocator);
        defer {
            var it = directories.iterator();
            while (it.next()) |entry|
                archive.allocator.free(entry.key_ptr.*);

            directories.deinit();
        }

        var it = archive.files.iterator();
        while (it.next()) |entry| {
            if (std.fs.path.dirname(entry.key_ptr.*)) |dir_path| {
                if (!directories.contains(dir_path)) {
                    var i: usize = 0;
                    while (i < dir_path.len) {
                        while (i < dir_path.len and dir_path[i] != '/') : (i += 1) {}

                        const sub_path = dir_path[0..i];

                        if (!directories.contains(sub_path)) {
                            try writeDirectory(writer, sub_path);
                            try directories.put(sub_path, {});
                        }
                    }
                }
            }

            try writeFile(writer, entry.key_ptr.*, entry.value_ptr.*);
        }

        try writeTerminator(writer);
    }
};

test "lorem ipsum" {
    const path = "lorem.txt";
    const text = @embedFile(path);
    const expected = @embedFile("lorem.txt.cpio");

    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);

    var archive = Archive.init(std.testing.allocator);
    defer archive.deinit();

    try archive.addFile(path, text);
    try archive.write(fbs.writer());

    try std.testing.expectEqualStrings(expected, fbs.getWritten());
}
