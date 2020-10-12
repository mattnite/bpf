pub fn export_map(comptime name: []const u8, target: anytype) void {
    @export(target, .{ .name = name, .section = "maps", .linkage = .Strong });
}

pub fn export_license(target: anytype) void {
    @export(target, .{ .name = "license", .section = "license", .linkage = .Strong });
}

pub fn export_version(target: anytype) void {
    @export(target, .{ .name = "version", .section = "version", .linkage = .Strong });
}

pub fn export_tracepoint(comptime tracepoint: anytype, target: fn (*tracepoint.Ctx()) c_int) void {
    @export(target, .{ .name = "", .section = tracepoint.section(), .linkage = .Strong });
}
