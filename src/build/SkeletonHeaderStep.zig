const std = @import("std");
const ProbeStep = @import("ProbeStep.zig");
const Builder = std.build.Builder;
const Step = std.build.Step;
const Term = std.ChildProcess.Term;

const Self = @This();

// TODO: install()

step: Step,
builder: *Builder,
probe_step: *ProbeStep,
out_filename: []const u8,

pub fn create(builder: *Builder, name: []const u8, root: []const u8) !*Self {
    var ret = try builder.allocator.create(Self);
    errdefer builder.allocator.destroy(ret);

    ret.* = Self{
        .step = Step.init(.custom, "bpf_skel", builder.allocator, make),
        .builder = builder,
        .probe_step = try ProbeStep.create(builder, name, root),
        .out_filename = try std.fs.path.join(builder.allocator, &.{
            builder.cache_root,
            "bpf",
            "skeletons",
            try std.fmt.allocPrint(builder.allocator, "{s}_skel.h", .{name}),
        }),
    };

    ret.step.dependOn(&ret.probe_step.step);

    return ret;
}

fn make(step: *Step) !void {
    const self = @fieldParentPtr(Self, "step", step);

    try std.fs.cwd().makePath(std.fs.path.dirname(self.out_filename).?);
    const out_file = try std.fs.cwd().createFile(self.out_filename, .{
        .truncate = true,
    });
    defer out_file.close();

    var bpftool = std.ChildProcess.init(&.{
        "bpftool",
        "gen",
        "skeleton",
        self.probe_step.out_filename,
        "name",
        self.probe_step.probe.name,
    }, self.builder.allocator);

    // TODO: allocate stderr for prettier printing?
    bpftool.stdout = out_file;
    bpftool.stdout_behavior = .Pipe;
    const term = try bpftool.spawnAndWait();
    if (term != .Exited or term.Exited != 0) {
        std.log.err("something went wrong with bpftool", .{});
        return error.Explained;
    }
}
