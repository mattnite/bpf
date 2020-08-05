const std = @import("std");
const Self = @This();
const Link = @import("link.zig");

name: []const u8,
type: ProgType,
insns: []Insn,
loaded: bool,
instances: []fd_t,
expected_attach_type: AttachType,

// TODO: name vs title

pub fn load(self: *Self, license: []const u8, kern_version: u32) !void {
    if (self.loaded) {
        return error.AlreadyLoaded;
    }

    // TODO: finish
}

pub fn unload(self: *Self) void {
    for (self.instances) |instance| {
        try std.os.close(instance);
    }

    self.instances.len = 0;
}

pub fn pin_instance(self: *Self, path: []const u8, instance: fd_t) !void {}
pub fn unpin_instance(self: *Self, path: []const u8, instance: fd_t) !void {}

pub fn pin(self: *Self, path: []const u8) !void {}
pub fn unpin(self: *Self, path: []const u8) !void {}

// attach functions
pub fn attach(self: *Self) !*Link {}
pub fn attach_perf_event(self: *Self, perf_event: fd_t) !*Link {}
pub fn attach_kprobe(self: *Self, retprobe: bool, func_name: []const u8) !*Link {}
pub fn attach_uprobe(self: *Self, retprobe: bool, pid: pid_t, binary_path: []const u8, func_offset: usize) !*Link {}
pub fn attach_tracepoint(self: *Self, tp_category: []const u8, tp_name: []const u8) !*Link {}
pub fn attach_raw_tracepoint(self: *Self, tp_name: []const u8) !*Link {}
pub fn attach_trace(self: *Self) !*Link {}
pub fn attach_lsm(self: *Self) !*Link {}
pub fn attach_cgroup(self: *Self, cgroup: fd_t) !*Link {}
pub fn attach_netns(self: *Self, netns: fd_t) !*Link {}
pub fn attach_xdp(self: *Self, ifindex: isize) !*Link {}
pub fn attach_iter(self: *Self, opts: *IterAttachOps) !*Link {}
// TODO: do we need fd? or is that just an instance?
pub fn set_attach_target(self: *Self, prog: fd_t, attach_func_name: []const u8) !void {}
