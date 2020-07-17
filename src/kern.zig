pub usingnamespace @import("common.zig");
pub const helpers = @import("helpers.zig");
const std = @import("std");

pub const MapDef = struct {
    map_type: MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
};

pub const ktime_get_ns = helpers.ktime_get_ns;
pub const get_prandom_u32 = helpers.get_prandom_u32;
pub const get_smp_processor_id = helpers.get_smp_processor_id;
pub const get_current_pid_tgid = helpers.get_current_pid_tgid;
pub const get_current_uid_gid = helpers.get_current_uid_gid;
pub const get_cgroup_classid = helpers.get_cgroup_classid;

pub fn trace_printk(comptime fmt: []const u8, args: []u64) !u32 {
    const rc = switch (args.len) {
        0 => helpers.trace_printk(fmt.ptr, fmt.len, 0, 0, 0),
        1 => helpers.trace_printk(fmt.ptr, fmt.len, args[0], 0, 0),
        2 => helpers.trace_printk(fmt.ptr, fmt.len, args[0], args[1], 0),
        3 => helpers.trace_printk(fmt.ptr, fmt.len, args[0], args[1], args[2]),
        else => @compileError("Maximum 3 args for trace_printk"),
    };

    return switch (rc) {
        0...std.math.maxInt(c_int) => @intCast(u32, rc),
        EINVAL => error.Invalid,
        else => error.UnknownError,
    };
}

pub const PerfEventArray = Map(u32, u32, .perf_event_array, 0);

pub fn Map(comptime Key: type, comptime Value: type, map_type: MapType, entries: u32) type {
    return struct {
        base: MapDef,

        const Self = @This();

        pub fn init() Self {
            return Self{
                .base = .{
                    .map_type = map_type,
                    .key_size = @sizeOf(Key),
                    .value_size = @sizeOf(Value),
                    .max_entries = entries,
                },
            };
        }

        pub fn lookup(self: *const Self, key: *const Key) ?*Value {
            return helpers.map_lookup_elem(&self.base, key);
        }

        pub fn update(self: *const Self, key: *const Key, value: *const Value, flags: UpdateFlags) !void {
            switch (helpers.map_update_elem(&self.base, key, value, @enumToInt(flags))) {
                0 => return,
                else => return error.UnknownError,
            }
        }

        pub fn delete(self: *const Self, key: *const Key) !void {
            switch (helpers.map_delete_elem(&self.base, key)) {
                0 => return,
                else => return error.UnknownError,
            }
        }
    };
}

pub fn probe_read(comptime T: type, dst: []T, src: []const T) !void {
    if (dst.len < src.len) {
        return error.TooBig;
    }

    switch (helpers.probe_read(dst.ptr, src.len * @sizeOf(T), src.ptr)) {
        0 => return,
        else => return error.UnknownError,
    }
}

pub fn probe_read_user_str(comptime T: type, dst: []T, src: []const T) !void {
    if (dst.len < src.len) {
        return error.TooBig;
    }

    switch (helpers.probe_read_user_str(dst.ptr, @truncate(u32, src.len * @sizeOf(T)), src.ptr)) {
        0 => return,
        else => return error.UnknownError,
    }
}

pub fn skb_store_bytes(skb: *SkBuff, offset: u32, from: []const u8, flags: u64) !void {
    switch (helpers.skb_store_bytes(skb, offset, from.ptr, from.len, flags)) {
        0 => return,
        else => return error.UnknownError,
    }
}

pub fn l3_csum_replace(skb: *SkBuff, offset: u32, from: u64, to: u64, size: u64) !void {
    switch (helpers.l3_csum_replace(skb, offset, from, to, size)) {
        0 => return,
        else => return error.UnknownError,
    }
}

pub fn l4_csum_replace(skb: *SkBuff, offset: u32, from: u64, to: u64, flags: u64) !void {
    switch (helpers.l4_csum_replace(skb, offset, from, to, flags)) {
        0 => return,
        else => return error.UnknownError,
    }
}

pub fn tail_call(ctx: var, map: *ProgArrayMap, index: u32) !void {
    switch (helpers.tail_call(ctx, map, index)) {
        0 => return,
        else => return error.UnknownError,
    }
}

pub fn clone_redirect(skb: *SkBuff, ifindex: u32, flags: u64) !void {
    switch (helpers.clone_redirect(skb, ifindex, flags)) {
        0 => return,
        else => return error.UnknownError,
    }
}

pub fn get_current_comm(buf: []u8) !void {
    switch (helpers.get_current_comm(buf.ptr, @truncate(u32, buf.len))) {
        0 => return,
        else => return error.UnknownError,
    }
}

pub fn skb_vlan_push(skb: *SkBuff, vlan_proto: u16, vlan_tci: u16) !void {
    switch (helpers.skb_vlan_push(skb, vlan_proto, vlan_tci)) {
        0 => return,
        else => return error.UnknownError,
    }
}

pub fn skb_vlan_pop(skb: *SkBuff) !void {
    switch (helpers.skb_vlan_pop(skb)) {
        0 => return,
        else => return error.UnknownError,
    }
}

pub fn skb_get_tunnel_key(skb: *SkBuff, key: *TunnelKey, size: u32, flags: u64) !void {
    switch (helpers.skb_get_tunnel_key(skb, key, size, flags)) {
        0 => return,
        else => return error.UnknownError,
    }
}

pub fn skb_set_tunnel_key(skb: *SkBuff, key: TunnelKey, size: u32, flags: u64) !void {
    switch (helpers.skb_set_tunnel_key(skb, key, size, flags)) {
        0 => return,
        else => return error.UnknownError,
    }
}

// TODO split bpf_direct for Xdp and non-xdp programs

pub fn get_route_realm(skb: *SkBuff) ?u32 {
    const ret = helpers.get_route_realm(skb);
    return if (ret == 0) null else ret;
}

pub fn perf_event_output(ctx: var, map: var, flags: u64, data: []u8) !void {
    switch (helpers.perf_event_output(ctx, &map.base, flags, data.ptr, data.len)) {
        0 => return,
        else => return error.UnknownError,
    }
}
