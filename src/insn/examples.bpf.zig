export fn load() callconv(.Naked) void {
    asm volatile (
        \\ r1 = 0x1
    );
}

export fn return_one(_: ?*anyopaque) callconv(.C) c_int {
    return 1;
}
