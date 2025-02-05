export fn load(_: ?*anyopaque) linksection("load") callconv(.Naked) void {
    asm volatile (
        \\ r1 = 0x1
    );
}

export fn return_one(_: ?*anyopaque) linksection("return_one") callconv(.C) c_int {
    return 1;
}
