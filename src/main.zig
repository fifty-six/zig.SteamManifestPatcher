const std = @import("std");
const math = std.math;

const psapi = std.os.windows.psapi;
const win = std.os.windows;

const c = @import("./c.zig");

const STR: []const u8 = "Depot download failed : Manifest not available";

usingnamespace @import("./wmem.zig");

pub fn main() !void {
    caught_main() catch |e| {
        std.debug.print("{}\n", .{e});

        if (@errorReturnTrace()) |trace| {
            std.debug.dumpStackTrace(trace.*);
        }
    };

    try catch_if_ncli();
}

pub fn caught_main() !void {
    const stdout = std.io.getStdOut().writer();

    var heap = std.heap.HeapAllocator.init();
    defer heap.deinit();

    const allocator = &heap.allocator;

    const proc_id = (try proc_id_by_name("steam.exe")) orelse return error.ProcessNotFound;

    try stdout.print("Got process handle.\n", .{});

    const flags = c.PROCESS_QUERY_INFORMATION | c.PROCESS_VM_OPERATION | c.PROCESS_VM_READ | c.PROCESS_VM_WRITE;

    const proc_handle = c.OpenProcess(flags, @boolToInt(false), proc_id) orelse return error.UnableToOpenProcess;

    const mod_handle = try handle_for_mod(proc_handle, "steamclient.dll");
    const handle_addr = @ptrToInt(mod_handle);

    const size = try get_module_size(proc_handle, mod_handle);

    try stdout.print("Module handle address: {x}\n", .{handle_addr});

    const buf = try read_memory_address(proc_handle, handle_addr, size, allocator);

    const str_ind = std.mem.indexOf(u8, buf, STR) orelse return error.StringNotFound;
    const str_addr = handle_addr + str_ind;

    // Sentinel-terminated by the leading zeros (LE).
    // We only want up to the zeros as the push we use
    // takes an intermediate with size 16 or 32, which is
    // smaller than a usize
    const bytes = @ptrCast([*:0]const u8, &str_addr);

    // As an actual slice
    const slice: []const u8 = std.mem.span(bytes);

    // Insert push before address
    const clone = try allocator.alloc(u8, slice.len + 1);
    defer allocator.free(clone);

    std.mem.copy(u8, clone[1..], slice);

    // push instr
    clone[0] = 0x68;

    try print_buffer(clone);

    const push_ind = std.mem.indexOf(u8, buf, clone) orelse return error.PatternNotFound;

    try stdout.print("Addr: {x}\n", .{handle_addr + push_ind});

    var ind = push_ind;

    while (buf[ind] != 0x0F and buf[ind + 1] != 0x85) {
        ind -= 1;
    }

    // Either the patch has already been applied or the jnz isn't there
    // We want to prevent writing over code which isn't actually part
    // of what we want to patch.
    if (ind < push_ind - 10) {
        return error.PatchAlreadyApplied;
    }

    // Replace 2-byte jnz with nop, jmp
    buf[ind] = 0x90;
    buf[ind + 1] = 0xE9;

    const patch_addr = @ptrToInt(mod_handle) + ind;

    try write_patch(proc_handle, mod_handle, size, patch_addr, buf[ind .. ind + 2]);

    try stdout.print("Wrote patch to memory.\n", .{});

    // Read 10 bytes before and after the patch address.
    const patched = try read_memory_address(proc_handle, patch_addr - 10, 20, allocator);
    defer allocator.free(patched);

    // Make sure patch was applied correctly
    if (!std.mem.eql(u8, buf[ind - 10 .. ind + 10], patched)) {
        try stdout.print("Expected: ", .{});
        try print_buffer(buf[ind - 10 .. ind + 10]);
        try stdout.print("Got: ", .{});
        try print_buffer(patched);

        return error.PatchAppliedIncorrectly;
    }
}

pub fn catch_if_ncli() !void {
    const stdout = std.io.getStdOut().writer();

    var buf: [10]c.LPDWORD = undefined;

    const count = c.GetConsoleProcessList(@ptrCast(*u32, &buf), buf.len);

    // Run from the CLI.
    if (count != 1) {
        return;
    }

    try stdout.print("Press ENTER to close.", .{});

    // Keep console open
    _ = try std.io.getStdIn().reader().readByte();
}

pub fn print_buffer(buf: []const u8) !void {
    const stdout = std.io.getStdOut().writer();

    for (buf) |char| {
        try stdout.print("{X:0>2} ", .{char});
    }

    try stdout.print("\n", .{});
}
