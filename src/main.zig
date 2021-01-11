const std = @import("std");
const math = std.math;

const psapi = std.os.windows.psapi;
const win = std.os.windows;

const c = @import("./c.zig");

const STR: []const u8 = "Depot download failed : Manifest not available";

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

    var proc_id = try proc_id_by_name("steam.exe");

    try stdout.print("Got process handle.\n", .{});

    const flags = c.PROCESS_QUERY_INFORMATION | c.PROCESS_VM_OPERATION | c.PROCESS_VM_READ | c.PROCESS_VM_WRITE;

    var proc_handle = c.OpenProcess(flags, @boolToInt(false), proc_id);

    var mod_handle = try handle_for_mod(proc_handle, "steamclient.dll");
    const handle_addr = @ptrToInt(mod_handle);

    var size = try get_module_size(proc_handle, mod_handle);

    try stdout.print("Module handle address: {x}\n", .{handle_addr});

    var str_addr = try get_memory_address(proc_handle, handle_addr, size, STR, allocator);

    // Sentinel-terminated by the leading zeros (LE).
    var bytes = @ptrCast([*:0]const u8, &str_addr);

    // As an actual slice
    var slice: []const u8 = std.mem.spanZ(bytes);

    // Insert pop before address
    var clone = try allocator.alloc(u8, slice.len + 1);
    defer allocator.free(clone);

    std.mem.copy(u8, clone[1..], slice);

    // pop instr
    clone[0] = 0x68;

    try print_buffer(clone);

    var buf = try read_memory_address(proc_handle, @ptrToInt(mod_handle), size, allocator);

    var ind = std.mem.indexOf(u8, buf, clone) orelse return error.PatternNotFound;

    try stdout.print("Addr: {x}\n", .{handle_addr + ind});

    while (buf[ind] != 0x0F and buf[ind + 1] != 0x85) {
        ind -= 1;
    }

    // Replace 2-byte jnz with nop, jmp
    buf[ind    ] = 0x90;
    buf[ind + 1] = 0xE9;

    var patch_addr = @ptrToInt(mod_handle) + ind;

    try write_patch(proc_handle, mod_handle, size, patch_addr, buf[ind..ind + 2]);

    try stdout.print("Wrote patch to memory.\n", .{});

    // Read 10 bytes before and after the patch address.
    var patched = try read_memory_address(proc_handle, patch_addr - 10, 20, allocator);
    defer allocator.free(patched);

    // Make sure patch was applied correctly
    if (!std.mem.eql(u8, buf[ind - 10..ind + 10], patched)) {
        try stdout.print("Expected: ", .{});
        try print_buffer(buf[ind - 10.. ind + 10]);
        try stdout.print("Got: ", .{});
        try print_buffer(patched);

        return error.PatchAppliedIncorrectly;
    }
}

pub fn catch_if_ncli() !void {
    var stdout = std.io.getStdOut().writer();

    var buf: [10]c.LPDWORD = undefined;

    var count = c.GetConsoleProcessList(@ptrCast(*u32, &buf), buf.len);

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

pub fn write_patch(proc: win.HANDLE, module: win.HANDLE, size: usize, addr: usize, patch: []const u8) !void {
    var old_protection: win.DWORD = undefined;

    if (c.VirtualProtectEx(proc, module, @truncate(u32, size), c.PAGE_EXECUTE_READWRITE, &old_protection) == 0)
        return error.ProtectionUnwritable;

    var bytes_written: win.SIZE_T = undefined;

    if (c.WriteProcessMemory(proc, @intToPtr(*c_void, addr), @ptrCast(*const c_void, patch), patch.len, &bytes_written) == 0)
        return error.UnableToWriteMemory;
}

pub fn get_module_size(proc: win.HANDLE, module: win.HANDLE) !usize {
    var mod_info: win.MODULEINFO = undefined;

    if (win.psapi.GetModuleInformation(proc, @ptrCast(win.HMODULE, module), &mod_info, @sizeOf(win.MODULEINFO)) == 0)
        return error.ModuleInfoUnavailable;

    return mod_info.SizeOfImage;
}

pub fn read_memory_address(proc_handle: win.HANDLE, addr: usize, size: usize, alloc: *std.mem.Allocator) ![]u8 {
    var buf : []u8 = try alloc.alloc(u8, size);

    var bytes_read : win.SIZE_T = undefined;

    if (c.ReadProcessMemory(proc_handle, @intToPtr(win.LPCVOID, addr), @ptrCast(*c_void, buf), size, &bytes_read) == 0)
        return error.MemoryUnreadable;

    return buf[0..bytes_read];
}

pub fn get_memory_address(proc_handle: win.HANDLE, addr: usize, size: usize, mem: []const u8, alloc: *std.mem.Allocator) !usize {
    var buf : []u8 = try alloc.alloc(u8, size);
    defer alloc.free(buf);

    var bytes_read : win.SIZE_T = undefined;

    if (c.ReadProcessMemory(proc_handle, @intToPtr(win.LPCVOID, addr), @ptrCast(*c_void, buf), size, &bytes_read) == 0)
        return error.MemoryUnreadable;

    var ind = std.mem.indexOf(u8, buf[0..bytes_read], mem) orelse return error.PatternNotFound;

    return addr + ind;
}

pub fn handle_for_mod(procHandle: win.HANDLE, target: []const u8) !win.HMODULE {
    var handles: [1024]win.HMODULE = undefined;
    var cbNeeded: win.DWORD = undefined;

    if (psapi.EnumProcessModulesEx(procHandle, &handles, handles.len, &cbNeeded, c.LIST_MODULES_ALL) == 0)
        return error.UnableToEnumerate;

    if (cbNeeded > 1024 * @sizeOf(win.HMODULE))
        return error.BufferTooSmall;

    for (handles[0..(cbNeeded / @sizeOf(win.HMODULE))]) |handle| {
        var name: [win.MAX_PATH : 0]u8 = undefined;

        if (psapi.GetModuleFileNameExA(procHandle, handle, &name, name.len / @sizeOf(u8)) == 0)
            continue;

        var slice = std.mem.spanZ(&name);

        if (std.mem.endsWith(u8, slice, target))
            return handle;
    }

    return error.HandleNotFound;
}

pub fn proc_id_by_name(name: []const u8) !u32 {
    var entry: c.ProcessEntry32 = undefined;
    entry.dwSize = @sizeOf(c.ProcessEntry32);

    var snap: win.HANDLE = c.CreateToolhelp32Snapshot(c.TH32CS_SNAPPROCESS, 0);

    if (c.Process32First(snap, &entry) == 0)
        return error.UnableToProcess;

    while (c.Process32Next(snap, &entry) != 0) {
        var slice = std.mem.spanZ(&entry.szExeFile);

        if (std.mem.eql(u8, slice, name))
            return entry.th32ProcessID;
    }

    return error.ProcessNotFound;
}
