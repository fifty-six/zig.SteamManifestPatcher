const std = @import("std");
const psapi = std.os.windows.psapi;

const win = std.os.windows;

const c = @import("./c.zig");

// steamclient.dll
// .text : 383E41DD
const EGG = [_]u8 { 
    // call addr
    0xE8, 0x4B, 0xF7, 0xEC, 0xFF,
    // test al, al
    0x84, 0xC0,
    // jnz addr
    0x0F, 0x85, 0x9D, 0x00, 0x00, 0x00 
};

const PATCH = [_]u8 { 
    // jnz => nop, jmp
    // nop, jmp is used because jnz is 2-byte.
    0x90, 0xE9
};

// After test al, al
const PATCH_OFFSET = 7;

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

    var size = try get_module_size(proc_handle, mod_handle);

    try stdout.print("Module handle address: {x}\n", .{@ptrToInt(mod_handle)});

    var patch_addr = try get_memory_address(proc_handle, @ptrToInt(mod_handle), size, EGG[0..], allocator);

    // We add the offset in order to skip rewriting unchanged instructions.
    patch_addr += PATCH_OFFSET;

    try stdout.print("Found patch address: {x}\n", .{patch_addr});

    try write_patch(proc_handle, mod_handle, size, patch_addr, PATCH[0..]);

    try stdout.print("Wrote patch to memory.\n", .{});

    var patched = try read_memory_address(proc_handle, patch_addr - PATCH_OFFSET, EGG.len, allocator);
    defer allocator.free(patched);

    var egg_clone = try std.mem.dupe(allocator, u8, &EGG);

    std.mem.copy(u8, egg_clone[PATCH_OFFSET..PATCH_OFFSET + PATCH.len], &PATCH);

    // Make sure patch was applied correctly
    if (!std.mem.eql(u8, egg_clone, patched)) {
        try stdout.print("Expected: ", .{});
        try print_buffer(egg_clone);
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

pub fn print_buffer(buf: []u8) !void {
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
