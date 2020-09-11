const std = @import("std");
const psapi = std.os.windows.psapi;

const win = std.os.windows;

const c = @import("./c.zig");

pub fn main() !void {
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

    var patch_addr = try get_patch_addr(proc_handle, @ptrToInt(mod_handle), size, allocator);

    try stdout.print("Found patch address: {x}\n", .{patch_addr});

    try write_patch(proc_handle, mod_handle, size, patch_addr);

    try stdout.print("Wrote patch to memory.\n", .{});
}

pub fn write_patch(proc: win.HANDLE, module: win.HANDLE, size: usize, addr: usize) !void {
    var old_protection: win.DWORD = undefined;

    if (c.VirtualProtectEx(proc, module, @truncate(u32, size), c.PAGE_EXECUTE_READWRITE, &old_protection) == 0)
        return error.ProtectionUnwritable;

    var patch = [_]u8 { 0x0F, 0x84, 0x2E, 0xFF, 0xFF, 0xFF };

    var bytes_written: win.SIZE_T = undefined;

    if (c.WriteProcessMemory(proc, @intToPtr(*c_void, addr), @ptrCast(*c_void, &patch), patch.len, &bytes_written) == 0)
        return error.UnableToWriteMemory;
}

pub fn get_module_size(proc: win.HANDLE, module: win.HANDLE) !usize {
    var mod_info: win.MODULEINFO = undefined;

    if (win.psapi.GetModuleInformation(proc, @ptrCast(win.HMODULE, module), &mod_info, @sizeOf(win.MODULEINFO)) == 0)
        return error.ModuleInfoUnavailable;

    return mod_info.SizeOfImage;
}

pub fn get_patch_addr(proc_handle: win.HANDLE, addr: usize, size: usize, alloc: *std.mem.Allocator) !usize {
    var buf : []u8 = try alloc.alloc(u8, size);
    defer alloc.free(buf);

    var bytes_read : win.SIZE_T = undefined;

    if (c.ReadProcessMemory(proc_handle, @intToPtr(win.LPCVOID, addr), @ptrCast(*c_void, buf), size, &bytes_read) == 0)
        return error.MemoryUnreadable;

    const egg = [_]u8 { 0x84, 0xC0, 0x0F, 0x85, 0x2E, 0xFF, 0xFF, 0xFF };

    var ind = std.mem.indexOf(u8, buf[0..bytes_read], &egg) orelse return error.PatternNotFound;

    return addr + ind + 2;
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
