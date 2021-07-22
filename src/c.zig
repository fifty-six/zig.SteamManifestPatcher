pub const LIST_MODULES_ALL = 0x03;

pub usingnamespace @cImport({
    @cInclude("windows.h");
    @cInclude("tlhelp32.h");
    @cInclude("memoryapi.h");
});
