pub const win = @import("std").os.windows;

pub const HANDLE = win.HANDLE;
pub const DWORD = win.DWORD;
pub const HMODULE = win.HMODULE;
pub const LPCVOID = win.LPCVOID;
pub const LPVOID = win.LPVOID;
pub const SIZE_T = win.SIZE_T;
pub const BOOL = win.BOOL;

pub const TH32CS_SNAPPROCESS = 0x00000002;
pub const LIST_MODULES_ALL = 0x03;

pub const PAGE_EXECUTE_READWRITE = 0x40;

pub const PROCESS_VM_WRITE          = 0x0020;
pub const PROCESS_VM_READ           = 0x0010;
pub const PROCESS_VM_OPERATION      = 0x0008;
pub const PROCESS_QUERY_INFORMATION = 0x0400;

pub const MAX_PATH = 260;

pub const ProcessEntry32 = extern struct {
    dwSize: DWORD,
    cntUsage: DWORD,
    th32ProcessID: DWORD,
    th32DefaultHeapID: win.ULONG_PTR,
    th32ModuleID: DWORD,
    cntThreads: DWORD,
    th32ParentProcessID: DWORD,
    pcPriClassBase: win.LONG,
    dwFlags: DWORD,
    szExeFile: [MAX_PATH : 0]win.CHAR
};

pub extern fn CreateToolhelp32Snapshot(dwFlags: c_ulong, th32ProcessID: c_ulong) callconv(.Stdcall) HANDLE;

pub extern fn Process32First(hSnapshot: HANDLE, lppe: *ProcessEntry32) callconv(.Stdcall) c_int;

pub extern fn Process32Next(hSnapshot: HANDLE, lppe: *ProcessEntry32) callconv(.Stdcall) c_int;

pub extern fn OpenProcess(dwDesiredAccess: c_ulong, bInheritHandle: c_int, dwProcessId: c_ulong) callconv(.Stdcall) HANDLE;

pub extern fn ReadProcessMemory(hProcess: HANDLE, lpBaseAddress: LPCVOID, lpBuffer: LPVOID, nSize: SIZE_T, lpNumberOfBytesRead: *SIZE_T) callconv(.Stdcall) BOOL;

pub extern fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPCVOID, lpBuffer: LPVOID, nSize: SIZE_T, lpNumberOfBytesWritten: *SIZE_T) callconv(.Stdcall) BOOL;

pub extern fn VirtualProtectEx(hProcess: HANDLE, lpAddress: win.LPCVOID, dwSize: DWORD, flNewProtect: DWORD, lpflOldProtect: *DWORD) callconv(.Stdcall) BOOL;