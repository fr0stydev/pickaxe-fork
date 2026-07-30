#pragma once
/*
 * Minimal KaynLdr-style reflective loader (Havoc / @C5pider).
 * Runs inside the sacrificial process from the raw DLL mapping.
 */
#include <windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((LONG)(Status)) >= 0)
#endif

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

#define HASH_KEY 5381
#define NTDLL_HASH 0x70e61753
#define SYS_LDRLOADDLL 0x9e456a43
#define SYS_NTALLOCATEVIRTUALMEMORY 0xf783b8ec
#define SYS_NTPROTECTEDVIRTUALMEMORY 0x50e92888

typedef struct _PPF_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} PPF_UNICODE_STRING;

typedef struct _PPF_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PPF_PEB_LDR_DATA;

typedef struct _PPF_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    PPF_UNICODE_STRING FullDllName;
    PPF_UNICODE_STRING BaseDllName;
} PPF_LDR_DATA_TABLE_ENTRY, *PPPF_LDR_DATA_TABLE_ENTRY;

typedef struct _PPF_PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPF_PEB_LDR_DATA* Ldr;
} PPF_PEB;

typedef LONG NTSTATUS;

typedef NTSTATUS(NTAPI* FN_LdrLoadDll)(
    PWCHAR PathToFile,
    ULONG Flags,
    PPF_UNICODE_STRING* ModuleFileName,
    PHANDLE ModuleHandle);

typedef NTSTATUS(NTAPI* FN_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS(NTAPI* FN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

typedef struct _KAYNINSTANCE {
    struct {
        FN_LdrLoadDll LdrLoadDll;
        FN_NtAllocateVirtualMemory NtAllocateVirtualMemory;
        FN_NtProtectVirtualMemory NtProtectVirtualMemory;
    } Win32;
    struct {
        PVOID Ntdll;
    } Modules;
} KAYNINSTANCE;

__declspec(dllexport) void WINAPI KaynLoader(LPVOID lpParameter);
