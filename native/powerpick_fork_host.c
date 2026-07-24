/*
 * Sacrificial-process CLR host DLL for powerpick-fork.
 *
 * Launch: rundll32.exe "<dll>",PowerPickForkRun <mapName>
 * Map: magic | slot[160] | asmLen | asm | argsLen | args ("exec <b64>")
 *
 * Uses ICLRRuntimeHost::ExecuteInDefaultAppDomain after staging the managed
 * EXE to %TEMP% — avoids MinGW Invoke_3/VARIANT ABI crashes.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>

#include "powerpick_fork_clr.h"

#define PPF_MAGIC 0x4B464650u /* 'PFFK' */
#define PPF_SLOT_MAX 160

typedef HRESULT (WINAPI *FN_CLRCreateInstance)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);

/* ICLRRuntimeHost — subset used for ExecuteInDefaultAppDomain */
static GUID xCLSID_CLRRuntimeHost = {
    0x90F1A06E, 0x7712, 0x4762, {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02}
};
static GUID xIID_ICLRRuntimeHost = {
    0x90F1A06C, 0x7712, 0x4762, {0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02}
};

typedef struct ICLRRuntimeHost ICLRRuntimeHost;

typedef struct ICLRRuntimeHostVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(ICLRRuntimeHost*, REFIID, void**);
    ULONG(STDMETHODCALLTYPE* AddRef)(ICLRRuntimeHost*);
    ULONG(STDMETHODCALLTYPE* Release)(ICLRRuntimeHost*);
    HRESULT(STDMETHODCALLTYPE* Start)(ICLRRuntimeHost*);
    HRESULT(STDMETHODCALLTYPE* Stop)(ICLRRuntimeHost*);
    HRESULT(STDMETHODCALLTYPE* SetHostControl)(ICLRRuntimeHost*, void*);
    HRESULT(STDMETHODCALLTYPE* GetCLRControl)(ICLRRuntimeHost*, void**);
    HRESULT(STDMETHODCALLTYPE* UnloadAppDomain)(ICLRRuntimeHost*, DWORD, BOOL);
    HRESULT(STDMETHODCALLTYPE* ExecuteInAppDomain)(ICLRRuntimeHost*, DWORD, void*, void*);
    HRESULT(STDMETHODCALLTYPE* GetCurrentAppDomainId)(ICLRRuntimeHost*, DWORD*);
    HRESULT(STDMETHODCALLTYPE* ExecuteApplication)(
        ICLRRuntimeHost*, LPCWSTR, int, LPCWSTR const*, DWORD*);
    HRESULT(STDMETHODCALLTYPE* ExecuteInDefaultAppDomain)(
        ICLRRuntimeHost* This,
        LPCWSTR pwzAssemblyPath,
        LPCWSTR pwzTypeName,
        LPCWSTR pwzMethodName,
        LPCWSTR pwzArgument,
        DWORD* pReturnValue);
} ICLRRuntimeHostVtbl;

struct ICLRRuntimeHost {
    ICLRRuntimeHostVtbl* lpVtbl;
};

static void* PpAlloc(SIZE_T n)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
}

static void PpFree(void* p)
{
    if (p) {
        HeapFree(GetProcessHeap(), 0, p);
    }
}

static void PpCopy(void* dst, const void* src, SIZE_T n)
{
    BYTE* d = (BYTE*)dst;
    const BYTE* s = (const BYTE*)src;
    while (n--) {
        *d++ = *s++;
    }
}

static SIZE_T PpLen(const char* s)
{
    SIZE_T n = 0;
    if (!s) {
        return 0;
    }
    while (s[n]) {
        n++;
    }
    return n;
}

static void SlotWrite(HANDLE hSlot, const char* msg)
{
    DWORD written = 0;
    if (hSlot == NULL || hSlot == INVALID_HANDLE_VALUE || msg == NULL) {
        return;
    }
    WriteFile(hSlot, msg, (DWORD)PpLen(msg), &written, NULL);
    FlushFileBuffers(hSlot);
}

static BOOL PpAsciiToWide(const char* ascii, wchar_t* out, int outChars)
{
    if (!ascii || !out || outChars <= 0) {
        return FALSE;
    }
    return MultiByteToWideChar(CP_ACP, 0, ascii, -1, out, outChars) > 0;
}

static BOOL PpWriteTempExe(const BYTE* pe, DWORD peLen, char* outPath, SIZE_T outPathLen)
{
    char tempDir[MAX_PATH];
    char name[16];
    DWORD n;
    HANDLE hFile;
    DWORD written = 0;
    BOOL ok;
    DWORD tick;
    int i;

    n = GetTempPathA((DWORD)sizeof(tempDir), tempDir);
    if (n == 0 || n >= sizeof(tempDir)) {
        return FALSE;
    }

    tick = GetTickCount();
    name[0] = 'p';
    name[1] = 'p';
    name[2] = 'f';
    for (i = 0; i < 8; i++) {
        const char* hex = "0123456789ABCDEF";
        name[3 + i] = hex[(tick >> (28 - 4 * i)) & 0xF];
    }
    name[11] = '\0';

    if (outPathLen < PpLen(tempDir) + 16) {
        return FALSE;
    }
    {
        SIZE_T k;
        for (k = 0; tempDir[k]; k++) {
            outPath[k] = tempDir[k];
        }
        for (i = 0; name[i]; i++) {
            outPath[k++] = name[i];
        }
        outPath[k++] = '.';
        outPath[k++] = 'e';
        outPath[k++] = 'x';
        outPath[k++] = 'e';
        outPath[k] = '\0';
    }

    hFile = CreateFileA(
        outPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    ok = WriteFile(hFile, pe, peLen, &written, NULL);
    CloseHandle(hFile);
    if (!ok || written != peLen) {
        DeleteFileA(outPath);
        return FALSE;
    }
    return TRUE;
}

static int RunHost(const char* mapName)
{
    HANDLE hMap = NULL;
    LPVOID view = NULL;
    BYTE* p;
    DWORD magic;
    char slotPath[PPF_SLOT_MAX];
    DWORD asmLen;
    BYTE* asmBytes;
    DWORD argsLen;
    char* argsAscii;
    char* argsCopy = NULL;
    HANDLE hSlotWrite = INVALID_HANDLE_VALUE;
    HANDLE stdOut = INVALID_HANDLE_VALUE;
    HANDLE stdErr = INVALID_HANDLE_VALUE;
    BOOL comInit = FALSE;
    char exePathA[MAX_PATH];
    wchar_t exePathW[MAX_PATH];
    wchar_t argW[4096];
    ICLRMetaHost* pClrMetaHost = NULL;
    ICLRRuntimeInfo* pClrRuntimeInfo = NULL;
    ICLRRuntimeHost* pRuntimeHost = NULL;
    FN_CLRCreateInstance pCLRCreateInstance;
    HMODULE mscoree;
    HRESULT hr;
    DWORD managedRet = 0;
    int exitCode = 1;
    BOOL wroteExe = FALSE;

    exePathA[0] = '\0';

    if (mapName == NULL || mapName[0] == '\0') {
        return 2;
    }
    while (*mapName == ' ') {
        mapName++;
    }

    hMap = OpenFileMappingA(FILE_MAP_READ, FALSE, mapName);
    if (hMap == NULL) {
        return 3;
    }

    view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (view == NULL) {
        CloseHandle(hMap);
        return 4;
    }

    p = (BYTE*)view;
    magic = *(DWORD*)p;
    if (magic != PPF_MAGIC) {
        UnmapViewOfFile(view);
        CloseHandle(hMap);
        return 5;
    }

    PpCopy(slotPath, p + 4, PPF_SLOT_MAX);
    slotPath[PPF_SLOT_MAX - 1] = '\0';
    if (slotPath[0] == '\0') {
        UnmapViewOfFile(view);
        CloseHandle(hMap);
        return 6;
    }

    asmLen = *(DWORD*)(p + 4 + PPF_SLOT_MAX);
    if (asmLen == 0 || asmLen > 64 * 1024 * 1024) {
        UnmapViewOfFile(view);
        CloseHandle(hMap);
        return 7;
    }

    asmBytes = p + 4 + PPF_SLOT_MAX + 4;
    argsLen = *(DWORD*)(asmBytes + asmLen);
    argsAscii = (char*)(asmBytes + asmLen + 4);
    if (argsLen == 0 || argsLen > 4 * 1024 * 1024) {
        UnmapViewOfFile(view);
        CloseHandle(hMap);
        return 8;
    }

    argsCopy = (char*)PpAlloc((SIZE_T)argsLen + 1);
    if (!argsCopy) {
        UnmapViewOfFile(view);
        CloseHandle(hMap);
        return 9;
    }
    PpCopy(argsCopy, argsAscii, argsLen);
    argsCopy[argsLen] = '\0';

    if (!PpWriteTempExe(asmBytes, asmLen, exePathA, sizeof(exePathA))) {
        PpFree(argsCopy);
        UnmapViewOfFile(view);
        CloseHandle(hMap);
        return 11;
    }
    wroteExe = TRUE;

    /* Keep map open for managed ForkExec; only need slot path from it. */
    PpFree(argsCopy);
    argsCopy = NULL;

    hSlotWrite = CreateFileA(
        slotPath,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hSlotWrite == INVALID_HANDLE_VALUE) {
        DeleteFileA(exePathA);
        UnmapViewOfFile(view);
        CloseHandle(hMap);
        return 10;
    }

    {
        HANDLE hOut = NULL;
        HANDLE hErr = NULL;
        if (!DuplicateHandle(
                GetCurrentProcess(), hSlotWrite, GetCurrentProcess(), &hOut,
                0, TRUE, DUPLICATE_SAME_ACCESS) ||
            !DuplicateHandle(
                GetCurrentProcess(), hSlotWrite, GetCurrentProcess(), &hErr,
                0, TRUE, DUPLICATE_SAME_ACCESS)) {
            SlotWrite(hSlotWrite, "[!] host: DuplicateHandle failed\n");
            goto done;
        }
        SetStdHandle(STD_OUTPUT_HANDLE, hOut);
        SetStdHandle(STD_ERROR_HANDLE, hErr);
        stdOut = hOut;
        stdErr = hErr;
    }

    if (!PpAsciiToWide(exePathA, exePathW, MAX_PATH) ||
        !PpAsciiToWide(mapName, argW, 4096)) {
        SlotWrite(hSlotWrite, "[!] host: path/map conversion failed\n");
        goto done;
    }

    {
        HRESULT cohr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        if (cohr == S_OK || cohr == S_FALSE) {
            comInit = TRUE;
        } else if (cohr != RPC_E_CHANGED_MODE) {
            SlotWrite(hSlotWrite, "[!] host: CoInitializeEx failed\n");
            goto done;
        }
    }

    mscoree = LoadLibraryA("mscoree.dll");
    if (!mscoree) {
        SlotWrite(hSlotWrite, "[!] host: mscoree.dll missing\n");
        goto done;
    }
    pCLRCreateInstance =
        (FN_CLRCreateInstance)GetProcAddress(mscoree, "CLRCreateInstance");
    if (!pCLRCreateInstance) {
        SlotWrite(hSlotWrite, "[!] host: CLRCreateInstance missing\n");
        goto done;
    }

    hr = pCLRCreateInstance(&xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (void**)&pClrMetaHost);
    if (hr != S_OK) {
        SlotWrite(hSlotWrite, "[!] host: CLRMetaHost failed\n");
        goto done;
    }

    hr = pClrMetaHost->lpVtbl->GetRuntime(
        pClrMetaHost, L"v4.0.30319", &xIID_ICLRRuntimeInfo, (void**)&pClrRuntimeInfo);
    if (hr != S_OK) {
        SlotWrite(hSlotWrite, "[!] host: GetRuntime failed\n");
        goto done;
    }

    hr = pClrRuntimeInfo->lpVtbl->GetInterface(
        pClrRuntimeInfo,
        &xCLSID_CLRRuntimeHost,
        &xIID_ICLRRuntimeHost,
        (void**)&pRuntimeHost);
    if (hr != S_OK) {
        SlotWrite(hSlotWrite, "[!] host: ICLRRuntimeHost QI failed\n");
        goto done;
    }

    hr = pRuntimeHost->lpVtbl->Start(pRuntimeHost);
    if (hr != S_OK) {
        SlotWrite(hSlotWrite, "[!] host: ICLRRuntimeHost Start failed\n");
        goto done;
    }

    hr = pRuntimeHost->lpVtbl->ExecuteInDefaultAppDomain(
        pRuntimeHost,
        exePathW,
        L"PowerPickFork.Program",
        L"ForkExec",
        argW,
        &managedRet);
    if (hr != S_OK) {
        SlotWrite(hSlotWrite, "[!] host: ExecuteInDefaultAppDomain failed\n");
        exitCode = 1;
    } else {
        exitCode = (int)managedRet;
    }

done:
    PpFree(argsCopy);
    if (pRuntimeHost) {
        pRuntimeHost->lpVtbl->Release(pRuntimeHost);
    }
    if (pClrRuntimeInfo) {
        pClrRuntimeInfo->lpVtbl->Release(pClrRuntimeInfo);
    }
    if (pClrMetaHost) {
        pClrMetaHost->lpVtbl->Release(pClrMetaHost);
    }
    if (stdOut != INVALID_HANDLE_VALUE && stdOut != hSlotWrite) {
        CloseHandle(stdOut);
    }
    if (stdErr != INVALID_HANDLE_VALUE && stdErr != hSlotWrite && stdErr != stdOut) {
        CloseHandle(stdErr);
    }
    if (hSlotWrite != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(hSlotWrite);
        CloseHandle(hSlotWrite);
    }
    if (view) {
        UnmapViewOfFile(view);
    }
    if (hMap) {
        CloseHandle(hMap);
    }
    if (wroteExe && exePathA[0]) {
        DeleteFileA(exePathA);
    }
    if (comInit) {
        CoUninitialize();
    }
    return exitCode;
}

__declspec(dllexport) void CALLBACK PowerPickForkRun(
    HWND hwnd,
    HINSTANCE hinst,
    LPSTR lpszCmdLine,
    int nCmdShow)
{
    int code;
    (void)hwnd;
    (void)hinst;
    (void)nCmdShow;
    code = RunHost(lpszCmdLine ? lpszCmdLine : "");
    ExitProcess((UINT)code);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}
