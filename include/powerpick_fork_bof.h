#pragma once
#include <windows.h>

#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)

#ifndef _TRUNCATE
#define _TRUNCATE ((size_t)-1)
#endif

#define PPF_MAGIC 0x4B464650u /* 'PFFK' */
#define PPF_DEFAULT_SPAWNTO "C:\\Windows\\System32\\rundll32.exe"
#define PPF_WAIT_MS (180 * 1000)
#define PPF_SLOT_MAX 160
#define CHUNK_SIZE 65535
#define INITIAL_BUFFER_SIZE 65535
#define TMPBUFLEN 64
#define PPF_MAX_IMPORTS 16
#define PPF_IMPORT_KEY_PREFIX "ppfimp-"
#define PPF_IMPORT_KEY_PREFIX_LEN 7

/* MSVCRT */
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict _Dst, const void* __restrict _Src, size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
WINBASEAPI SIZE_T WINAPI MSVCRT$strlen(const char* str);
WINBASEAPI int __cdecl MSVCRT$_snprintf(char* s, size_t n, const char* fmt, ...);
WINBASEAPI void __cdecl MSVCRT$free(void* _Memory);
WINBASEAPI int __cdecl MSVCRT$strncmp(const char* _Str1, const char* _Str2, size_t _MaxCount);

/* KERNEL32 */
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
WINBASEAPI void* WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateMailslotA(LPCSTR lpName, DWORD nMaxMessageSize, DWORD lReadTimeout, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
WINBASEAPI BOOL WINAPI KERNEL32$GetMailslotInfo(HANDLE hMailslot, LPDWORD lpMaxMessageSize, LPDWORD lpNextSize, LPDWORD lpMessageCount, LPDWORD lpReadTimeout);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
WINBASEAPI HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
WINBASEAPI HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL hMem);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
WINBASEAPI LPVOID WINAPI KERNEL32$MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
WINBASEAPI BOOL WINAPI KERNEL32$UnmapViewOfFile(LPCVOID lpBaseAddress);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
WINBASEAPI BOOL WINAPI KERNEL32$ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
WINBASEAPI SIZE_T WINAPI KERNEL32$VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
WINBASEAPI BOOL WINAPI KERNEL32$GetExitCodeThread(HANDLE hThread, LPDWORD lpExitCode);
WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread(HANDLE hThread);
WINBASEAPI DWORD WINAPI KERNEL32$QueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
WINBASEAPI BOOL WINAPI KERNEL32$TerminateProcess(HANDLE hProcess, UINT uExitCode);
WINBASEAPI BOOL WINAPI KERNEL32$GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
WINBASEAPI BOOL WINAPI KERNEL32$FlushFileBuffers(HANDLE hFile);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI void WINAPI KERNEL32$SetLastError(DWORD dwErrCode);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI DWORD WINAPI KERNEL32$GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer);
WINBASEAPI UINT WINAPI KERNEL32$GetWindowsDirectoryA(LPSTR lpBuffer, UINT uSize);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
WINBASEAPI BOOL WINAPI KERNEL32$DeleteFileA(LPCSTR lpFileName);
WINBASEAPI LPWCH WINAPI KERNEL32$GetEnvironmentStringsW(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$FreeEnvironmentStringsW(LPWCH penv);
WINBASEAPI int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
WINBASEAPI int WINAPI KERNEL32$lstrlenW(LPCWSTR lpString);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread(VOID);

/* ADVAPI32 — optional --impersonate spawn */
WINBASEAPI BOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
WINBASEAPI BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
WINBASEAPI BOOL WINAPI ADVAPI32$CreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINBASEAPI BOOL WINAPI ADVAPI32$CreateProcessWithTokenW(HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInfo);
WINBASEAPI BOOL WINAPI ADVAPI32$RevertToSelf(VOID);
WINBASEAPI BOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE hToken);

typedef BOOLEAN(WINAPI* RTLGENRANDOM)(PVOID, ULONG);
