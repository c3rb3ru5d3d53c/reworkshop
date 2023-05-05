// https://github.com/LloydLabs/Windows-API-Hashing/blob/master/resolve.h


#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <subauth.h>

#define RESOLVE_NAME_MAX 4096
#define RESOLVE_REL_CALC(x,y) ((LPBYTE)x + y)

typedef HMODULE(WINAPI* _LoadLibraryW)(LPCWSTR);
typedef HMODULE(WINAPI* _LoadLibraryA)(LPCSTR);
typedef void(WINAPI* _ExitProcess)(UINT);
typedef BOOL(WINAPI* _GetUserNameA)(LPSTR, LPDWORD);
typedef LPVOID(WINAPI* _VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* _VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef INT(WINAPI* _getaddrinfo)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
typedef INT(WINAPI* _WSAStartup)(WORD, LPWSADATA);
typedef INT(WINAPI* _WSACleanup)();
typedef SOCKET(WINAPI* _socket)(int, int, int);
typedef int (WINAPI* _connect)(SOCKET, const sockaddr*, int);
typedef int (WINAPI* _closesocket)(SOCKET);
typedef VOID(WINAPI* _freeaddrinfo)(PADDRINFOA);
typedef int(WINAPI* _send)(SOCKET, const char*, int, int);
typedef int (WINAPI* _recv)(SOCKET, char*, int, int);
typedef int (WINAPI* _MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef BOOL(WINAPI* _IsDebuggerPresent)();
typedef HINSTANCE(WINAPI* _ShellExecuteA)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
typedef HMODULE(WINAPI* _GetModuleHandleA)(LPCSTR);
typedef HMODULE(WINAPI* _GetModuleHandleW)(LPCWSTR);

typedef struct RESOLVE_ENTRY {
    CONST UINT32 u32Hash;
    LPCSTR cszwMod;
    PVOID lpAddr;
} RESOLVE_ENTRY, * PRESOLVE_ENTRY;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    UCHAR           Reserved1[16];
    PVOID           Reserved2[10];
    UNICODE_STRING  ImagePathName;
    UNICODE_STRING  CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    BYTE                          Reserved4[104];
    PVOID                         Reserved5[52];
    PVOID                         PostProcessInitRoutine;
    BYTE                          Reserved6[128];
    PVOID                         Reserved7[1];
    ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _MODULE_ENTRY {
    UNICODE_STRING BaseName; // BaseName of the module
    UNICODE_STRING FullName; // FullName of the module
    ULONG SizeOfImage; // Size in bytes of the module
    PVOID BaseAddress; // Base address of the module
    PVOID EntryPoint; // Entrypoint of the module
} MODULE_ENTRY, * PMODULE_ENTRY;

typedef struct _MODULE_INFORMATION_TABLE {
    ULONG Pid; // PID of the process
    ULONG ModuleCount; // Modules count for the above pointer
    PMODULE_ENTRY Modules; // Pointer to 0...* modules
} MODULE_INFORMATION_TABLE, * PMODULE_INFORMATION_TABLE;

UINT32 resolve_hash_stra(LPCSTR s);
UINT32 resolve_hash_strw(LPCWSTR s);
SIZE_T resolve_strlenw(LPCWSTR s);
SIZE_T resolve_strlena(LPCSTR s);
UINT32 resolve_hash(BYTE* data, SIZE_T data_size);
FARPROC resolve_func(HMODULE hLibrary, UINT32 func_hash);
HMODULE resolve_loadlibraryw(LPCWSTR module);
HMODULE resolve_loadlibrarya(LPCSTR module);
//void resolve_print(LPCWSTR module_name, LPCSTR func_name);
FARPROC resolve_api(UINT32 module_hash, UINT32 func_hash);
BYTE* resolve_zero_memory(BYTE* data, SIZE_T data_size);
void resolve_strcata(char* dest, char * src, SIZE_T max_size);
void* resolve_memcpy(void* dest, const void* src, size_t n);