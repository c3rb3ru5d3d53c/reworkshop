// https://raw.githubusercontent.com/LloydLabs/Windows-API-Hashing/master/resolve.c

#include "resolve.h"
#include <wchar.h>
#include <stdio.h>

BYTE* resolve_zero_memory(BYTE* data, SIZE_T data_size) {
	for (int i = 0; i < data_size; i++) {
		data[i] = 0x00;
	}
	return data;
}

__declspec(noinline) UINT32 resolve_hash(BYTE* data, SIZE_T data_size) {
	UINT32 hash = 0xdeadbeef;
	for (SIZE_T i = 0; i < data_size; i++) {
		BYTE c = data[i];
		hash += c;
		hash ^= hash << 8;
	}
	return hash;
}

SIZE_T resolve_strlena(LPCSTR s) {
	size_t l = 0;
	while (*s != '\0') {
		++l;
		++s;
	}
	return l;
}

SIZE_T resolve_strlenw(LPCWSTR s) {
	size_t l = 0;
	while (*s != L'\0') {
		++l;
		++s;
	}
	return l;
}

UINT32 resolve_hash_stra(LPCSTR s) {
	return resolve_hash((BYTE*)s, resolve_strlena(s));
}

UINT32 resolve_hash_strw(LPCWSTR s) {
	return resolve_hash((BYTE*)s, resolve_strlenw(s));
}

PPEB resolve_getpeb() {
#if defined(_WIN64)
	return (PPEB)__readgsqword(0x60);
#else
	return (PPEB)__readfsdword(0x30);
#endif
}

void resolve_strcata(char *dest, char * src, SIZE_T max_size) {
	while (*dest && max_size > 0) {
		dest++;
		max_size--;
	}
	while (*src && max_size > 1) {
		*dest++ = *src++;
		max_size--;
	}
	*dest = '\0';
}

void * resolve_memcpy(void* dest, const void* src, size_t n) {
	char* dest_ptr = (char*)dest;
	const char* src_ptr = (const char*)src;
	while (n--) {
		*dest_ptr++ = *src_ptr++;
	}
	return dest;
}

HMODULE resolve_loadlibraryw(LPCWSTR module) {
	PPEB pPEB = resolve_getpeb();
	if (pPEB == NULL) {
		return NULL;
	}

	PPEB_LDR_DATA pLdrData = NULL;
	PLIST_ENTRY pHeadEntry = NULL;
	PLIST_ENTRY pEntry = NULL;
	PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;

	pLdrData = pPEB->Ldr;
	pHeadEntry = &pLdrData->InMemoryOrderModuleList;
	pEntry = pHeadEntry->Flink;
	while (pEntry != pHeadEntry) {
		pLdrEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);
		if (resolve_hash_strw(pLdrEntry->BaseDllName.Buffer) == 0xa1f2c0b0) {
			_LoadLibraryW LoadLibraryW = (_LoadLibraryW)resolve_func((HMODULE)pLdrEntry->DllBase, 0x43bce09b);
			if (LoadLibraryW == NULL) {
				return NULL;
			}
			HMODULE hModule = LoadLibraryW(module);
			if (hModule == NULL) {
				return NULL;
			}
			return hModule;
		}
		pEntry = pEntry->Flink;
	}
}

HMODULE resolve_loadlibrarya(LPCSTR module) {
	PPEB pPEB = resolve_getpeb();
	if (pPEB == NULL) {
		return NULL;
	}

	PPEB_LDR_DATA pLdrData = NULL;
	PLIST_ENTRY pHeadEntry = NULL;
	PLIST_ENTRY pEntry = NULL;
	PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;

	pLdrData = pPEB->Ldr;
	pHeadEntry = &pLdrData->InMemoryOrderModuleList;
	pEntry = pHeadEntry->Flink;
	while (pEntry != pHeadEntry) {
		pLdrEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);
		if (resolve_hash_strw(pLdrEntry->BaseDllName.Buffer) == 0xa1f2c0b0) {
			_LoadLibraryA LoadLibraryA = (_LoadLibraryA)resolve_func((HMODULE)pLdrEntry->DllBase, 0x43bcfe85);
			if (LoadLibraryA == NULL) {
				return NULL;
			}
			HMODULE hModule = LoadLibraryA(module);
			if (hModule == NULL) {
				return NULL;
			}
			return hModule;
		}
		pEntry = pEntry->Flink;
	}
	return NULL;
}

FARPROC resolve_api(UINT32 module_hash, UINT32 func_hash) {
	PPEB pPEB = resolve_getpeb();
	if (pPEB == NULL) {
		return NULL;
	}
	PPEB_LDR_DATA pLdrData = NULL;
	PLIST_ENTRY pHeadEntry = NULL;
	PLIST_ENTRY pEntry = NULL;
	PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;
	pLdrData = pPEB->Ldr;
	pHeadEntry = &pLdrData->InMemoryOrderModuleList;
	pEntry = pHeadEntry->Flink;
	while (pEntry != pHeadEntry) {
		pLdrEntry = CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);
		if (resolve_hash_strw(pLdrEntry->BaseDllName.Buffer) == module_hash) {
			FARPROC pFunc = resolve_func((HMODULE)pLdrEntry->DllBase, func_hash);
			if (pFunc == NULL) {
				return NULL;
			}
			return pFunc;
		}
		pEntry = pEntry->Flink;
	}
	return NULL;
}

FARPROC resolve_func(HMODULE hLibrary, UINT32 func_hash)
{
	PIMAGE_DOS_HEADER pDOSHdr = (PIMAGE_DOS_HEADER)hLibrary;
	if (pDOSHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	PIMAGE_NT_HEADERS pNTHdr = (PIMAGE_NT_HEADERS)RESOLVE_REL_CALC(hLibrary, pDOSHdr->e_lfanew);
	if (pNTHdr->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	if (
		(pNTHdr->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0 ||
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0
		)
	{
		return NULL;
	}

	PIMAGE_EXPORT_DIRECTORY pIED = (PIMAGE_EXPORT_DIRECTORY)RESOLVE_REL_CALC(hLibrary,
		pNTHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pdwAddress = (PDWORD)RESOLVE_REL_CALC(hLibrary, pIED->AddressOfFunctions);
	PDWORD pdwNames = (PDWORD)RESOLVE_REL_CALC(hLibrary, pIED->AddressOfNames);
	PWORD pwOrd = (PWORD)RESOLVE_REL_CALC(hLibrary, pIED->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pIED->AddressOfFunctions; i++)
	{
		UINT32 u32FuncHash = resolve_hash_stra((LPCSTR)RESOLVE_REL_CALC(hLibrary, pdwNames[i]));
		if (u32FuncHash == func_hash)
		{
			return (FARPROC)RESOLVE_REL_CALC(hLibrary, pdwAddress[pwOrd[i]]);
		}
	}
	return NULL;
}
