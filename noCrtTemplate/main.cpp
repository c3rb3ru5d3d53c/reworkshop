#include "resolve.h"
#include "application.h"

#include <Windows.h>

void __stdcall WinMainCRTStartup()
{
	WinMain(NULL, NULL, NULL, SW_SHOWDEFAULT);
	_ExitProcess ExitProcess = (_ExitProcess)resolve_api(0x72d1dd1f, 0x349aa368);
	ExitProcess(ERROR_SUCCESS);
}