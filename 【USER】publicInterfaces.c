#include "publicInterface.h"

HANDLE global_main_hDevice = NULL;

VOID (*functionsBeginStub[DRIVER_USER_INTERACTION_MODULES_NUM])(HANDLE* hDevice) = {
	debuggerBeginStub,
	injectionBeginStub,
	processHideBeginStub,
	listProcessModuleThreadBeginStub,
	memoryScannerBeginStub,
	getHandleInKernelBeginStub,
	readWriteMemoryBeginStub,
	rebuildDebugSystemBeginStub
};

VOID (*functionsReleaseStub[DRIVER_USER_INTERACTION_MODULES_NUM])(VOID) = {
	debuggerReleaseStub,
	injectionReleaseStub,
	processHideReleaseStub,
	listProcessModuleThreadReleaseStub,
	memoryScannerReleaseStub,
	getHandleInKernelReleaseStub,
	readWriteMemoryReleaseStub,
	rebuildDebugSystemReleaseStub
};

BOOL initializeGlobalKernelFileHandle(
	VOID
)
{
	global_main_hDevice = CreateFile(L"\\\\.\\ANYIFEI_SYMBOLINK_NAME", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (!global_main_hDevice)
	{
		return FALSE;
	}
	return TRUE;
}

BOOL closeGlobalKernelFileHandle(
	VOID
)
{
	DeviceIoControl(global_main_hDevice, ____$_UNLOAD_DRIVER_PREPARE_$____, NULL, 0, NULL, 0, NULL, NULL);
	CloseHandle(global_main_hDevice);
	return TRUE;
}

VOID beginStub(
	DRIVER_MODULES index
)
{
	functionsBeginStub[index](&global_main_hDevice);
	return;
}

VOID releaseStub(
	DRIVER_MODULES index
)
{
	functionsReleaseStub[index]();
	return;
}