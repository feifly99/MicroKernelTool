#include "listProcessModuleThread.h"

static HANDLE g_hDevice = NULL;

VOID listProcessModuleThreadBeginStub(
	IN HANDLE* hDevice
)
{
	g_hDevice = *hDevice;
	return;
}

VOID listProcessModuleThreadReleaseStub(
	VOID
)
{
	g_hDevice = NULL;
	return;
}

BOOL listModules(
	IN HANDLE pid
)
{
	HANDLE krnlPidTrans = pid;	
	return DeviceIoControl(g_hDevice, ____$_LIST_PROCESS_MODULE_$____, &krnlPidTrans, sizeof(HANDLE), NULL, 0, NULL, NULL);
}

BOOL listThreads(
	IN HANDLE pid
)
{
	HANDLE krnlPidTrans = pid;
	return DeviceIoControl(g_hDevice, ____$_LIST_PROCESS_THREAD_$____, &krnlPidTrans, sizeof(HANDLE), NULL, 0, NULL, NULL);
}