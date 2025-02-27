#include "getHandleInKernel.h"

static HANDLE g_hDevice = NULL;

VOID getHandleInKernelBeginStub(
	IN HANDLE* hDevice
)
{
	g_hDevice = *hDevice;
	return;
}

VOID getHandleInKernelReleaseStub(
	VOID
)
{
	g_hDevice = NULL;
	return;
}

HANDLE superGetProcessHandle(
	IN HANDLE pidInput
)
{
	HANDLE inputPid = pidInput;
	HANDLE processHandle = NULL;
	DeviceIoControl(g_hDevice, ____$_GET_PROCESS_HANDLE_$____, &inputPid, sizeof(HANDLE), &processHandle, sizeof(HANDLE), NULL, NULL);
	if ((ULONG64)GetProcessId(processHandle) != (ULONG64)pidInput)
	{
		printf("得到的句柄对应的Pid: %d和输入Pid: %llu不同，谨慎使用！\n", GetProcessId(processHandle), (ULONG64)pidInput);
	}
	return processHandle;
}

VOID superCloseProcessHandle(
	IN HANDLE processHandle
)
{
	HANDLE stackTempProcessHandle = processHandle;
	DeviceIoControl(g_hDevice, ____$_CLOSE_PROCESS_HANDLE_$____, &stackTempProcessHandle, sizeof(HANDLE), NULL, 0, NULL, NULL);
	return;
}