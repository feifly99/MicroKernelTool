#include "hideProcess.h"

static HANDLE g_hDevice = NULL;

VOID processHideBeginStub(
	IN HANDLE* hDevice
)
{
	g_hDevice = *hDevice;
	return;
}

VOID processHideReleaseStub(
	VOID
)
{
	g_hDevice = NULL;
	return;
}

VOID hideProcess(
	HANDLE pid
)
{
	HANDLE krnlTrans = pid;
	DeviceIoControl(g_hDevice, ____$_PROCESS_HIDEN_PROCEDURE_$____, &krnlTrans, sizeof(HANDLE), NULL, 0, NULL, NULL);
	return;
}

VOID restoreHidenProcess(
	VOID
)
{
	DeviceIoControl(g_hDevice, ____$_PROCESS_RESTORE_PROCEDURE_$____, NULL, 0, NULL, 0, NULL, NULL);
	return;
}