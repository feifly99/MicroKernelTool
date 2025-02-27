#include "dllInjection.h"

static HANDLE g_hDevice = NULL;

VOID injectionBeginStub(
	IN HANDLE* hDevice
)
{
	g_hDevice = *hDevice;
	return;
}

VOID injectionReleaseStub(
	VOID
)
{
	g_hDevice = NULL;
	return;
}

VOID dllInjection(
	IN HANDLE pid,
	IN PUCHAR dllPath
)
{
	UNREFERENCED_PARAMETER(pid);
	UNREFERENCED_PARAMETER(dllPath);
	return;
}