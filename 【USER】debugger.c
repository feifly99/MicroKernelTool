#include "debugger.h"

static HANDLE g_hDevice = NULL;

VOID debuggerBeginStub(
	IN HANDLE* hDevice
)
{
	g_hDevice = *hDevice;
	return;
}

VOID debuggerReleaseStub(
	VOID
)
{
	g_hDevice = NULL;
	return;
}