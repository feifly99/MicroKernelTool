#include "rebuildDebugSystem.h"

static HANDLE g_hDevice = NULL;

VOID rebuildDebugSystemBeginStub(
	IN HANDLE* hDevice
)
{
	g_hDevice = *hDevice;
	return;
}

VOID rebuildDebugSystemReleaseStub(
	VOID
)
{
	g_hDevice = NULL;
	return;
}

VOID rebuildDebugSystem(
	IN USHORT newDebugPortOffset
)
{
	USHORT newOffset = newDebugPortOffset;
	DeviceIoControl(g_hDevice, ____$_REBUILD_DEBUG_SYSTEM_$____, &newOffset, sizeof(USHORT), NULL, 0, NULL, NULL);
	return;
}

VOID restoreDebugSystem(
	VOID
)
{
	DeviceIoControl(g_hDevice, ____$_REBUILD_DEBUG_SYSTEM_$____, NULL, 0, NULL, 0, NULL, NULL);
	return;
}