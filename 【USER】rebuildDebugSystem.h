#ifndef __DEBUG_SYSTEM_REBUILD__
#define __DEBUG_SYSTEM_REBUILD__

#include "BaseHeader.h"

VOID rebuildDebugSystemBeginStub(
	IN HANDLE* hDevice
);

VOID rebuildDebugSystemReleaseStub(
	VOID
);

VOID rebuildDebugSystem(
	IN USHORT newDebugPortOffset
);

VOID restoreDebugSystem(
	VOID
);

#endif