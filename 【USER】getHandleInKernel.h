#ifndef __TEMP__
#define __TEMP__

#include "BaseHeader.h"

VOID getHandleInKernelBeginStub(
	IN HANDLE* hDevice
);

VOID getHandleInKernelReleaseStub(
	VOID
);

HANDLE superGetProcessHandle(
	IN HANDLE pidInput
);

VOID superCloseProcessHandle(
	IN HANDLE processHandle
);

#endif