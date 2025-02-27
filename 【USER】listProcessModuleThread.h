#ifndef __LIST_PROCESS_MODULE_THREAD__
#define __LIST_PROCESS_MODULE_THREAD__

#include "BaseHeader.h"

VOID listProcessModuleThreadBeginStub(
	IN HANDLE* hDevice
);

VOID listProcessModuleThreadReleaseStub(
	VOID
);

BOOL listModules(
	IN HANDLE pid
);

BOOL listThreads(
	IN HANDLE pid
);

#endif