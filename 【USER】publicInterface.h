#ifndef __PUBLIC_INTERFACE_USER__
#define __PUBLIC_INTERFACE_USER__

#include "debugger.h"
#include "dllInjection.h"
#include "hideProcess.h"
#include "listProcessModuleThread.h"
#include "memoryScanner.h"
#include "getHandleInKernel.h"
#include "readWriteMemory.h"
#include "rebuildDebugSystem.h"

typedef enum _DRIVER_MODULES {
	//子功能号：
	DEBUGGER_STUB = 0,
	INJECTION_STUB = 1,
	PROCESS_HIDEN_STUB = 2,
	LIST_PROCESS_MODULE_THREAD_STUB = 3,
	MEMORY_SCANNER_STUB = 4,
	GET_HANDLE_STUB = 5,
	READ_WRITE_STUB = 6,
	REBUILD_DEBUG_SYSTEM_STUB = 7,
	//合计：
	DRIVER_USER_INTERACTION_MODULES_NUM = 8
}DRIVER_MODULES;

typedef struct _GET_PROCESS_HANDLE {
	HANDLE pid;
	HANDLE processHandle;
	ULONG isSetted;
}GET_PROCESS_HANDLE, *PGET_PROCESS_HANDLE;

BOOL initializeGlobalKernelFileHandle(
	VOID
);

BOOL closeGlobalKernelFileHandle(
	VOID
);

VOID beginStub(
	DRIVER_MODULES index
);

VOID releaseStub(
	DRIVER_MODULES index
);

#endif