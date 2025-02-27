#ifndef __DLL_INJECTION__
#define __DLL_INJECTION__

#include "BaseHeader.h"

typedef struct dllInjectionInfo
{
	HANDLE pidWannaInject;
	PUNICODE_STRING dllFullPath;
}DLL_INJECT_INFORMATION, *PDLL_INJECT_INFORMATION;

VOID injectionBeginStub(
	IN HANDLE* hDevice
);

VOID injectionReleaseStub(
	VOID
);

VOID dllInjection(
	IN HANDLE pid,
	IN PUCHAR dllPath
);

#endif