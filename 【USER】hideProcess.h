#ifndef __HIDE_PROCESS__
#define __HIDE_PROCESS__

#include "BaseHeader.h"

VOID processHideBeginStub(
	IN HANDLE* hDevice
);

VOID processHideReleaseStub(
	VOID
);

VOID hideProcess(
	HANDLE pid
);

VOID restoreHidenProcess(
	VOID
);

#endif