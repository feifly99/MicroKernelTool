#ifndef __SSDT_HIJACK_HEADER__
#define __SSDT_HIJACK_HEADER__

#include "DriverBaseHeader.h"

ULONG64 getPointerToSSDT(
);
ULONG64 getAvaliableExecuteMemoryInSSDT(
);
ULONG64 getSSDTFunctionAddressByIndex(
    IN ULONG64 index
);
ULONG hookSSDTProcedure(
    IN ULONG64 functionIndexInSSDT,
    IN ULONG64 newHookFunctionAddress
);
VOID hookSSDTRestore(
    IN ULONG64 functionIndexInSSDT,
    IN ULONG oldRellocationOffset
);

#endif
