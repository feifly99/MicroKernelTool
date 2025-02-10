#ifndef __SSDT_HIJACK_HEADER__
#define __SSDT_HIJACK_HEADER__

#include "DriverBaseHeader.h"

ULONG_PTR getPointerToSSDT(
);
ULONG_PTR getAvaliableExecuteMemoryInSSDT(
);
ULONG_PTR getSSDTFunctionAddressByIndex(
    IN SIZE_T index
);
ULONG hookSSDTProcedure(
    IN SIZE_T functionIndexInSSDT,
    IN ULONG_PTR newHookFunctionAddress
);
VOID hookSSDTRestore(
    IN SIZE_T functionIndexInSSDT,
    IN ULONG oldRellocationOffset
);

#endif
