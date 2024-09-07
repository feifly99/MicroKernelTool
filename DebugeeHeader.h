#ifndef __DEBUGEE_DRIVER_HEADER__
#define __DEBUGEE_DRIVER_HEADER__

#include "DriverBaseHeader.h"

#define onceReadPagesCount 64

#define DELAY_ONE_MICROSECOND     (-10)
#define DELAY_ONE_MILLISECOND    (DELAY_ONE_MICROSECOND*1000)

typedef ULONG64 UL64;
typedef MEMORY_INFORMATION_CLASS* PMEMORY_INFORMATION_CLASS;
typedef PEPROCESS* PPEPROCESS;

typedef struct _ValidAddressLink
{
    ULONG64 beginAddress;
    ULONG64 endAddress;
    ULONG memoryState;
    ULONG memoryProtectAttributes;
    BOOLEAN executeFlag;
    ULONG64 regionGap;
    ULONG64 pageNums;
    SINGLE_LIST_ENTRY ValidAddressEntry;
}VAL, * PVAL;

typedef struct _ResultSavedLink
{
    ULONG times;
    ULONG64 address;
    LIST_ENTRY ResultAddressEntry;
}RSL, * PRSL, ** PPRSL;

VOID KernelDriverThreadSleep(
    LONG msec
);
PVAL createValidAddressNode(
    ULONG64 begin, 
    ULONG64 end, 
    ULONG memState, 
    ULONG memProtectAttributes, 
    BOOLEAN executeFlag
);
PRSL createSavedResultNode(
    ULONG times, 
    ULONG64 address
);
VOID getRegionGapAndPages(
    PVAL headVAL
);
ULONG64 getMaxRegionPages(
    //此函数补全VAL结构的regionGap和pageNums成员
    PVAL head
); 
//KMP Algorithm
VOID computeLPSArray(
    CONST UCHAR* pattern, 
    UL64 M, 
    UL64* lps
);
VOID KMP_searchPattern(
    CONST UCHAR* des, 
    CONST UCHAR* pattern, 
    SIZE_T desLen, 
    SIZE_T patLen, 
    ULONG64 pageBeginAddress, 
    UL64* lpsAddress, 
    PRSL* headRSL
);
//Debug judge and output
BOOLEAN isSame(
    PUCHAR A, 
    PUCHAR B, 
    SIZE_T size
);
VOID printListVAL(
    PVAL headVAL
);
VOID printListRSL(
    PRSL headRSL
);
VOID ReadBuffer(
    PVOID bufferHead, 
    SIZE_T size
);
//Single&Double linked list built
VOID buildValidAddressSingleList(
    //此函数补全VAL结构的SINGLE_LIST_ENTRY成员
    PHANDLE phProcess, 
    PMEMORY_INFORMATION_CLASS pMIC, 
    PMEMORY_BASIC_INFORMATION pmbi, 
    PVAL* headVAL, 
    ULONG64 addressMaxLimit
); 
VOID buildDoubleLinkedAddressListForPatternStringByKMPAlgorithm(
    //此函数补全RSL结构的LIST_ENTRY成员
    PVAL headVAL, 
    PPEPROCESS pPe, 
    PUCHAR pattern, 
    SIZE_T patternLen, 
    PRSL* headRSL
);
//FreeLinkLists
VOID ExFreeResultSavedLink(
    PRSL* headRSL
);
VOID ExFreeValidAddressLink(
    PVAL* headVAL
);
#endif