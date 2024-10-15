#ifndef __MEMORY_SCANNER_HEADER__
#define __MEMORY_SCANNER_HEADER__

#include "DriverBaseHeader.h"

typedef struct _ValidAddressList
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

typedef struct _ResultSavedList
{
    ULONG times;
    ULONG64 address;
    ULONG64 rslAddressBufferLen;
    ULONG64 thisNodeAddressPageMaxValidAddress;
    PUCHAR buffer;
    LIST_ENTRY ResultAddressEntry;
}RSL, * PRSL, ** PPRSL;

typedef union _SearchModeInput
{
    struct _preciseMode
    {
        PUCHAR value_hexBytePointer;
        UCHAR dataLen;
    }preciseMode;

    struct _fuzzyMode
    {
        PUCHAR lowLimit_hexBytePointer;
        PUCHAR highLimit_hexBytePointer;
        UCHAR dataLen;
    }fuzzyMode;
}SMI, * PSMI;

PVAL createValidAddressNode(
    IN ULONG64 begin,
    IN ULONG64 end,
    IN ULONG memState,
    IN ULONG memProtectAttributes,
    IN BOOLEAN executeFlag
);
VOID getRegionGapAndPages(
    //此函数补全VAL结构的regionGap和pageNums成员
    IN_OUT PVAL headVAL
);
PRSL createSavedResultNode(
    IN ULONG times,
    IN ULONG64 address,
    IN ULONG64 addressBufferLen,
    IN PVAL headVAL
);
//KMP Algorithm
VOID KMP_computeLPSArray(
    CONST PUCHAR pattern,
    SIZE_T patLen,
    LONG* lps
);
VOID KMP_searchPattern(
    IN CONST PUCHAR des,
    IN CONST PUCHAR pattern,
    IN SIZE_T desLen,
    IN SIZE_T patLen,
    IN ULONG64 pageBeginAddress,
    IN PVAL headVAL,
    OUT ULONG64* addressWannaFreed,
    OUT PRSL* headRSL
);
VOID FUZZY_searchRegion(
    IN CONST PUCHAR des,
    IN SIZE_T desLen,
    IN UCHAR dataType, //[0]: 1b [1]: 2b [2]: 4b [3]: 8b [4]: float [5]: double
    IN PUCHAR lowHexPointer,
    IN PUCHAR highHexPointer,
    IN ULONG64 pageBeginAddress,
    IN PVAL headVAL,
    OUT PRSL* headRSL
);
BOOLEAN checkAllRSLAddressLenValid(
    IN PRSL headRSL
);
VOID printListVAL(
    IN PVAL headVAL
);
VOID printListRSL(
    IN PRSL headRSL
);
ULONG64 getMaxRegionPages(
    IN PVAL head
);
SIZE_T getNodeNumsForDoubleLinkedList(
    IN PRSL headRSL
);
UCHAR farBytesDiffer(
    IN PUCHAR oldPattern,
    IN PUCHAR newPattern,
    IN SIZE_T minSize
);
//Single&Double linked list built
VOID buildValidAddressSingleList(
    //此函数补全VAL结构的SINGLE_LIST_ENTRY成员
    IN PHANDLE phProcess,
    IN PMEMORY_INFORMATION_CLASS pMIC,
    IN PMEMORY_BASIC_INFORMATION pmbi,
    OUT PVAL* headVAL,
    IN ULONG64 addressMaxLimit
);
VOID buildDoubleLinkedAddressListForScaningResult(
    IN UCHAR searchMode, //[0]: precise search [1]: fuzzy search
    IN ULONG64 pid,
    IN PVAL headVAL,
    IN PSMI searchInput,
    OUT PRSL* headRSL
);
//FreeLinkLists
VOID ExFreeResultSavedLink(
    OUT PRSL* headRSL
);
VOID ExFreeValidAddressLink(
    OUT PVAL* headVAL
);
#endif
