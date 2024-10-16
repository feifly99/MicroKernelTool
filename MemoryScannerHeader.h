#ifndef __MEMORY_SCANNER_HEADER__
#define __MEMORY_SCANNER_HEADER__

#include "DriverBaseHeader.h"

#define __FIRST_PRECISE_SCAN__ 0x80
#define __FIRST_FUZZY_SCAN__ 0x90

#define __MODE_JUDGE_PRECISE__ 0x10
#define __MODE_JUDGE_FUZZY__ 0x18
#define __MODE_JUDGE_PATTERN__ 0x20

#define __TYPE_BYTE__ 0xA1
#define __TYPE_WORD__ 0xA2
#define __TYPE_DWORD__ 0xA3
#define __TYPE_QWORD__ 0xA4
#define __TYPE_PATTERN__ 0xA5
#define __TYPE_FLOAT__ 0xA6
#define __TYPE_DOUBLE__ 0xA7
#define __TYPE_NOT_FLOATING__ 0xA8

#define __Continue_PRECISE__ 0xC1
#define __Continue_LARGER__ 0xC2
#define __Continue_LOWER__ 0xC3
#define __Continue_UNCHANGED__ 0xC4
#define __Continue_REGION__ 0xC5

typedef UCHAR DATA_TYPE;

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
        SIZE_T dataLen;
    }preciseMode;

    struct _fuzzyMode
    {
        PUCHAR lowLimit_hexBytePointer;
        PUCHAR highLimit_hexBytePointer;
        SIZE_T dataLen;
    }fuzzyMode;

    struct _patternMode
    {
        PUCHAR pattern;
        SIZE_T patternLen;
    }patternMode;

    UCHAR modeJudge;

}SMI, * PSMI;

float mabs_float(
    float x
);

double mabs_double(
    double x
);

// Valid AddressLink
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
VOID buildValidAddressSingleList(
    //此函数补全VAL结构的SINGLE_LIST_ENTRY成员
    IN PHANDLE phProcess,
    IN PMEMORY_INFORMATION_CLASS pMIC,
    IN PMEMORY_BASIC_INFORMATION pmbi,
    OUT PVAL* headVAL,
    IN ULONG64 addressMaxLimit
);

// ResultSavedLink:
PRSL createResultSavedNode(
    IN ULONG times,
    IN ULONG64 address,
    IN ULONG64 addressBufferLen,
    IN PVAL headVAL
);
VOID initializePreciseSearchModeInput(
    OUT PSMI* smi,
    IN SIZE_T valueLen,
    IN PVOID pointerToIntegerValue
);
VOID initializeFuzzySearchModeInput(
    OUT PSMI* smi,
    IN SIZE_T valueLen,
    IN PVOID pointerToLowerValue,
    IN PVOID pointerToHigherValue
);
VOID initializePatternMatchTypeSearchModeInput(
    OUT PSMI* smi,
    IN PUCHAR pattern,
    IN SIZE_T patternLen
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
VOID buildDoubleLinkedAddressListForScaningResult( //APC attach inline
    IN ULONG64 pid,
    IN UCHAR firstSearchMode, //[0]: precise search [1]: fuzzy search
    IN PSMI smi,
    IN UCHAR dataType,
    IN PVAL headVAL,
    OUT PRSL* headRSL
);
VOID continueSearch(
    IN ULONG64 pid,
    IN UCHAR continueSearchType,
    IN UCHAR dataType,
    IN PSMI searchInput,
    IN_OUT PRSL* headRSL
);//如果第四个参数是【PRSL headRSL】输入就会出现泄露：只要是变化的值，永远传指针。
VOID checkSMI(
    IN PSMI smi
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
//FreeLinkLists
VOID ExFreeResultSavedLink(
    OUT PRSL* headRSL
);
VOID ExFreeValidAddressLink(
    OUT PVAL* headVAL
);
#endif
