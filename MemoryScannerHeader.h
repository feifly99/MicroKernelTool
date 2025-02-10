#ifndef __MEMORY_SCANNER_HEADER__
#define __MEMORY_SCANNER_HEADER__

#include "DriverBaseHeader.h"

typedef enum _valueType
{
    TYPE_BYTE           = 0xA1,
    TYPE_WORD           = 0xA2,
    TYPE_DWORD          = 0xA3,
    TYPE_QWORD          = 0xA4,
    TYPE_PATTERN        = 0xA5,
    TYPE_FLOAT          = 0xA6,
    TYPE_DOUBLE         = 0xA7,
    TYPE_NOT_FLOATING   = 0xA8
}VALUE_TYPE;

typedef enum _scanType
{
    FIRST_PRECISE_SCAN = 0x30, //need new input
    FIRST_REGION_SCAN = 0x40, //need new input
    FIRST_PATTERN_SCAN = 0xFF, //need new input
    CONTINUE_PRECISE = 0x30C0, //need new input
    CONTINUE_REGION = 0x40C0, //need new input
    CONTINUE_PATTERN = 0xFFC0, //need new input
    CONTINUE_LARGER = 0x50C0,
    CONTINUE_LOWER = 0x60C0,
    CONTINUE_UNCHANGED = 0x70C0,
    CONTINUE_INCREASED_BY = 0x80C0,
    CONTINUE_DECREASED_BY = 0x90C0,
}SCAN_TYPE;

typedef enum _UnionMemberType
{
    //标记枚举类型实际选取的结构.
    //三个枚举值对应三个结构，其目的在于方便地内核化用户层指针.
    UNION_MEMBER_PRECISE = 1,
    UNION_MEMBER_REGION = 2,
    UNION_MEMBER_PATTERN = 3
}UNION_MEMBER_TYPE;

typedef enum _largerLowerEqualType
{
    COMPARE_LARGER = 1,
    COMPARE_LOWER = 2,
    COMPARE_UNCHANGED = 3
}LLE_JUDGE;

typedef struct _ValidAddressList
{
    ULONG_PTR beginAddress;
    ULONG_PTR endAddress;
    ULONG memoryState;
    ULONG memoryProtectAttributes;
    BOOLEAN executeFlag;
    SIZE_T regionGap;
    SIZE_T pageNums;
    SINGLE_LIST_ENTRY ValidAddressEntry;
}VAL, * PVAL;

typedef struct _ResultSavedList
{
    ULONG times;
    ULONG_PTR targetAddress;
    SIZE_T targetAddressBufferLen;
    ULONG_PTR thisNodePageBeginAddress;
    ULONG_PTR thisNodePageEndAddres;
    ULONG protect;
    PUCHAR buffer;
    LIST_ENTRY ResultAddressEntry;
}RSL, * PRSL, ** PPRSL;

typedef struct _SearchInfo
{
    ULONG isFirstScan;
    VALUE_TYPE valueType;
    SCAN_TYPE scanType;
    UNION_MEMBER_TYPE memberType;
    union
    {
        struct _precise
        {
            PVOID ptr2Value;
            SIZE_T valueLen;
        }precise;
        struct _region
        {
            PVOID ptr2HigherBound;
            PVOID ptr2LowerBound;
            SIZE_T valueLen;
        }region;
        struct _pattern
        {
            PUCHAR ptr2Pattern;
            SIZE_T patternLen;
        }pattern;
    }u;
}SI, * PSI;

VOID getRegionGapAndPages(
    IN_OUT PVAL headVAL
);
VOID buildValidAddressSingleList(
    IN ULONG64 pid,
    OUT PVAL* headVAL,
    IN ULONG_PTR addressMaxLimit
); 
VOID searchTargetBySearchInfo(
    IN PSI si,
    IN ULONG64 pid,
    IN PVAL headVAL,
    OUT PRSL* headRSL
);
VOID checkSI(
    IN PSI si
);
VOID freeSI(
    IN PSI* si
);
BOOLEAN checkAllRSLAddressLenValid(
    IN PRSL headRSL
);
VOID printListVAL(
    IN PVAL headVAL
);
VOID printListRSL(
    IN_OPT ULONG64 pid,
    IN PRSL* headRSL
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
