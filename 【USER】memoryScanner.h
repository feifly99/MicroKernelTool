#ifndef __USER_MODE_CODE__
#define __USER_MODE_CODE__

#include "BaseHeader.h"

typedef enum _valueType
{
    TYPE_BYTE = 0xA1,
    TYPE_WORD = 0xA2,
    TYPE_DWORD = 0xA3,
    TYPE_QWORD = 0xA4,
    TYPE_PATTERN = 0xA5,
    TYPE_FLOAT = 0xA6,
    TYPE_DOUBLE = 0xA7,
    TYPE_NOT_FLOATING = 0xA8
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

typedef enum _UnionMemberRegion
{
    //标记枚举类型实际选取的结构.
    //三个枚举值对应三个结构，其目的在于方便地内核化用户层指针.
    UNION_MEMBER_PRECISE = 1,
    UNION_MEMBER_REGION = 2,
    UNION_MEMBER_PATTERN = 3
}UNION_MEMBER_TYPE;

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

VOID memoryScannerBeginStub(
    IN HANDLE* hDevice
);

VOID memoryScannerReleaseStub(
    VOID
);

VOID enterScanLoop(
    HANDLE pid
);

#endif