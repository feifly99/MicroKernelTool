#ifndef __USER_MODE_CODE__
#define __USER_MODE_CODE__

#include "BaseHeader.h"

#define ____$_INITIZE_PROCESS_ID_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_INITIALIZE_PROCESS_MEMORY_SPACE_$____         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_SEARCH_PROCEDURE_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8003, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_STOP_SEARCH_PROCEDURE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_MODULE_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8005, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_THREAD_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_WRITE_PROCESS_MEMORY_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8007, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_PROCESS_HIDEN_PROCEDURE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_PROCESS_PRETENT_PROCEDURE_$____				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8009, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_UNLOAD_DRIVER_PREPARE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800A, METHOD_BUFFERED, FILE_ANY_ACCESS)

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

PSI initializeSI(
    IN ULONG isFistScan,
    IN VALUE_TYPE valueType,
    IN SCAN_TYPE scanType,
    IN UNION_MEMBER_TYPE memberType,
    IN PVOID ptr2MainInput,
    IN PVOID ptr2SubInput,
    IN SIZE_T patternTypeLengthInput
);

VOID checkSI(
    IN PSI si
);

VOID freeSI(
    IN PSI* si
);

#endif
