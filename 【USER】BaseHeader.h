#ifndef __BASE_HEADER__
#define __BASE_HEADER__

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#pragma warning(disable: 6011)

#define DIRECT_WRITE_TO 

typedef struct _UNICODE_STRING 
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

#define RTL_CONSTANT_STRING(s) \
{ \
    sizeof( s ) - sizeof( (s)[0] ), \
    sizeof( s ) - sizeof( (s)[0] ) + sizeof(WCHAR), \
    s \
}

#define __PLACE_HOLDER__

#define log(sen) printf("%s\n", (CONST CHAR*)#sen);

#define ____$_PREPARE_SEARCH_PROCEDURE_$____				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_ENTER_SEARCH_PROCEDURE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_STOP_SEARCH_PROCEDURE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8003, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_MODULE_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_THREAD_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8005, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_WRITE_PROCESS_MEMORY_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_PROCESS_HIDEN_PROCEDURE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8007, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_PROCESS_PRETENT_PROCEDURE_$____				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_UNLOAD_DRIVER_PREPARE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8009, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_GET_PROCESS_HANDLE_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_CLOSE_PROCESS_HANDLE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_DLL_KERNELMODE_INJECTION_$____                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_READ_PROCESS_MEMORY_$____                     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_PROCESS_RESTORE_PROCEDURE_$____               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_REBUILD_DEBUG_SYSTEM_$____                    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_RESTORE_DEBUG_SYSTEM_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8010, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif