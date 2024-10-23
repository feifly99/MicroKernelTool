#ifndef __NONTYPED_FUNCTION_HEADER__
#define __NONTYPED_FUNCTION_HEADER__

#include "DriverBaseHeader.h"

#define REG_NUM 20

VOID DbgPrintF(
    IN float* floatNumPointer,
    OUT_OPT INT* _integer,
    OUT_OPT ULONG64* _fraction
);
VOID DbgPrintD(
    IN double* doubleNumPointer,
    OUT_OPT INT* _integer,
    OUT_OPT ULONG64* _fraction
);
NTSTATUS readPhysicalAddress(
    IN PVOID physicalAddress,
    IN PVOID receivedBuffer,
    IN SIZE_T readSize,
    IN_OPT SIZE_T* bytesTransferred
);
ULONG64 getPhysicalAddressByCR3AndVirtualAddress(
    IN ULONG64 cr3,
    IN ULONG64 VirtualAddress
);
VOID writePhysicalMemory(
    IN ULONG64 physicalAddress,
    IN PUCHAR writeBuffer,
    IN SIZE_T writeLenLessThan0x1000
);
VOID displayAllIDTFunctionAddress(

);
VOID readAllRegistors(
    ULONG64 pid
);
VOID change64ValueBit(
    ULONG64* target64ValuePointer,
    SIZE_T bitLoc,
    UCHAR targetBinaryBitValue
);
UCHAR get64ValueBit(
    ULONG64 target64Value,
    SIZE_T bitLoc
);
VOID displayAllModuleInfomationByProcessId(
    IN ULONG64 pid
);
VOID displayKernelModules(
    PDRIVER_OBJECT driverObject
);
VOID displayAllThreadInfomationByProcessId(
    IN ULONG64 pid
);

ULONG64 getPIDByProcessName(
    IN PUCHAR name
);
ULONG64 getDllInLoadAddress(
    IN HANDLE pid,
    IN PUNICODE_STRING dllName
);
VOID displayDllExportFunctionTable(
    IN HANDLE pid,
    IN PVOID dllBaseInLoad
);
ULONG64 getDllExportFunctionAddressByName(
    IN HANDLE pid,
    IN PVOID dllBaseInLoad,
    IN PUCHAR funcName
);
UCHAR readByte(
    IN HANDLE pid,
    IN PVOID address
);
VOID writeProcessMemory(
    IN ULONG64 pid,
    IN PVOID targetAddress,
    IN PVOID pointerToContent,
    IN SIZE_T size
);

VOID hideThisDriver(
    IN PDRIVER_OBJECT driverObject
);
VOID restoreThisDriver(
    IN PDRIVER_OBJECT driverObject
);

VOID readImagePathNameAndCommandLine(
    IN HANDLE pid
);
#endif
