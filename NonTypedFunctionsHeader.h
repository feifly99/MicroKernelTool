#ifndef __NONTYPED_FUNCTION_HEADER__
#define __NONTYPED_FUNCTION_HEADER__

#include "DriverBaseHeader.h"

#define REG_NUM 20

typedef struct dllInjectionInfo
{
    HANDLE pidWannaInject;
    PUNICODE_STRING dllFullPath;
}DLL_INJECT_INFORMATION, * PDLL_INJECT_INFORMATION;

VOID kernelSleep(
    LONG milisecond
);
ULONG64 getCR3SaferByPID(
    IN ULONG64 pid
);
NTSTATUS readPhysicalAddress(
    IN PVOID physicalAddress,
    IN PVOID receivedBuffer,
    IN SIZE_T readSize,
    IN_OPT SIZE_T* bytesTransferred
);
ULONG_PTR getPhysicalAddressByCR3AndVirtualAddress(
    IN ULONG64 cr3,
    IN ULONG_PTR VirtualAddress
);
VOID writePhysicalMemory(
    IN ULONG_PTR physicalAddress,
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
ULONG_PTR getDllInLoadAddress(
    IN HANDLE pid,
    IN PUNICODE_STRING dllName
);
VOID displayDllExportFunctionTable(
    IN HANDLE pid,
    IN PVOID dllBaseInLoad
);
VOID dllInjectionByRemoteThread(
    HANDLE pid,
    PUNICODE_STRING dllFullPath
);
ULONG_PTR getDllExportFunctionAddressByName(
    IN HANDLE pid,
    IN PVOID dllBaseInLoad,
    IN PUCHAR funcName
);
ULONG_PTR getDllExportFunctionAddressByNameKernelMode(
    IN PVOID dllBaseInLoad,
    IN PUCHAR funcName
);
ULONG_PTR getDllExportFunctionAddressByNameKernelMode(
    IN PVOID dllBaseInLoad,
    IN PUCHAR funcName
);
UCHAR readByte(
    IN HANDLE pid,
    IN PVOID address
);
VOID readProcessMemory(
    IN ULONG64 pid,
    IN PVOID targetAddress,
    IN SIZE_T readLength,
    IN PVOID* receivedBuffer
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
ULONG_PTR getIdtEntry(
    VOID
);
#endif
