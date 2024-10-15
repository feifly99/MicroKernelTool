#include "NonTypedFunctionsHeader.h"

#pragma warning(disable:6387)
#pragma warning(disable:4702)

VOID DbgPrintF(
    IN float* floatNumPointer, 
    OUT_OPT INT* _integer,
    OUT_OPT ULONG64* _fraction
)
{
    INT integerPart = 0;
    ULONG64 fractionalPart = 0;
    UINT f = *(UINT*)floatNumPointer;
    UINT sign = (f >> 31) & 1;
    UINT exponent = (f >> 23) & 0xFF;
    UINT mantissa = f & 0x7FFFFF;
    INT exp = exponent - 127;
    float value = (float)0.0;
    float fractionalValue = (float)0.0;
    if (exponent == 0)
    {
        value = (float)(mantissa) / (1 << 23);
    }
    else
    {
        value = 1.0f + (float)(mantissa) / (1 << 23);
    }
    value = value * (float)(1 << exp);
    if (sign)
    {
        value = -value;
    }
    integerPart = (INT)value;
    if (value < 0)
    {
        value = -value;
    }
    fractionalValue = value - (float)integerPart;
    fractionalPart = (ULONG64)(fractionalValue * 100000000);
    DbgPrint("%d.%llu\n", integerPart, fractionalPart);
    if (_integer != NULL)
    {
        *_integer = integerPart;
    }
    if (_fraction != NULL)
    {
        *_fraction = fractionalPart;
    }
    return;
}
VOID DbgPrintD(
    IN double* doubleNumPointer,
    OUT_OPT INT* _integer,
    OUT_OPT ULONG64* _fraction
)
{
    INT integerPart = 0;
    ULONG64 fractionalPart = 0;
    UINT64 bitRepresentation = *(UINT64*)doubleNumPointer; 
    UINT sign = (bitRepresentation >> 63) & 1;
    UINT exponent = (bitRepresentation >> 52) & 0x7FF;
    UINT64 mantissa = bitRepresentation & 0xFFFFFFFFFFFFF;
    int exp = 0;
    double value = 0.0;
    double fractionalValue = 0.0;
    if (exponent == 0)
    {
        value = (double)(mantissa) / (1ULL << 52); 
    }
    else
    {
        value = 1.0 + (double)(mantissa) / (1ULL << 52);
    }
    exp = (int)exponent - 1023; 
    value = value * (double)(1ULL << exp); 
    if (sign)
    {
        value = -value;
    }
    integerPart = (INT)value;
    if (value < 0)
    {
        value = -value; 
    }
    fractionalValue = value - (double)integerPart;
    fractionalPart = (ULONG64)(fractionalValue * 100000000);
    DbgPrint("%d.%llu\n", integerPart, fractionalPart); 
    if (_integer != NULL)
    {
        *_integer = integerPart; 
    }
    if (_fraction != NULL)
    {
        *_fraction = fractionalPart; 
    }
    return;
}
VOID displayAllModuleInfomationByProcessId(
    IN ULONG64 pid
)
{
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KAPC_STATE apc = { 0 };
    KeStackAttachProcess(pe, &apc);
    ULONG64 pebAddress = (ULONG64)pe + 0x550;
    ULONG64 peb = *(ULONG64*)pebAddress;
    ULONG64 pldAddress = peb + 0x18;
    ULONG64 pld = *(ULONG64*)pldAddress;
    ULONG64 InLoadOrderModuleListAddress = (ULONG64)pld + 0x10;
    PLIST_ENTRY initialEntryAddress = (PLIST_ENTRY)InLoadOrderModuleListAddress;
    PLIST_ENTRY temp = initialEntryAddress;
    while ((UL64)temp != (ULONG64)initialEntryAddress->Blink)
    {
        DbgPrint("DllBase: %p \t DllName: %wZ", *(HANDLE*)((ULONG64)temp->Flink + 0x30), (PUNICODE_STRING)((ULONG64)temp->Flink + 0x58));
        temp = temp->Flink;
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
VOID displayAllThreadInfomationByProcessId(
    IN ULONG64 pid
)
{
    PEPROCESS pe = NULL;
    ULONG64 cidAddress = 0x0;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    ULONG64 initialEntryAddress = (UL64)pe + 0x5E0;
    PLIST_ENTRY firstThreadListEntryAddress = ((PLIST_ENTRY)((UL64)pe + 0x5E0))->Flink;
    while ((UL64)firstThreadListEntryAddress != (UL64)(((PLIST_ENTRY)initialEntryAddress)))
    {
        cidAddress = (UL64)firstThreadListEntryAddress - 0x4E8 + 0x478;
        DbgPrint("threadID: %p, threadStartAddress: 0x%p", ((PCLIENT_ID)cidAddress)->UniqueThread, *(PVOID*)((UL64)firstThreadListEntryAddress - 0x4E8 + 0x450));
        firstThreadListEntryAddress = firstThreadListEntryAddress->Flink;
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
}
VOID displayKernelModules(
    PDRIVER_OBJECT driverObject
)
{
    /*                                            DriverLinkListStruct
    *       ---------------------------------------------------------------------------------------------------
    *       |                                      [InLoadOrderLinks]                                         |
    *       |      <NullStructure>        <WholeStructure>                            <WholeStructure>        |
            |       HeadListEntry           ntoskrnl.exe                                MyDriver1.sys         |
            |------->  Flink       ---->       Flink        ---->       ...     ---->       Flink       ------|
                         |                       |                       |                    |
                         |-----------            |------------           |--------            |----------------
                                    |                        |                   |                            |
            |--------  Blink        |--       Blink          |--       ...       |---       Blink             |
    *       |                                                                                                 |
    *       |                                                                                                 |
    *       |-------------------------------------------------------------------------------------------------|
    */
    //    Section->LDR->InLoadOrderLinks [_LIST_ENTRY]，连接的是下一个驱动对象的LDR，也就是Section所指向的结构
    // WholeStruct表示所在域是一个完整的LDR结构。相对应地，NullStruct表示所在域只有一个LIST_ENTRY，没有有效结构，是链表头
    //              最后一个加载的驱动位于双链表的结尾部分，结尾部分的驱动的下一个是链表头，不存储有效信息
    ULONG64 driverSectionAddress = (ULONG64)driverObject + 0x28;
    ULONG64 driverSection = *(ULONG64*)driverSectionAddress;
    ULONG64 driverModuleListHeadAddress = (ULONG64)((PLIST_ENTRY)driverSection)->Flink;
    ULONG64 temp = (ULONG64)(((PLIST_ENTRY)driverModuleListHeadAddress)->Flink);
    while (temp != driverModuleListHeadAddress)
    {
        DbgPrint("ModuleName: %wZ\tModuleBaseAddress: 0x%p\t", (PUNICODE_STRING)(temp + 0x58), *(PVOID*)(temp + 0x30));
        temp = (ULONG64)(((PLIST_ENTRY)temp)->Flink);
    }
    //DbgPrint("DriverBaseName: %wZ, DriverDllBase: 0x%p, DriverDllEntryPoint: 0x%p", (PUNICODE_STRING)(temp + 0x48),(PVOID)(temp + 0x30),(PVOID)(temp + 0x38));
    //一定要加上ULONG64转换，不然就按sizeof(PLIST_ENTRY)寻址去了！以后地址参与运算一律PUCHAR或者ULONG64.
}

ULONG64 getPIDByProcessName(
    IN PUCHAR name
)
{
    ULONG64 pe = (ULONG64)IoGetCurrentProcess();
    ULONG64 head = pe;
    ULONG64 listEntryOffset = 0x448;
    ULONG64 uniqueProcessIdOffset = 0x440;
    ULONG64 imageFileNameOffset = 0x5A8;
    SIZE_T maxHoldenLength = 15;
    pe = (ULONG64)(((PLIST_ENTRY)(pe + listEntryOffset))->Flink) - listEntryOffset;
    while (pe != head)
    {
        if (strncmp((PVOID)(pe + imageFileNameOffset), (PVOID)name, min(strlen((CONST CHAR*)name), maxHoldenLength) - 1) != 0)
        {
            //imageFileName如果字符个数大于等于15，那么最后一位一定是\0.
            //所以比较时，如果输入字符串长度大于等于15，那么要比较前14个字节就行.
            pe = (ULONG64)(((PLIST_ENTRY)(pe + listEntryOffset))->Flink) - listEntryOffset;
        }
        else
        {
            break;
        }
    }
    return *(ULONG64*)(pe + uniqueProcessIdOffset);
}
ULONG64 getDllInLoadAddress(
    IN HANDLE pid,
    IN PUNICODE_STRING dllName
)
{
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KAPC_STATE apc = { 0 };
    KeStackAttachProcess(pe, &apc);
    ULONG64 pebAddress = (ULONG64)pe + 0x550;
    ULONG64 peb = *(ULONG64*)pebAddress;
    ULONG64 pldAddress = peb + 0x18;
    ULONG64 pld = *(ULONG64*)pldAddress;
    ULONG64 InLoadOrderModuleListAddress = (ULONG64)pld + 0x10;
    PLIST_ENTRY initialEntryAddress = (PLIST_ENTRY)InLoadOrderModuleListAddress;
    PLIST_ENTRY temp = initialEntryAddress;
    ULONG64 ret = 0x0;
    while ((UL64)temp != (ULONG64)initialEntryAddress->Blink)
    {
        if(RtlCompareUnicodeString(dllName, (PUNICODE_STRING)((ULONG64)temp->Flink + 0x58), TRUE) == 0)
        {
            ret =  *(ULONG64*)((ULONG64)temp->Flink + 0x30);
            break;
        }
        temp = temp->Flink;
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return ret;
}
VOID displayDllExportFunctionTable(
    IN HANDLE pid,
    IN PVOID dllBaseInLoad
)
{
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KAPC_STATE apc = { 0 };
    KeStackAttachProcess(pe, &apc);
    SIZE_T sizeTOTAL = __asm__getFuncNumsExportedTotal_Via_DllBase(dllBaseInLoad);
    SIZE_T sizeNAME = __asm__getFuncNumsExportedByName_Via_DllBase(dllBaseInLoad);
    SIZE_T diff = 0;
    if (sizeTOTAL >= sizeNAME)
    {
        diff = sizeTOTAL - sizeNAME;
    }
    for (SIZE_T j = 0; j < sizeNAME; j++)
    {
        DbgPrint("Func Name: %s, Func Address: 0x%p", __asm__getFuncNameByIndex_Via_DllBase(dllBaseInLoad, j), __asm__getFuncAddressByIndex_Via_DllBase(dllBaseInLoad, diff, j));
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
ULONG64 getDllExportFunctionAddressByName(
    IN HANDLE pid,
    IN PVOID dllBaseInLoad,
    IN PUCHAR funcName
)
{
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KAPC_STATE apc = { 0 };
    KeStackAttachProcess(pe, &apc);
    SIZE_T sizeTOTAL = __asm__getFuncNumsExportedTotal_Via_DllBase(dllBaseInLoad);
    SIZE_T sizeNAME = __asm__getFuncNumsExportedByName_Via_DllBase(dllBaseInLoad);
    SIZE_T diff = 0;
    ULONG64 ret = 0x0;
    if (sizeTOTAL >= sizeNAME)
    {
        diff = sizeTOTAL - sizeNAME;
    }
    for (SIZE_T j = 0; j < sizeNAME; j++)
    {
        if (strncmp((CONST CHAR*)funcName,(CONST CHAR*)__asm__getFuncNameByIndex_Via_DllBase(dllBaseInLoad, j), min(strlen((CONST CHAR*)funcName),strlen((CONST CHAR*)__asm__getFuncNameByIndex_Via_DllBase(dllBaseInLoad, j))) - 1) == 0)
        {
            ret = (ULONG64)__asm__getFuncAddressByIndex_Via_DllBase(dllBaseInLoad, diff, j);
            break;
        }
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return ret;
}
UCHAR readByte(
    IN HANDLE pid, 
    IN PVOID address
)
{
    UCHAR targetByte = 0x00;
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId(pid, &pe);
    KAPC_STATE apc = { 0 };
    KeStackAttachProcess(pe, &apc);
    memcpy(&targetByte, address, 1);
    DbgPrint("%hhx", targetByte);
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return targetByte;
}
VOID writeProcessMemory(
    IN ULONG64 pid,
    IN PVOID targetAddress,
    IN PVOID pointerToContent,
    IN SIZE_T size
)
{
    ULONG64 oldCR0 = 0x0;
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KAPC_STATE apc = { 0 };
    KeStackAttachProcess(pe, &apc);
    __asm__WRbreak(&oldCR0);
    RtlCopyMemory(targetAddress, pointerToContent, size);
    __asm__WRrestore(oldCR0);
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
VOID hideThisDriver(
    IN PDRIVER_OBJECT driverObject
)
{
    ((PLIST_ENTRY)(driverObject->DriverSection))->Blink->Flink = ((PLIST_ENTRY)(driverObject->DriverSection))->Flink;
    ((PLIST_ENTRY)(driverObject->DriverSection))->Flink->Blink = ((PLIST_ENTRY)(driverObject->DriverSection))->Blink;
    return;
}
VOID restoreThisDriver(
    IN PDRIVER_OBJECT driverObject
)
{
    ((PLIST_ENTRY)(driverObject->DriverSection))->Flink->Blink = (PLIST_ENTRY)(driverObject->DriverSection);
    ((PLIST_ENTRY)(driverObject->DriverSection))->Blink->Flink = (PLIST_ENTRY)(driverObject->DriverSection);
    return;
}
VOID readImagePathNameAndCommandLine(
    IN HANDLE pid
)
{
    //如果遇到应该蓝屏但是没蓝屏：看看下没下内核断点KdBreakPoint！！
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId(pid, &pe);
    KAPC_STATE apc = { 0 };
    KeStackAttachProcess(pe, &apc);
    PVOID ImagePathNameAddress = (PVOID)__asm__getImagePathNameAddress((ULONG64)pe);
    PVOID CommandLineAddress = (PVOID)((ULONG64)ImagePathNameAddress + 0x10);
    DbgPrint("ImagePathName: %wZ", (PUNICODE_STRING)ImagePathNameAddress);
    DbgPrint("CommandLine: %wZ", (PUNICODE_STRING)CommandLineAddress);
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
