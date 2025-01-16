#include "NonTypedFunctionsHeader.h"

extern ULONG64 getSSDTFunctionAddressByIndex(
    IN ULONG64 index
);

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
ULONG64 getCR3SaferByPID(
    IN ULONG64 pid
)
{
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    ULONG64 cr3 = *(ULONG64*)((ULONG64)pe + 0x28);
    ObDereferenceObject(pe);
    return cr3;
}
NTSTATUS readPhysicalAddress(
    IN PVOID physicalAddress,
    IN PVOID receivedBuffer,
    IN SIZE_T readSize,
    IN_OPT SIZE_T* bytesTransferred
)
{
    MM_COPY_ADDRESS Read = { 0 };
    Read.PhysicalAddress.QuadPart = (LONG64)physicalAddress;
    if (bytesTransferred == NULL)
    {
        SIZE_T ret = 0;
        return MmCopyMemory(receivedBuffer, Read, readSize, MM_COPY_MEMORY_PHYSICAL, &ret);
    }
    else
    {
        return MmCopyMemory(receivedBuffer, Read, readSize, MM_COPY_MEMORY_PHYSICAL, bytesTransferred);
    }
}
ULONG64 getPhysicalAddressByCR3AndVirtualAddress(
    IN ULONG64 cr3,
    IN ULONG64 VirtualAddress
)
{
    cr3 = (cr3 >> 12) << 12;
    ULONG64 ultimatePhysicalAddress = 0;
    ULONG64 ultimatePhysicalAddressPageHeader = 0;
    ULONG64 VPO = (VirtualAddress << 52) >> 52;
    ULONG64 PFN4 = ((VirtualAddress << 43) >> 43) >> 12;
    ULONG64 PFN3 = ((VirtualAddress << 34) >> 34) >> 21;
    ULONG64 PFN2 = ((VirtualAddress << 25) >> 25) >> 30;
    ULONG64 PFN1 = ((VirtualAddress << 16) >> 16) >> 39;
    SIZE_T ret = 0;
    ULONG64 a = 0, b = 0, c = 0;
    readPhysicalAddress((PVOID)(cr3 + 8 * PFN1), &a, sizeof(ULONG64), &ret);
    if (ret == 0) return 0;
    a = (((a << 24) >> 24) >> 12) << 12;
    readPhysicalAddress((PVOID)(a + 8 * PFN2), &b, sizeof(ULONG64), &ret);
    if (ret == 0) return 0;
    b = (((b << 24) >> 24) >> 12) << 12;
    readPhysicalAddress((PVOID)(b + 8 * PFN3), &c, sizeof(ULONG64), &ret);
    if (ret == 0) return 0;
    c = (((c << 24) >> 24) >> 12) << 12;
    readPhysicalAddress((PVOID)(c + 8 * PFN4), &ultimatePhysicalAddressPageHeader, sizeof(ULONG64), &ret);
    if (ret == 0) return 0;
    ultimatePhysicalAddressPageHeader = (((ultimatePhysicalAddressPageHeader << 24) >> 24) >> 12) << 12;
    ultimatePhysicalAddress = ultimatePhysicalAddressPageHeader + VPO;
    return ultimatePhysicalAddress;
}
VOID writePhysicalMemory(
    IN ULONG64 physicalAddress,
    IN PUCHAR writeBuffer,
    IN SIZE_T writeLenLessThan0x1000
)
{
    PHYSICAL_ADDRESS p_address = { 0 };
    p_address.QuadPart = (LONG64)physicalAddress;
    MEMORY_CACHING_TYPE p_type = MmNonCachedUnordered;
    PVOID kernelAddressMappedByPhysical = MmMapIoSpace(p_address, 0x1000, p_type);
    CR0breakOperation(memcpy(kernelAddressMappedByPhysical, writeBuffer, writeLenLessThan0x1000););
    MmUnmapIoSpace(kernelAddressMappedByPhysical, 0x1000);
    return;
}
VOID displayAllIDTFunctionAddress(

)
{
    ULONG64 x = 0;
    __asm__getIDT(&x);
    ULONG64 base = (0xFFFFULL << 48) + (x >> 16);
    ULONG64 frac1 = 0;
    ULONG64 frac2 = 0;
    for (SIZE_T j = 0; j < 0xFF; j++)
    {
        frac1 = *(ULONG64*)base;
        frac2 = *(ULONG64*)(base + 8);
        DbgPrint("[%zX]: 0x%llX", j, (ULONG64)(frac2 << 32) + (ULONG64)((frac1 >> 48) << 16) + (ULONG64)((frac1 << 48) >> 48));
        base += 0x10;
    }
    return;
}
VOID readAllRegistors(
    ULONG64 pid
)
{
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    ULONG64 REG_ARRAY[REG_NUM] = { 0 };
    __asm__readAllRegistors(REG_ARRAY);
    DbgPrint("rax: %llX", REG_ARRAY[0]);
    DbgPrint("rbx: %llX", REG_ARRAY[1]);
    DbgPrint("rcx: %llX", REG_ARRAY[2]);
    DbgPrint("rdx: %llX", REG_ARRAY[3]);
    DbgPrint("rdi: %llX", REG_ARRAY[4]);
    DbgPrint("rsi: %llX", REG_ARRAY[5]);
    DbgPrint("rbp: %llX", REG_ARRAY[6]);
    DbgPrint("rsp: %llX", REG_ARRAY[7]);
    DbgPrint("r8: %llX",  REG_ARRAY[8]);
    DbgPrint("r9: %llX",  REG_ARRAY[9]);
    DbgPrint("cr0: %llX", REG_ARRAY[10]);
    DbgPrint("cr2: %llX", REG_ARRAY[11]);
    DbgPrint("cr3: %llX", REG_ARRAY[12]);
    DbgPrint("cr4: %llX", REG_ARRAY[13]);
    DbgPrint("dr0: %llX", REG_ARRAY[14]);
    DbgPrint("dr1: %llX", REG_ARRAY[15]);
    DbgPrint("dr2: %llX", REG_ARRAY[16]);
    DbgPrint("dr3: %llX", REG_ARRAY[17]);
    DbgPrint("dr6: %llX", REG_ARRAY[18]);
    DbgPrint("dr7: %llX", REG_ARRAY[19]);
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
}
VOID change64ValueBit(
    ULONG64* target64ValuePointer,
    SIZE_T bitLoc,
    UCHAR targetBinaryBitValue
) 
{
    if (bitLoc >= 64) 
    {
        return; 
    }
    if (targetBinaryBitValue == 1) 
    {
        *target64ValuePointer |= (1ULL << bitLoc);
    }
    else 
    {
        *target64ValuePointer &= ~(1ULL << bitLoc);
    }
}
UCHAR get64ValueBit(
    ULONG64 target64Value,
    SIZE_T bitLoc
)
{
    if (bitLoc >= 64)
    {
        return 0xFF;
    }
    return (UCHAR)((target64Value & (1ULL << bitLoc)) >> bitLoc);
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

VOID dllInjectionByRemoteThread(
    PUCHAR processNameWannaInjectTo,
    PUNICODE_STRING dllFullPath
)
{
    UNREFERENCED_PARAMETER(dllFullPath);

    CONST ULONG64 SYSTEM_PID = 0x4;

    ULONG64 pid = getPIDByProcessName(processNameWannaInjectTo);
    if (pid == SYSTEM_PID)
    {
        DbgPrint("非法PID，已驳回.");
        return ;
    }
    ULONG64 stablePid = getPIDByProcessName((PUCHAR)"explorer.exe");
    if (stablePid == SYSTEM_PID)
    {
        DbgPrint("非法常驻PID，已驳回.");
        return;
    }

    UNICODE_STRING ntdll = RTL_CONSTANT_STRING(L"ntdll.dll");
    ULONG_PTR LdrLoadDll = (ULONG_PTR)getDllExportFunctionAddressByName((HANDLE)stablePid, (PVOID)getDllInLoadAddress((HANDLE)stablePid, &ntdll), (PUCHAR)"LdrLoadDll");
    DbgPrint("[LdrLoadDll地址: 0x%p]", (PVOID)LdrLoadDll);

    ULONG_PTR NtCreateThreadEx = (ULONG_PTR)getSSDTFunctionAddressByIndex(0xC2);
    DbgPrint("[NtCreateThreadEx地址: 0x%p]", (PVOID)NtCreateThreadEx);

    HANDLE processHandle = NULL;
    OBJECT_ATTRIBUTES processObja = { 0 };
    InitializeObjectAttributes(&processObja, NULL, 0, NULL, NULL);
    CLIENT_ID cidInput = { 0 };
    cidInput.UniqueProcess = (HANDLE)pid;
    cidInput.UniqueThread = NULL;
    NtOpenProcess(&processHandle, PROCESS_ALL_ACCESS, &processObja, &cidInput);
    
    PVOID machineCodeUserMem = NULL;
    SIZE_T machineCodeSize = 0x1000;
    ZwAllocateVirtualMemory(processHandle, &machineCodeUserMem, 0, &machineCodeSize, MEM_COMMIT, PAGE_EXECUTE); 

    PVOID unicodeStringUserMem = NULL;
    SIZE_T unicodeStringSize = 0x1000;
    ZwAllocateVirtualMemory(processHandle, &unicodeStringUserMem, 0, &unicodeStringSize, MEM_COMMIT, PAGE_READONLY); 
    ULONG_PTR unicodeStructAddress = ((ULONG_PTR)unicodeStringUserMem + 0x100);
    ULONG_PTR retDllHandleAddress = ((ULONG_PTR)unicodeStringUserMem + 0x300);
    ULONG_PTR retDllHandleInput2LdrLoadDll = ((ULONG_PTR)unicodeStringUserMem + 0x500);

    UCHAR shellCode[] = { //0x48
        0x48, 0x83, 0xEC, 0x48,                                     // sub rsp, 48h
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, <ntdll!LdrLoadDll>
        0x48, 0x31, 0xC9,                                           // xor rcx, rcx
        0x48, 0x31, 0xD2,                                           // xor rdx, rdx
        0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r8, <unicodeString>
        0x49, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r9, <dllRetHandle>
        0xFF, 0xD0,                                                 // call rax
        0x90,                                                       // nop
        0x48, 0x83, 0xC4, 0x48,                                     // add rsp, 48h
        0xC3                                                        // ret                      
    };

    ULONG_PTR LdrLoadDllAddressRelo = (ULONG_PTR)machineCodeUserMem + 6;
    ULONG_PTR dllPathUnicodeStringRelo = (ULONG_PTR)machineCodeUserMem + 22;
    ULONG_PTR dllHandleRetAddressRelo = (ULONG_PTR)machineCodeUserMem + 32;

    ULONG64 oldCR0 = 0x0;
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KAPC_STATE apc = { 0 };
    KeStackAttachProcess(pe, &apc);
    __asm__WRbreak(&oldCR0);

    /*进程内交互开始*/
    //1.写入shellCode于machineCodeUserMem.
    RtlCopyMemory(machineCodeUserMem, shellCode, sizeof(shellCode));
    //2.写入WSTR的DLL完整路径宽字符串D:\\testDll.dll于unicodeStringUserMem.
    RtlCopyMemory(unicodeStringUserMem, dllFullPath->Buffer, dllFullPath->MaximumLength);
    //3.写入UNICODE_STRING的DLL结构作为LdrLoadDll的第三个参数.
    //位于unicodeStringUserMem + 0x100(unicodeStructAddress).
    *(USHORT*)unicodeStructAddress = dllFullPath->Length;
    *(USHORT*)(unicodeStructAddress + 2) = dllFullPath->MaximumLength;
    *(ULONG_PTR*)(unicodeStructAddress + 8) = (ULONG_PTR)unicodeStringUserMem;
    //4.写入dllHandle的返回地址.
    //此地址指向unicodeStringUserMem + 0x300(retDllHandleAddress).
    //此地址位于unicodeStringUserMem + 0x500(retDllHandleInput2LdrLoadDll).
    RtlCopyMemory((PVOID)retDllHandleInput2LdrLoadDll, &retDllHandleAddress, 8);
    //5.重定位LdrLoadDll的call地址rax.
    RtlCopyMemory((PVOID)LdrLoadDllAddressRelo, &LdrLoadDll, 8);
    //6.重定位dllPathUnicodeString的地址r8.
    RtlCopyMemory((PVOID)dllPathUnicodeStringRelo, &unicodeStructAddress, 8);
    //7.重定位dllHandleRetAddress的地址r9.
    RtlCopyMemory((PVOID)dllHandleRetAddressRelo, &retDllHandleInput2LdrLoadDll, 8);
    /*进程内交互结束*/

    __asm__WRrestore(oldCR0);
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);

    DbgPrint("[machineCodeUserMem] -> 0x%p", machineCodeUserMem);
    DbgPrint("[unicodeStringUserMem] -> 0x%p", unicodeStringUserMem);
    DbgPrint("[unicodeStructAddress] -> 0x%p", (PVOID)unicodeStructAddress);
    DbgPrint("[retDllHandleInput2LdrLoadDll] -> 0x%p", (PVOID)retDllHandleInput2LdrLoadDll);

    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES threadObja = { 0 }; InitializeObjectAttributes(&threadObja, NULL, 0, NULL, NULL);

    typedef INT (*PUSER_THREAD_START_ROUTINE)(PVOID param);

    NTSTATUS st = ((NTSTATUS (*)(
        _Out_ PHANDLE ThreadHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
        _In_ HANDLE ProcessHandle,
        _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
        _In_opt_ PVOID Argument,
        _In_ ULONG CreateFlags,
        _In_ SIZE_T ZeroBits,
        _In_ SIZE_T StackSize,
        _In_ SIZE_T MaximumStackSize,
        _In_opt_ PVOID AttributeList
        ))NtCreateThreadEx)(
        &threadHandle,
        THREAD_ALL_ACCESS,
        &threadObja,
        processHandle,
        (PUSER_THREAD_START_ROUTINE)machineCodeUserMem,
        NULL,
        0x4, //THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER.
        0,
        0,
        0,
        NULL
    );
    if (NT_SUCCESS(st))
    {
        DbgPrint("成功.");
    }
    
    //多线程冲突：用户线程还没执行完，驱动线程就把用户线程执行的机器码FREE了，导致失效。
    //而从WINDBG和各类调试器来看，逻辑均没问题，位于机器码的第一个字节断点也能命中。
    //非常难以排查！
    //内核线程必须等待一会直到用户线程执行完成之后，才能释放用户空间虚拟内存！
    LARGE_INTEGER waitTime = { 0 };
    waitTime.QuadPart = -10000 * 2000;
    KeDelayExecutionThread(KernelMode, TRUE, &waitTime);

    SIZE_T freeSizeNeededMustForReleaseType = 0x0;
    ZwFreeVirtualMemory(processHandle, &machineCodeUserMem, &freeSizeNeededMustForReleaseType, MEM_RELEASE);
    ZwFreeVirtualMemory(processHandle, &unicodeStringUserMem, &freeSizeNeededMustForReleaseType, MEM_RELEASE);
    
    ZwClose(threadHandle);
    ZwClose(processHandle);

    return;
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
    DbgPrint("%hhX", targetByte);
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
ULONG_PTR getIdtEntry(
    VOID
)
{
    ULONG64 idtValue = 0;
    __asm__getIDT(&idtValue);
    ULONG64 front48 = (*(ULONG64*)(((0xffffull) << 48) + ((idtValue >> 16)) + 6)) << 16;
    USHORT behind16 = *(USHORT*)(((0xffffull) << 48) + ((idtValue >> 16)));
    ULONG64 retAddressValue = front48 + behind16;
    return (ULONG_PTR)retAddressValue;
}
