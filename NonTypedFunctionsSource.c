#include "NonTypedFunctionsHeader.h"

extern ULONG64 getSSDTFunctionAddressByIndex(
    IN ULONG64 index
);

#pragma warning(disable: 6387)
#pragma warning(disable: 4702)
#pragma warning(disable: 6011)

VOID kernelSleep(LONG milisecond)
{
    //输入必须为LONG而不是ULONG.
    //因为有无符号数互相运算，结果隐式转换为无符号数.
    //注意Quard成员是LONGLONG而非ULONG64.
    LARGE_INTEGER t = { 0 };
    t.QuadPart = -10000 * milisecond;
    KeDelayExecutionThread(KernelMode, TRUE, &t);
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
ULONG_PTR getPhysicalAddressByCR3AndVirtualAddress(
    IN ULONG64 cr3,
    IN ULONG_PTR VirtualAddress
)
{
    cr3 = (cr3 >> 12) << 12;
    ULONG_PTR ultimatePhysicalAddress = 0;
    ULONG_PTR ultimatePhysicalAddressPageHeader = 0;
    ULONG_PTR VPO = (VirtualAddress << 52) >> 52;
    ULONG_PTR PFN4 = ((VirtualAddress << 43) >> 43) >> 12;
    ULONG_PTR PFN3 = ((VirtualAddress << 34) >> 34) >> 21;
    ULONG_PTR PFN2 = ((VirtualAddress << 25) >> 25) >> 30;
    ULONG_PTR PFN1 = ((VirtualAddress << 16) >> 16) >> 39;
    SIZE_T ret = 0;
    ULONG_PTR a = 0, b = 0, c = 0;
    readPhysicalAddress((PVOID)(cr3 + 8 * PFN1), &a, sizeof(ULONG_PTR), &ret);
    if (ret == 0) return 0;
    a = (((a << 24) >> 24) >> 12) << 12;
    readPhysicalAddress((PVOID)(a + 8 * PFN2), &b, sizeof(ULONG_PTR), &ret);
    if (ret == 0) return 0;
    b = (((b << 24) >> 24) >> 12) << 12;
    readPhysicalAddress((PVOID)(b + 8 * PFN3), &c, sizeof(ULONG_PTR), &ret);
    if (ret == 0) return 0;
    c = (((c << 24) >> 24) >> 12) << 12;
    readPhysicalAddress((PVOID)(c + 8 * PFN4), &ultimatePhysicalAddressPageHeader, sizeof(ULONG_PTR), &ret);
    if (ret == 0) return 0;
    ultimatePhysicalAddressPageHeader = (((ultimatePhysicalAddressPageHeader << 24) >> 24) >> 12) << 12;
    ultimatePhysicalAddress = ultimatePhysicalAddressPageHeader + VPO;
    return ultimatePhysicalAddress;
}
VOID writePhysicalMemory(
    IN ULONG_PTR physicalAddress,
    IN PUCHAR writeBuffer,
    IN SIZE_T writeLenLessThan0x1000
)
{
    PHYSICAL_ADDRESS p_address = { 0 };
    p_address.QuadPart = (LONG64)physicalAddress;
    PVOID kernelAddressMappedByPhysical = MmMapIoSpace(p_address, 0x1000, MmNonCachedUnordered);
    CR0breakOperation(RtlCopyMemory(kernelAddressMappedByPhysical, writeBuffer, writeLenLessThan0x1000););
    MmUnmapIoSpace(kernelAddressMappedByPhysical, 0x1000);
    return;
}
VOID displayAllIDTFunctionAddress(

)
{
    ULONG_PTR x = 0;
    __asm__getIDT(&x);
    ULONG_PTR base = (0xFFFFULL << 48) + (x >> 16);
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
    ULONG_PTR pebAddress = (ULONG_PTR)pe + 0x550;
    ULONG_PTR peb = *(ULONG_PTR*)pebAddress;
    ULONG_PTR pldAddress = peb + 0x18;
    ULONG_PTR pld = *(ULONG_PTR*)pldAddress;
    ULONG_PTR InLoadOrderModuleListAddress = (ULONG_PTR)pld + 0x10;
    PLIST_ENTRY initialEntryAddress = (PLIST_ENTRY)InLoadOrderModuleListAddress;
    PLIST_ENTRY temp = initialEntryAddress;
    while ((ULONG_PTR)temp != (ULONG_PTR)initialEntryAddress->Blink)
    {
        DbgPrint("DllBase: %p \t DllName: %wZ", *(HANDLE*)((ULONG_PTR)temp->Flink + 0x30), (PUNICODE_STRING)((ULONG_PTR)temp->Flink + 0x58));
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
    ULONG_PTR cidAddress = 0x0;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    ULONG_PTR initialEntryAddress = (ULONG_PTR)pe + 0x5E0;
    PLIST_ENTRY firstThreadListEntryAddress = ((PLIST_ENTRY)((ULONG_PTR)pe + 0x5E0))->Flink;
    while ((ULONG_PTR)firstThreadListEntryAddress != (ULONG_PTR)(((PLIST_ENTRY)initialEntryAddress)))
    {
        cidAddress = (ULONG_PTR)firstThreadListEntryAddress - 0x4E8 + 0x478;
        DbgPrint("threadID: %p, threadStartAddress: 0x%p", ((PCLIENT_ID)cidAddress)->UniqueThread, *(PVOID*)((ULONG_PTR)firstThreadListEntryAddress - 0x4E8 + 0x450));
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
    ULONG_PTR driverSectionAddress = (ULONG_PTR)driverObject + 0x28;
    ULONG_PTR driverSection = *(ULONG_PTR*)driverSectionAddress;
    ULONG_PTR driverModuleListHeadAddress = (ULONG_PTR)((PLIST_ENTRY)driverSection)->Flink;
    ULONG_PTR temp = (ULONG_PTR)(((PLIST_ENTRY)driverModuleListHeadAddress)->Flink);
    while (temp != driverModuleListHeadAddress)
    {
        DbgPrint("ModuleName: %wZ\tModuleBaseAddress: 0x%p\t", (PUNICODE_STRING)(temp + 0x58), *(PVOID*)(temp + 0x30));
        temp = (ULONG_PTR)(((PLIST_ENTRY)temp)->Flink);
    }
    //DbgPrint("DriverBaseName: %wZ, DriverDllBase: 0x%p, DriverDllEntryPoint: 0x%p", (PUNICODE_STRING)(temp + 0x48),(PVOID)(temp + 0x30),(PVOID)(temp + 0x38));
    //一定要加上ULONG_PTR转换，不然就按sizeof(PLIST_ENTRY)寻址去了！以后地址参与运算一律PUCHAR或者ULONG_PTR.
}

ULONG64 getPIDByProcessName(
    IN PUCHAR name
)
{
    ULONG_PTR pe = (ULONG_PTR)IoGetCurrentProcess();
    ULONG_PTR head = pe;
    ULONG_PTR listEntryOffset = 0x448;
    ULONG_PTR uniqueProcessIdOffset = 0x440;
    ULONG_PTR imageFileNameOffset = 0x5A8;
    SIZE_T maxHoldenLength = 15;
    pe = (ULONG_PTR)(((PLIST_ENTRY)(pe + listEntryOffset))->Flink) - listEntryOffset;
    while (pe != head)
    {
        if (strncmp((PVOID)(pe + imageFileNameOffset), (PVOID)name, min(strlen((CONST CHAR*)name), maxHoldenLength) - 1) != 0)
        {
            //imageFileName如果字符个数大于等于15，那么最后一位一定是'\0'.
            //所以比较时，如果输入字符串长度大于等于15，那么要比较前14个字节就行.
            pe = (ULONG_PTR)(((PLIST_ENTRY)(pe + listEntryOffset))->Flink) - listEntryOffset;
        }
        else
        {
            break;
        }
    }
    return *(ULONG_PTR*)(pe + uniqueProcessIdOffset);
}
ULONG_PTR getDllInLoadAddress(
    IN HANDLE pid,
    IN PUNICODE_STRING dllName
)
{
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KAPC_STATE apc = { 0 };
    KeStackAttachProcess(pe, &apc);
    ULONG_PTR pebAddress = (ULONG_PTR)pe + 0x550;
    ULONG_PTR peb = *(ULONG_PTR*)pebAddress;
    ULONG_PTR pldAddress = peb + 0x18;
    ULONG_PTR pld = *(ULONG_PTR*)pldAddress;
    ULONG_PTR InLoadOrderModuleListAddress = (ULONG_PTR)pld + 0x10;
    PLIST_ENTRY initialEntryAddress = (PLIST_ENTRY)InLoadOrderModuleListAddress;
    PLIST_ENTRY temp = initialEntryAddress;
    ULONG_PTR ret = 0x0;
    while ((UL64)temp != (ULONG_PTR)initialEntryAddress->Blink)
    {
        if(RtlCompareUnicodeString(dllName, (PUNICODE_STRING)((ULONG_PTR)temp->Flink + 0x58), TRUE) == 0)
        {
            ret =  *(ULONG_PTR*)((ULONG_PTR)temp->Flink + 0x30);
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
ULONG_PTR getDllExportFunctionAddressByName(
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
        if (strncmp((CONST CHAR*)funcName, (CONST CHAR*)__asm__getFuncNameByIndex_Via_DllBase(dllBaseInLoad, j), min(strlen((CONST CHAR*)funcName), strlen((CONST CHAR*)__asm__getFuncNameByIndex_Via_DllBase(dllBaseInLoad, j))) - 1) == 0)
        {
            ret = (ULONG64)__asm__getFuncAddressByIndex_Via_DllBase(dllBaseInLoad, diff, j);
            break;
        }
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return ret;
}
ULONG_PTR getDllExportFunctionAddressByNameKernelMode(
    IN PVOID dllBaseInLoad,
    IN PUCHAR funcName
)
{
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
        if (strncmp((CONST CHAR*)funcName, (CONST CHAR*)__asm__getFuncNameByIndex_Via_DllBase(dllBaseInLoad, j), min(strlen((CONST CHAR*)funcName), strlen((CONST CHAR*)__asm__getFuncNameByIndex_Via_DllBase(dllBaseInLoad, j))) - 1) == 0)
        {
            ret = (ULONG64)__asm__getFuncAddressByIndex_Via_DllBase(dllBaseInLoad, diff, j);
            break;
        }
    }
    return ret;
}
VOID dllInjectionByRemoteThread(
    HANDLE pid,
    PUNICODE_STRING dllFullPath
)
{
    UNICODE_STRING ntdll = RTL_CONSTANT_STRING(L"ntdll.dll");
    ULONG_PTR LdrLoadDll = (ULONG_PTR)getDllExportFunctionAddressByName((HANDLE)pid, (PVOID)getDllInLoadAddress((HANDLE)pid, &ntdll), (PUCHAR)"LdrLoadDll");
    DbgPrint("[LdrLoadDll地址: 0x%p]", (PVOID)LdrLoadDll);

    ULONG_PTR NtCreateThreadEx = (ULONG_PTR)getSSDTFunctionAddressByIndex(0x00C2); //0xC7 as Windows 11 23H2
    DbgPrint("[NtCreateThreadEx地址: 0x%p]", (PVOID)NtCreateThreadEx);

    ULONG_PTR NtResumeThread = (ULONG_PTR)getSSDTFunctionAddressByIndex(0x0052); //0x52
    DbgPrint("[NtResumeThread地址: 0x%p]", (PVOID)NtResumeThread);

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
    //READWRITE的血泪史.
    ZwAllocateVirtualMemory(processHandle, &unicodeStringUserMem, 0, &unicodeStringSize, MEM_COMMIT, PAGE_READWRITE); 
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
        0x48, 0x83, 0xC4, 0x48,                                     // add rsp, 48h
        0x31, 0xC0,                                                 // xor rax, rax
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
        0x1, //THREAD_CREATE_FLAGS_SUSPENDED.
        0,
        0,
        0,
        NULL
    );
    if (NT_SUCCESS(st))
    {
        DbgPrint("成功.");
    }

    LONG BasePriority = (LONG)LOW_REALTIME_PRIORITY - 1;

    if (BasePriority == 15) 
    {
        BasePriority = ((HIGH_PRIORITY + 1) / 2);
    }
    if (BasePriority == -15) 
    {
        BasePriority = -((HIGH_PRIORITY + 1) / 2);
    }

    st = ZwSetInformationThread(
        threadHandle,
        ThreadBasePriority,
        &BasePriority,
        sizeof(BasePriority)
    );
    DbgPrint("ZwSetInformationThread %lX", st);

    kernelSleep(2000);

    ((NTSTATUS (*)(
        HANDLE ThreadHandle,
        PULONG PreviousSuspendCount
        ))NtResumeThread)(
        threadHandle, 
        NULL
    );

    LARGE_INTEGER time = { 0 };
    time.QuadPart = -10000 * 60000;
    //多线程调试、堆栈分析、汇编代码阅读、断点不命中、双机调试无法复现、未等待线程结束、双
    //调试器调试（VS+WINDBG）、用户层复现；
    //先在用户层复现，再在驱动层分析，最后解决。
    DbgPrint("Wa: %lX", ZwWaitForSingleObject(threadHandle, TRUE, &time));

    kernelSleep(1000);

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
VOID readProcessMemory(
    IN ULONG64 pid,
    IN PVOID targetAddress,
    IN SIZE_T readLength,
    IN PVOID* receivedBuffer
)
{
    PMDL mdl = NULL;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    mdl = IoAllocateMdl((PVOID)((ULONG_PTR)targetAddress & ~0xFFFull), (readLength + 0xFFFull) & ~0xFFFull, FALSE, FALSE, NULL);
    SIZE_T offset = (ULONG_PTR)targetAddress & 0xFFFull;
    __try
    {
        MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
        PVOID krnlMapped = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
        RtlCopyMemory(*receivedBuffer, (PVOID)((ULONG_PTR)krnlMapped + offset), readLength);
        MmUnlockPages(mdl);
    }
    __except (1)
    {
        log(读取的页面不在物理页！);
    }
    IoFreeMdl(mdl);
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
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
    PVOID ImagePathNameAddress = (PVOID)__asm__getImagePathNameAddress((ULONG_PTR)pe);
    PVOID CommandLineAddress = (PVOID)((ULONG_PTR)ImagePathNameAddress + 0x10);
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
    ULONG_PTR idtValue = 0;
    __asm__getIDT(&idtValue);
    ULONG_PTR front48 = (*(ULONG_PTR*)(((0xffffull) << 48) + ((idtValue >> 16)) + 6)) << 16;
    USHORT behind16 = *(USHORT*)(((0xffffull) << 48) + ((idtValue >> 16)));
    ULONG_PTR retAddressValue = front48 + behind16;
    return (ULONG_PTR)retAddressValue;
}
