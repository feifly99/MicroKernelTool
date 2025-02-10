#include "MemoryScannerHeader.h"

#pragma warning(disable:6387)
#pragma warning(disable:6011)
#pragma warning(disable:4702)

static ULONG visitedTimes = 0;
CONST SIZE_T singlePageSize = 1024;

ULONG64 getCR3SaferByPID(
    IN ULONG64 pid
);

extern ULONG_PTR getPhysicalAddressByCR3AndVirtualAddress(
    IN ULONG64 cr3,
    IN ULONG_PTR VirtualAddress
);

static VOID DbgPrintF(
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
static VOID DbgPrintD(
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
static PVAL createValidAddressNode(
    IN ULONG_PTR begin,
    IN ULONG_PTR end,
    IN ULONG memState,
    IN ULONG memProtectAttributes,
    IN BOOLEAN executeFlag
)
{
    PVAL newNode = (PVAL)ExAllocatePoolWithTag(PagedPool, sizeof(VAL), 'z+aa');
    if (newNode)
    {
        newNode->beginAddress = begin;
        newNode->endAddress = end;
        newNode->memoryState = memState;
        newNode->memoryProtectAttributes = memProtectAttributes;
        newNode->executeFlag = executeFlag;
        newNode->regionGap = 0x0;
        newNode->pageNums = 0x0;
        newNode->ValidAddressEntry.Next = NULL;
    }
    return newNode;
}
VOID getRegionGapAndPages(
    IN_OUT PVAL headVAL
)
{
    PVAL temp = headVAL;
    while (temp->ValidAddressEntry.Next != NULL)
    {
        temp->regionGap = temp->endAddress - temp->beginAddress;
        temp->pageNums = (temp->regionGap) / 0x1000 + 1;
        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    temp->regionGap = temp->endAddress - temp->beginAddress;
    temp->pageNums = (temp->regionGap) / 0x1000 + 1;
    return;
}
VOID buildValidAddressSingleList(
    IN ULONG64 pid,
    OUT PVAL* headVAL,
    IN ULONG_PTR addressMaxLimit
)
{
    PVAL temp = NULL;
    ULONG_PTR currentAddress = 0x0;
    HANDLE processHandle = NULL;
    CLIENT_ID cid = { 0 };
    OBJECT_ATTRIBUTES obja = { 0 };
    cid.UniqueProcess = (HANDLE)pid;
    cid.UniqueThread = NULL;
    InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
    //OPENPROCESS句柄周期，要尽量用最新鲜的.
    ZwOpenProcess(&processHandle, GENERIC_ALL, &obja, &cid);
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    while (currentAddress <= addressMaxLimit)
    {
        if (NT_SUCCESS(ZwQueryVirtualMemory(processHandle, (PVOID)currentAddress, MemoryBasicInformation, &mbi, sizeof(MEMORY_BASIC_INFORMATION), NULL)))
        {
            //注意0x00的PAGE_NO_ALLOCATED.
            if (mbi.Protect != 0x00 && mbi.Protect != PAGE_NOACCESS && mbi.Protect != 0x104 && mbi.Protect != PAGE_GUARD)
            {
                if (*headVAL == NULL)
                {
                    if ((mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) && mbi.State == MEM_COMMIT)
                    {
                        PVAL newNode = createValidAddressNode((ULONG_PTR)mbi.BaseAddress, (ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize - 1, (ULONG)mbi.State, (ULONG)mbi.Protect, TRUE);
                        *headVAL = newNode;
                    }
                    else 
                    {
                        if (mbi.State == MEM_COMMIT)
                        {
                            PVAL newNode = createValidAddressNode((ULONG_PTR)mbi.BaseAddress, (ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize - 1, (ULONG)mbi.State, (ULONG)mbi.Protect, FALSE);
                            *headVAL = newNode;
                        }
                    }
                }
                else
                {
                    temp = *headVAL;
                    while (temp->ValidAddressEntry.Next != NULL)
                    {
                        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
                    }
                    if ((mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY) && mbi.State == MEM_COMMIT)
                    {
                        PVAL newNode = createValidAddressNode((ULONG_PTR)mbi.BaseAddress, (ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize - 1, (ULONG)mbi.State, (ULONG)mbi.Protect, TRUE);
                        temp->ValidAddressEntry.Next = &newNode->ValidAddressEntry;
                    }
                    else
                    {
                        if (mbi.State == MEM_COMMIT)
                        {
                            PVAL newNode = createValidAddressNode((ULONG_PTR)mbi.BaseAddress, (ULONG_PTR)mbi.BaseAddress + (ULONG_PTR)mbi.RegionSize - 1, (ULONG)mbi.State, (ULONG)mbi.Protect, FALSE);
                            temp->ValidAddressEntry.Next = &newNode->ValidAddressEntry;
                        }
                    }
                }
            }
        }
        currentAddress = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    }
    ZwClose(processHandle);
}
static PRSL createResultSavedNode(
    IN ULONG times,
    IN PVOID kernelAddressPointingToTarget,
    IN ULONG_PTR targetAddress,
    IN SIZE_T targetAddressBufferLen,
    IN PVAL headVAL
)
{
    PRSL newNode = (PRSL)ExAllocatePoolWithTag(PagedPool, sizeof(RSL), 'z+aa');
    if (newNode)
    {
        newNode->times = times;
        newNode->targetAddress = targetAddress;
        newNode->targetAddressBufferLen = targetAddressBufferLen;
        newNode->ResultAddressEntry.Flink = NULL;
        newNode->ResultAddressEntry.Blink = NULL;
        newNode->buffer = ExAllocatePoolWithTag(NonPagedPool, newNode->targetAddressBufferLen, 'z+aa');
        RtlCopyMemory(newNode->buffer, kernelAddressPointingToTarget, newNode->targetAddressBufferLen);
        PVAL tempVAL = headVAL;
        while (tempVAL->ValidAddressEntry.Next != NULL)
        {
            if (newNode->targetAddress <= tempVAL->endAddress && newNode->targetAddress >= tempVAL->beginAddress)
            {
                newNode->thisNodePageBeginAddress = tempVAL->beginAddress;
                newNode->thisNodePageEndAddres = tempVAL->endAddress;
                newNode->protect = tempVAL->memoryProtectAttributes;
                break;
            }
            else
            {
                tempVAL = CONTAINING_RECORD(tempVAL->ValidAddressEntry.Next, VAL, ValidAddressEntry);
            }
        }
    }
    return newNode;
}
static VOID continueUpdateResultSavedBuffer(
    IN PVOID kernelTargetAddressMapped,
    IN PRSL* savedRsl
)
{
    //主要是考虑到字符串类型，所以要RTLZEROMEMORY.
    RtlZeroMemory((*savedRsl)->buffer, (*savedRsl)->targetAddressBufferLen);
    RtlCopyMemory((*savedRsl)->buffer, kernelTargetAddressMapped, (*savedRsl)->targetAddressBufferLen);
    return;
}
static VOID setResultSavedListVisitedTimes(
    IN PRSL* headRSL,
    IN ULONG visitedTime
)
{
    PRSL temp = *headRSL;
    if (temp == NULL)
    {
        log(空结果链表，无法设置访问次数.);
        return;
    }
    while (temp->ResultAddressEntry.Flink != &(*headRSL)->ResultAddressEntry)
    {
        temp->times = visitedTime;
        temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
    }
    temp->times = visitedTime;
    return;
}
static VOID BuildKMPTable(
    IN PUCHAR pattern, 
    IN SIZE_T patternSize, 
    OUT SIZE_T* kmpTable
)
{
    SIZE_T j = 0;
    kmpTable[0] = 0;
    for (SIZE_T i = 1; i < patternSize; i++) 
    {
        while (j > 0 && pattern[i] != pattern[j]) 
        {
            j = kmpTable[j - 1];
        }
        if (pattern[i] == pattern[j]) 
        {
            j++;
        }
        kmpTable[i] = j;
    }
    return;
}
static VOID KMP_match(
    IN PVOID kernelPageBeginAddress,
    IN SIZE_T pageSize,
    IN PUCHAR patternWannaFind,
    IN SIZE_T patternLen,
    IN ULONG_PTR userPageBeginAddress,
    IN PVAL headVAL,
    OUT ULONG_PTR* addressWannaFreed,
    OUT PRSL* headRSL
) 
{
    if (!kernelPageBeginAddress || !patternWannaFind || patternLen == 0 || pageSize < patternLen)
    {
        return;
    }

    PUCHAR text = (PUCHAR)kernelPageBeginAddress;
    SIZE_T* kmpTable = (SIZE_T*)ExAllocatePoolWithTag(NonPagedPool, patternLen * sizeof(SIZE_T), 'z+aa');
    if (!kmpTable) 
    {
        return;
    }

    BuildKMPTable(patternWannaFind, patternLen, kmpTable);

    SIZE_T j = 0;
    for (SIZE_T i = 0; i < pageSize; i++) 
    {
        while (j > 0 && text[i] != patternWannaFind[j]) 
        {
            j = kmpTable[j - 1];
        }
        if (text[i] == patternWannaFind[j]) 
        {
            j++;
        }
        if (j == patternLen)
        {
            if (*headRSL == NULL)
            {
                *headRSL = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + i - patternLen + 1), userPageBeginAddress + i - patternLen + 1, patternLen, headVAL);
                if (*headRSL)
                {
                    (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                }
            }
            else
            {
                PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                PRSL newNode = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + i - patternLen + 1), userPageBeginAddress + i - patternLen + 1, patternLen, headVAL);
                tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
            }
            j = kmpTable[j - 1];
        }
    }
    *addressWannaFreed = (ULONG_PTR)kmpTable;
}
VOID REGION_searchPattern(
    IN CONST PUCHAR kernelPageBeginAddress,
    IN SIZE_T kernelPageSize,
    IN VALUE_TYPE valueType,
    IN PUCHAR lowHexPointer,
    IN PUCHAR highHexPointer,
    IN ULONG64 userPageBeginAddress,
    IN PVAL headVAL,
    OUT PRSL* headRSL
)
{
    switch (valueType)
    {
        case TYPE_BYTE:
        {
            SIZE_T dataLen = 1;
            for (SIZE_T j = 0; j < kernelPageSize - dataLen + 1; j++)
            {
                if (*(PCHAR)(kernelPageBeginAddress + j) >= *(PCHAR)lowHexPointer && *(PCHAR)(kernelPageBeginAddress + j) <= *(PCHAR)highHexPointer)
                {
                    if (*headRSL == NULL)
                    {
                        *headRSL = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        if (*headRSL)
                        {
                            (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                            (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                        }
                    }
                    else
                    {
                        PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                        PRSL newNode = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                    }
                }
            }
            break;
        }
        case TYPE_WORD:
        {
            SIZE_T dataLen = 2;
            for (SIZE_T j = 0; j < kernelPageSize - dataLen + 1; j++)
            {
                if (*(PSHORT)(kernelPageBeginAddress + j) >= *(PSHORT)lowHexPointer && *(PSHORT)(kernelPageBeginAddress + j) <= *(PSHORT)highHexPointer)
                {
                    if (*headRSL == NULL)
                    {
                        *headRSL = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        if (*headRSL)
                        {
                            (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                            (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                        }
                    }
                    else
                    {
                        PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                        PRSL newNode = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                    }
                }
            }
            break;
        }
        case TYPE_DWORD:
        {
            SIZE_T dataLen = 4;
            for (SIZE_T j = 0; j < kernelPageSize - dataLen + 1; j++)
            {
                if (*(PINT)(kernelPageBeginAddress + j) >= *(PINT)lowHexPointer && *(PINT)(kernelPageBeginAddress + j) <= *(PINT)highHexPointer)
                {
                    if (*headRSL == NULL)
                    {
                        *headRSL = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        if (*headRSL)
                        {
                            (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                            (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                        }
                    }
                    else
                    {
                        PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                        PRSL newNode = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                    }
                }
            }
            break;
        }
        case TYPE_QWORD:
        {
            SIZE_T dataLen = 8;
            for (SIZE_T j = 0; j < kernelPageSize - dataLen + 1; j++)
            {
                if (*(PLONG64)(kernelPageBeginAddress + j) >= *(PLONG64)lowHexPointer && *(PLONG64)(kernelPageBeginAddress + j) <= *(PLONG64)highHexPointer)
                {
                    if (*headRSL == NULL)
                    {
                        *headRSL = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        if (*headRSL)
                        {
                            (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                            (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                        }
                    }
                    else
                    {
                        PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                        PRSL newNode = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                    }
                }
            }
            break;
        }
        case TYPE_FLOAT:
        {
            SIZE_T dataLen = 4;
            for (SIZE_T j = 0; j < kernelPageSize - dataLen + 1; j++)
            {
                if (*(float*)(kernelPageBeginAddress + j) >= *(float*)lowHexPointer && *(float*)(kernelPageBeginAddress + j) <= *(float*)highHexPointer)
                {
                    if (*headRSL == NULL)
                    {
                        *headRSL = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        if (*headRSL)
                        {
                            (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                            (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                        }
                    }
                    else
                    {
                        PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                        PRSL newNode = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                    }
                }
            }
            break;
        }
        case TYPE_DOUBLE:
        {
            SIZE_T dataLen = 8;
            for (SIZE_T j = 0; j < kernelPageSize - dataLen + 1; j++)
            {
                if (*(double*)(kernelPageBeginAddress + j) >= *(float*)lowHexPointer && *(float*)(kernelPageBeginAddress + j) <= *(double*)highHexPointer)
                {
                    if (*headRSL == NULL)
                    {
                        *headRSL = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        if (*headRSL)
                        {
                            (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                            (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                        }
                    }
                    else
                    {
                        PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                        PRSL newNode = createResultSavedNode(visitedTimes, (PVOID)((ULONG_PTR)kernelPageBeginAddress + j), userPageBeginAddress + j, dataLen, headVAL);
                        tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                        newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                    }
                }
            }
            break;
        }
        default:
        {
            break;
        }
    }
    return;
}
/*
    尽管IoAllocateMdl参数中没用到PID，但是整个环境还是要在APC挂靠环境下！
    否则只能检测到【DLL公共地址】，就是那些7FF开头的DLL固定地址！《独属于PID所在进程空间的地址探测不到》！
    尽管ALLOCATEMDL在非APC挂靠环境下也能申请成功，但是无法锁定独属于用户进程的地址页面！
    x64所有进程都有公共的DLL载入地址，所以为了锁住用户独属的进程虚拟地址，还是要挂靠环境才能成功！
*/
static VOID searchTarget$FIRST_PRECISE_SCAN(
    IN PSI si,
    IN ULONG64 pid,
    IN PVAL headVAL,
    OUT PRSL* headRSL
)
{
    PVAL tempVAL = headVAL;
    PMDL mdl = NULL;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    while (tempVAL->ValidAddressEntry.Next != NULL)
    {
        SIZE_T pageNum = tempVAL->pageNums;
        for (SIZE_T currPageIndex = 0; currPageIndex < pageNum; currPageIndex++)
        {
            mdl = IoAllocateMdl((PVOID)((tempVAL->beginAddress + currPageIndex * PAGE_SIZE) & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
            __try
            {
                MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
                PVOID kernelPageAddress = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
                ULONG_PTR addressWannaFreed = 0;
                KMP_match(
                    kernelPageAddress,
                    PAGE_SIZE,
                    si->u.precise.ptr2Value,
                    si->u.precise.valueLen,
                    (tempVAL->beginAddress + currPageIndex * (SIZE_T)PAGE_SIZE) & ~0xFFFull,
                    headVAL,
                    &addressWannaFreed,
                    headRSL
                );
                ExFreePool((PVOID)addressWannaFreed);
                addressWannaFreed = 0;
                MmUnlockPages(mdl);
            }
            __except (1)
            {
                //log(锁定页面范围失败！此页面不在物理页中，跳到下一页.);
            }
            IoFreeMdl(mdl);
        }
        tempVAL = CONTAINING_RECORD(tempVAL->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
static VOID searchTarget$FIRST_REGION_SCAN(
    IN PSI si,
    IN ULONG64 pid,
    IN PVAL headVAL,
    OUT PRSL* headRSL
)
{
    PVAL tempVAL = headVAL;
    PMDL mdl = NULL;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    while (tempVAL->ValidAddressEntry.Next != NULL)
    {
        SIZE_T pageNum = tempVAL->pageNums;
        for (SIZE_T currPageIndex = 0; currPageIndex < pageNum; currPageIndex++)
        {
            //尽管IoAllocateMdl参数中没用到PID，但是整个环境还是要在APC挂靠环境下！
            //否则只能检测到【DLL公共地址】，就是那些7FF开头的DLL固定地址！《独属于PID所在进程空间的地址探测不到》！
            //尽管ALLOCATEMDL在非APC挂靠环境下也能申请成功，但是无法锁定独属于用户进程的地址页面！
            //x64所有进程都有公共的DLL载入地址，所以为了锁住用户独属的进程虚拟地址，还是要挂靠环境才能成功！
            mdl = IoAllocateMdl((PVOID)((tempVAL->beginAddress + currPageIndex * PAGE_SIZE) & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
            __try
            {
                MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
                PVOID kernelPageAddress = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
                ULONG_PTR addressWannaFreed = 0;
                REGION_searchPattern(
                    kernelPageAddress,
                    PAGE_SIZE,
                    si->valueType,
                    si->u.region.ptr2LowerBound,
                    si->u.region.ptr2HigherBound,
                    (tempVAL->beginAddress + currPageIndex * PAGE_SIZE) & ~0xFFFull,
                    headVAL,
                    headRSL
                );
                ExFreePool((PVOID)addressWannaFreed);
                addressWannaFreed = 0;
                MmUnlockPages(mdl);
            }
            __except (1)
            {
                //log(锁定页面范围失败！此页面不在物理页中，跳到下一页.);
            }
            IoFreeMdl(mdl);
        }
        tempVAL = CONTAINING_RECORD(tempVAL->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
static VOID searchTarget$FIRST_PATTERN_SCAN(
    IN PSI si,
    IN ULONG64 pid,
    IN PVAL headVAL,
    OUT PRSL* headRSL
)
{
    PVAL tempVAL = headVAL;
    PMDL mdl = NULL;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    while (tempVAL->ValidAddressEntry.Next != NULL)
    {
        SIZE_T pageNum = tempVAL->pageNums;
        for (SIZE_T currPageIndex = 0; currPageIndex < pageNum; currPageIndex++)
        {
            mdl = IoAllocateMdl((PVOID)((tempVAL->beginAddress + currPageIndex * PAGE_SIZE) & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
            __try
            {
                MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
                PVOID kernelPageAddress = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
                ULONG_PTR addressWannaFreed = 0;
                KMP_match(
                    kernelPageAddress,
                    PAGE_SIZE,
                    si->u.pattern.ptr2Pattern,
                    si->u.pattern.patternLen,
                    (tempVAL->beginAddress + currPageIndex * (SIZE_T)PAGE_SIZE) & ~0xFFFull,
                    headVAL,
                    &addressWannaFreed,
                    headRSL
                );
                ExFreePool((PVOID)addressWannaFreed);
                addressWannaFreed = 0;
                MmUnlockPages(mdl);
            }
            __except (1)
            {
                //log(锁定页面范围失败！此页面不在物理页中，跳到下一页.);
            }
            IoFreeMdl(mdl);
        }
        tempVAL = CONTAINING_RECORD(tempVAL->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
static VOID searchTargetFirstChance(
    IN PSI si,
    IN ULONG64 pid,
    IN PVAL headVAL,
    OUT PRSL* headRSL
)
{
    if (*headRSL != NULL)
    {
        log(进行第一次搜索，但是结果链表非空，表明之前内存没释放干净，已驳回.);
        return;
    }
    visitedTimes = 0;
    switch (si->scanType)
    {
        case FIRST_PRECISE_SCAN:
        {
            searchTarget$FIRST_PRECISE_SCAN(si, pid, headVAL, headRSL);
            break;
        }
        case FIRST_REGION_SCAN:
        {
            searchTarget$FIRST_REGION_SCAN(si, pid, headVAL, headRSL);
            break;
        }
        case FIRST_PATTERN_SCAN:
        {
            searchTarget$FIRST_PATTERN_SCAN(si, pid, headVAL, headRSL);
            break;
        }
        default:
        {
            break;
        }
    }
    return;
}
static BOOLEAN largerLowerEqual$$$JUDGE(
    VALUE_TYPE valueType,
    PVOID addressInRsl,
    PVOID oldValueBuffer,
    LLE_JUDGE mode
)
{
    switch (valueType)
    {
        case TYPE_BYTE:
        {
            switch (mode)
            {
                case COMPARE_LARGER:
                {
                    return *(CHAR*)addressInRsl <= *(CHAR*)oldValueBuffer;
                }
                case COMPARE_LOWER:
                {
                    return *(CHAR*)addressInRsl >= *(CHAR*)oldValueBuffer;
                }
                case COMPARE_UNCHANGED:
                {
                    return *(CHAR*)addressInRsl != *(CHAR*)oldValueBuffer;
                }
                default:
                {
                    break;
                }
            }
            break;
        }
        case TYPE_WORD:
        {
            switch (mode)
            {
                case COMPARE_LARGER:
                {
                    return *(SHORT*)addressInRsl <= *(SHORT*)oldValueBuffer;
                }
                case COMPARE_LOWER:
                {
                    return *(SHORT*)addressInRsl >= *(SHORT*)oldValueBuffer;
                }
                case COMPARE_UNCHANGED:
                {
                    return *(SHORT*)addressInRsl != *(SHORT*)oldValueBuffer;
                }
                default:
                {
                    break;
                }
            }
            break;
        }
        case TYPE_DWORD:
        {
            switch (mode)
            {
                case COMPARE_LARGER:
                {
                    return *(INT*)addressInRsl <= *(INT*)oldValueBuffer;
                }
                case COMPARE_LOWER:
                {
                    return *(INT*)addressInRsl >= *(INT*)oldValueBuffer;
                }
                case COMPARE_UNCHANGED:
                {
                    return *(INT*)addressInRsl != *(INT*)oldValueBuffer;
                }
                default:
                {
                    break;
                }
            }
            break;
        }
        case TYPE_QWORD:
        {
            switch (mode)
            {
                case COMPARE_LARGER:
                {
                    return *(LONG64*)addressInRsl <= *(LONG64*)oldValueBuffer;
                }
                case COMPARE_LOWER:
                {
                    return *(LONG64*)addressInRsl >= *(LONG64*)oldValueBuffer;
                }
                case COMPARE_UNCHANGED:
                {
                    return *(LONG64*)addressInRsl != *(LONG64*)oldValueBuffer;
                }
                default:
                {
                    break;
                }
            }
            break;
        }
        case TYPE_FLOAT:
        {
            switch (mode)
            {
                case COMPARE_LARGER:
                {
                    return *(float*)addressInRsl <= *(float*)oldValueBuffer;
                }
                case COMPARE_LOWER:
                {
                    return *(float*)addressInRsl >= *(float*)oldValueBuffer;
                }
                case COMPARE_UNCHANGED:
                {
                    return *(float*)addressInRsl != *(float*)oldValueBuffer;
                }
                default:
                {
                    break;
                }
            }
            break;
        }
        case TYPE_DOUBLE:
        {
            switch (mode)
            {
                case COMPARE_LARGER:
                {
                    return *(double*)addressInRsl <= *(double*)oldValueBuffer;
                }
                case COMPARE_LOWER:
                {
                    return *(double*)addressInRsl >= *(double*)oldValueBuffer;
                }
                case COMPARE_UNCHANGED:
                {
                    return *(double*)addressInRsl != *(double*)oldValueBuffer;
                }
                default:
                {
                    break;
                }
            }
            break;
        }
        default:
        {
            break;
        }
    }
    return 1;
}
static BOOLEAN region$$$JUDGE(
    VALUE_TYPE valueType,
    PVOID addressInRsl,
    PVOID lowerBoundPointer,
    PVOID higherBoundPointer
)
{
    switch (valueType)
    {
        case TYPE_BYTE:
        {
            return *(CHAR*)addressInRsl <= *(CHAR*)lowerBoundPointer || *(CHAR*)addressInRsl >= *(CHAR*)higherBoundPointer;
        }
        case TYPE_WORD:
        {
            return *(SHORT*)addressInRsl <= *(SHORT*)lowerBoundPointer || *(SHORT*)addressInRsl >= *(SHORT*)higherBoundPointer;
        }
        case TYPE_DWORD:
        {
            return *(INT*)addressInRsl <= *(INT*)lowerBoundPointer || *(INT*)addressInRsl >= *(INT*)higherBoundPointer;
        }
        case TYPE_QWORD:
        {
            return *(LONG64*)addressInRsl <= *(LONG64*)lowerBoundPointer || *(LONG64*)addressInRsl >= *(LONG64*)higherBoundPointer;
        }
        case TYPE_FLOAT:
        {
            return *(float*)addressInRsl <= *(float*)lowerBoundPointer || *(float*)addressInRsl >= *(float*)higherBoundPointer;
        }
        case TYPE_DOUBLE:
        {
            return *(double*)addressInRsl <= *(double*)lowerBoundPointer || *(double*)addressInRsl >= *(double*)higherBoundPointer;
        }
        default:
        {
            break;
        }
    }
    return 1;
}
static VOID searchTarget$$$CONTINUE_PRECISE_SCAN(
    IN PSI si,
    IN ULONG64 pid,
    OUT PLIST_ENTRY v
)
{
    PLIST_ENTRY head = v;
    PLIST_ENTRY currListLoc = v;
    PMDL mdl = NULL;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    while (currListLoc->Flink != head)
    {
        //这里不需要遍历页面数量了，因为目标地址最多就在一个页面中！
        PRSL curr = CONTAINING_RECORD(currListLoc->Flink, RSL, ResultAddressEntry);
        mdl = IoAllocateMdl((PVOID)(curr->targetAddress & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
        __try
        {
            MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
            SIZE_T offset = curr->targetAddress & 0xFFFull;
            PVOID kernelMapped = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (strncmp((CONST CHAR*)((ULONG_PTR)kernelMapped + offset), (CONST CHAR*)si->u.precise.ptr2Value, si->u.precise.valueLen) != 0)
            {
                currListLoc->Flink = currListLoc->Flink->Flink;
                currListLoc->Flink->Blink = currListLoc;
                curr->ResultAddressEntry.Flink = NULL;
                curr->ResultAddressEntry.Blink = NULL;
                ExFreePool(curr->buffer);
                curr->buffer = NULL;
                ExFreePool(curr);
                curr = NULL;
            }
            else
            {
                continueUpdateResultSavedBuffer((PVOID)((ULONG_PTR)kernelMapped + offset), &curr);
                currListLoc = currListLoc->Flink;
            }
            MmUnlockPages(mdl);
        }
        __except (1)
        {
            currListLoc->Flink = currListLoc->Flink->Flink;
            currListLoc->Flink->Blink = currListLoc;
            curr->ResultAddressEntry.Flink = NULL;
            curr->ResultAddressEntry.Blink = NULL;
            ExFreePool(curr->buffer);
            curr->buffer = NULL;
            ExFreePool(curr);
            curr = NULL;
        }
        IoFreeMdl(mdl);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
static VOID searchTarget$$$CONTINUE_LARGER_SCAN(
    IN PSI si,
    IN ULONG64 pid,
    OUT PLIST_ENTRY v
)
{
    PLIST_ENTRY head = v;
    PLIST_ENTRY currListLoc = v;
    PMDL mdl = NULL;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    while (currListLoc->Flink != head)
    {
        PRSL curr = CONTAINING_RECORD(currListLoc->Flink, RSL, ResultAddressEntry);
        mdl = IoAllocateMdl((PVOID)(curr->targetAddress & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
        __try
        {
            MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
            SIZE_T offset = curr->targetAddress & 0xFFFull;
            PVOID kernelMapped = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (largerLowerEqual$$$JUDGE(si->valueType, (PVOID)((ULONG_PTR)kernelMapped + offset), (PVOID)curr->buffer, COMPARE_LARGER))
            {
                currListLoc->Flink = currListLoc->Flink->Flink;
                currListLoc->Flink->Blink = currListLoc;
                curr->ResultAddressEntry.Flink = NULL;
                curr->ResultAddressEntry.Blink = NULL;
                ExFreePool(curr->buffer);
                curr->buffer = NULL;
                ExFreePool(curr);
                curr = NULL;
            }
            else
            {
                continueUpdateResultSavedBuffer((PVOID)((ULONG_PTR)kernelMapped + offset), &curr);
                currListLoc = currListLoc->Flink;
            }
            MmUnlockPages(mdl);
        }
        __except (1)
        {
            currListLoc->Flink = currListLoc->Flink->Flink;
            currListLoc->Flink->Blink = currListLoc;
            curr->ResultAddressEntry.Flink = NULL;
            curr->ResultAddressEntry.Blink = NULL;
            ExFreePool(curr->buffer);
            curr->buffer = NULL;
            ExFreePool(curr);
            curr = NULL;
        }
        IoFreeMdl(mdl);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
static VOID searchTarget$$$CONTINUE_LOWER_SCAN(
    IN PSI si,
    IN ULONG64 pid,
    OUT PLIST_ENTRY v
)
{
    PLIST_ENTRY head = v;
    PLIST_ENTRY currListLoc = v;
    PMDL mdl = NULL;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    while (currListLoc->Flink != head)
    {
        PRSL curr = CONTAINING_RECORD(currListLoc->Flink, RSL, ResultAddressEntry);
        mdl = IoAllocateMdl((PVOID)(curr->targetAddress & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
        __try
        {
            MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
            SIZE_T offset = curr->targetAddress & 0xFFFull;
            PVOID kernelMapped = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (largerLowerEqual$$$JUDGE(si->valueType, (PVOID)((ULONG_PTR)kernelMapped + offset), (PVOID)curr->buffer, COMPARE_LOWER))
            {
                currListLoc->Flink = currListLoc->Flink->Flink;
                currListLoc->Flink->Blink = currListLoc;
                curr->ResultAddressEntry.Flink = NULL;
                curr->ResultAddressEntry.Blink = NULL;
                ExFreePool(curr->buffer);
                curr->buffer = NULL;
                ExFreePool(curr);
                curr = NULL;
            }
            else
            {
                continueUpdateResultSavedBuffer((PVOID)((ULONG_PTR)kernelMapped + offset), &curr);
                currListLoc = currListLoc->Flink;
            }
            MmUnlockPages(mdl);
        }
        __except (1)
        {
            currListLoc->Flink = currListLoc->Flink->Flink;
            currListLoc->Flink->Blink = currListLoc;
            curr->ResultAddressEntry.Flink = NULL;
            curr->ResultAddressEntry.Blink = NULL;
            ExFreePool(curr->buffer);
            curr->buffer = NULL;
            ExFreePool(curr);
            curr = NULL;
        }
        IoFreeMdl(mdl);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
static VOID searchTarget$$$CONTINUE_UNCHANGED_SCAN(
    IN PSI si,
    IN ULONG64 pid,
    OUT PLIST_ENTRY v
)
{
    PLIST_ENTRY head = v;
    PLIST_ENTRY currListLoc = v;
    PMDL mdl = NULL;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    while (currListLoc->Flink != head)
    {
        PRSL curr = CONTAINING_RECORD(currListLoc->Flink, RSL, ResultAddressEntry);
        mdl = IoAllocateMdl((PVOID)(curr->targetAddress & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
        __try
        {
            MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
            SIZE_T offset = curr->targetAddress & 0xFFFull;
            PVOID kernelMapped = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (largerLowerEqual$$$JUDGE(si->valueType, (PVOID)((ULONG_PTR)kernelMapped + offset), (PVOID)curr->buffer, COMPARE_UNCHANGED))
            {
                currListLoc->Flink = currListLoc->Flink->Flink;
                currListLoc->Flink->Blink = currListLoc;
                curr->ResultAddressEntry.Flink = NULL;
                curr->ResultAddressEntry.Blink = NULL;
                ExFreePool(curr->buffer);
                curr->buffer = NULL;
                ExFreePool(curr);
                curr = NULL;
            }
            else
            {
                continueUpdateResultSavedBuffer((PVOID)((ULONG_PTR)kernelMapped + offset), &curr);
                currListLoc = currListLoc->Flink;
            }
            MmUnlockPages(mdl);
        }
        __except (1)
        {
            currListLoc->Flink = currListLoc->Flink->Flink;
            currListLoc->Flink->Blink = currListLoc;
            curr->ResultAddressEntry.Flink = NULL;
            curr->ResultAddressEntry.Blink = NULL;
            ExFreePool(curr->buffer);
            curr->buffer = NULL;
            ExFreePool(curr);
            curr = NULL;
        }
        IoFreeMdl(mdl);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
static VOID searchTarget$$$CONTINUE_REGION_SCAN(
    IN PSI si,
    IN ULONG64 pid,
    OUT PLIST_ENTRY v
)
{
    PLIST_ENTRY head = v;
    PLIST_ENTRY currListLoc = v;
    PMDL mdl = NULL;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    while (currListLoc->Flink != head)
    {
        PRSL curr = CONTAINING_RECORD(currListLoc->Flink, RSL, ResultAddressEntry);
        mdl = IoAllocateMdl((PVOID)(curr->targetAddress & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
        __try
        {
            MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
            SIZE_T offset = curr->targetAddress & 0xFFFull;
            PVOID kernelMapped = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            if (region$$$JUDGE(si->valueType, (PVOID)((ULONG_PTR)kernelMapped + offset), (PVOID)si->u.region.ptr2LowerBound, (PVOID)si->u.region.ptr2HigherBound))
            {
                currListLoc->Flink = currListLoc->Flink->Flink;
                currListLoc->Flink->Blink = currListLoc;
                curr->ResultAddressEntry.Flink = NULL;
                curr->ResultAddressEntry.Blink = NULL;
                ExFreePool(curr->buffer);
                curr->buffer = NULL;
                ExFreePool(curr);
                curr = NULL;
            }
            else
            {
                continueUpdateResultSavedBuffer((PVOID)((ULONG_PTR)kernelMapped + offset), &curr);
                currListLoc = currListLoc->Flink;
            }
            MmUnlockPages(mdl);
        }
        __except (1)
        {
            currListLoc->Flink = currListLoc->Flink->Flink;
            currListLoc->Flink->Blink = currListLoc;
            curr->ResultAddressEntry.Flink = NULL;
            curr->ResultAddressEntry.Blink = NULL;
            ExFreePool(curr->buffer);
            curr->buffer = NULL;
            ExFreePool(curr);
            curr = NULL;
        }
        IoFreeMdl(mdl);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
static VOID searchTarget$$$CONTINUE_PATTERN_SCAN(
    IN PSI si,
    IN ULONG64 pid,
    OUT PLIST_ENTRY v
)
{
    PLIST_ENTRY head = v;
    PLIST_ENTRY currListLoc = v;
    PMDL mdl = NULL;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KeStackAttachProcess(pe, &apc);
    while (currListLoc->Flink != head)
    {
        PRSL curr = CONTAINING_RECORD(currListLoc->Flink, RSL, ResultAddressEntry);
        mdl = IoAllocateMdl((PVOID)(curr->targetAddress & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
        __try
        {
            MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
            SIZE_T offset = curr->targetAddress & 0xFFFull;
            PVOID kernelMapped = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
            //通过WINDBG发现，如果第二次字符串搜索过长，可能会跨越边界导致蓝屏.
            //比如某个页的最后三个字节是匹配IDA，但是第二次读的是IDAPRO，那么这个页面就会因为无法读取过长的地址而触发蓝屏！
            //偶发性BUG
            if ((ULONG_PTR)kernelMapped + offset + si->u.pattern.patternLen >= (ULONG_PTR)kernelMapped + PAGE_SIZE)
            {
                log(新输入的字符串长度过长，导致结果节点中有内存跨越了两个页面！已经舍弃此结果.);
                currListLoc->Flink = currListLoc->Flink->Flink;
                currListLoc->Flink->Blink = currListLoc;
                curr->ResultAddressEntry.Flink = NULL;
                curr->ResultAddressEntry.Blink = NULL;
                ExFreePool(curr->buffer);
                curr->buffer = NULL;
                ExFreePool(curr);
                curr = NULL;
                currListLoc = currListLoc->Flink;
            }
            else
            {
                if (strncmp((CONST CHAR*)((ULONG_PTR)kernelMapped + offset), (CONST CHAR*)si->u.pattern.ptr2Pattern, si->u.pattern.patternLen) != 0)
                {
                    currListLoc->Flink = currListLoc->Flink->Flink;
                    currListLoc->Flink->Blink = currListLoc;
                    curr->ResultAddressEntry.Flink = NULL;
                    curr->ResultAddressEntry.Blink = NULL;
                    ExFreePool(curr->buffer);
                    curr->buffer = NULL;
                    ExFreePool(curr);
                    curr = NULL;
                }
                else
                {
                    continueUpdateResultSavedBuffer((PVOID)((ULONG_PTR)kernelMapped + offset), &curr);
                    currListLoc = currListLoc->Flink;
                }
            }
            MmUnlockPages(mdl);
        }
        __except (1)
        {
            currListLoc->Flink = currListLoc->Flink->Flink;
            currListLoc->Flink->Blink = currListLoc;
            curr->ResultAddressEntry.Flink = NULL;
            curr->ResultAddressEntry.Blink = NULL;
            ExFreePool(curr->buffer);
            curr->buffer = NULL;
            ExFreePool(curr);
            curr = NULL;
        }
        IoFreeMdl(mdl);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
static VOID searchTargetNonFirstChance(
    IN PSI si,
    IN ULONG64 pid,
    OUT PRSL* headRSL
)
{
    if (*headRSL == NULL)
    {
        log(进行第一次后的继续搜索，但是结果链表为空，表明试图访问空的结果链表，已驳回.);
        return;
    }
    LIST_ENTRY virtualListHead = { 0 };
    PLIST_ENTRY v = &virtualListHead;
    PLIST_ENTRY tail = (*headRSL)->ResultAddressEntry.Blink;
    v->Flink = &(*headRSL)->ResultAddressEntry;
    tail->Flink = v;
    v->Blink = tail;
    (*headRSL)->ResultAddressEntry.Blink = v;
    visitedTimes++;
    switch (si->scanType)
    {
        case CONTINUE_PRECISE:
        {
            searchTarget$$$CONTINUE_PRECISE_SCAN(si, pid, v);
            break;
        }
        case CONTINUE_LARGER:
        {
            searchTarget$$$CONTINUE_LARGER_SCAN(si, pid, v);
            break;
        }
        case CONTINUE_LOWER:
        {
            searchTarget$$$CONTINUE_LOWER_SCAN(si, pid, v);
            break;
        }
        case CONTINUE_UNCHANGED:
        {
            searchTarget$$$CONTINUE_UNCHANGED_SCAN(si, pid, v);
            break;
        }
        case CONTINUE_REGION:
        {
            searchTarget$$$CONTINUE_REGION_SCAN(si, pid, v);
            break;
        }
        case CONTINUE_PATTERN:
        {
            searchTarget$$$CONTINUE_PATTERN_SCAN(si, pid, v);
            break;
        }
        case CONTINUE_INCREASED_BY:
        {
            //searchTarget$CONTINUE_INCREASED_BY_SCAN(si, pid, v);
            break;
        }
        case CONTINUE_DECREASED_BY:
        {
            //searchTarget$CONTINUE_DECREASED_BY_SCAN(si, pid, v);
            break;
        }
        default:
        {
            break;
        }
    }
    if (v->Flink != v)
    {
        log(以下地址的数值发生了相应变化：);
        *headRSL = CONTAINING_RECORD(v->Flink, RSL, ResultAddressEntry);
        v->Blink->Flink = v->Flink;
        v->Flink->Blink = v->Blink;
        v->Flink = NULL;
        v->Blink = NULL;
        setResultSavedListVisitedTimes(headRSL, visitedTimes);
    }
    else
    {
        log(没有符合相应变化的数值变动.);
        //在这里，如果没有匹配到任何变化数值
        //curr = v;
        //curr = CONTAINING_RECORD(currListLoc->Flink, RSL, ResultAddressEntry);
        //ExFreePool(curr); curr = NULL;并不会影响headRSL!
        //上面两步操作完成后，*headRSL就是悬挂指针了，地址存在但是指向虚无！
        //再次进入IRP就会导致访问野指针导致蓝屏！
        //浅拷贝的代价！(curr第一步时和*headRSL的数值一样，但是free了curr置curr为NULL却没置*headRSL为NULL！)
        *headRSL = NULL;
        visitedTimes = 0;
    }
    return;
}
VOID searchTargetBySearchInfo(
    IN PSI si,
    IN ULONG64 pid,
    IN PVAL headVAL,
    OUT PRSL* headRSL
)
{
    if (si == NULL)
    {
        return;
    }
    if (si->isFirstScan)
    {
        searchTargetFirstChance(si, pid, headVAL, headRSL);
    }
    else
    {
        searchTargetNonFirstChance(si, pid, headRSL);
    }
    return;
}
VOID checkSI(
    IN PSI si
)
{
    DbgPrint("isFirstScan: %X\n", si->isFirstScan);
    DbgPrint("valueType: %X\n", si->valueType);
    DbgPrint("scanType: %X\n", si->scanType);
    DbgPrint("memberType: %X\n", si->memberType);
    switch (si->memberType)
    {
        case UNION_MEMBER_PRECISE:
        {
            switch (si->valueType)
            {
                case TYPE_BYTE:
                    DbgPrint("数值: %hhu, %hhd\n", *(UCHAR*)si->u.precise.ptr2Value, *(CHAR*)si->u.precise.ptr2Value);
                    break;
                case TYPE_WORD:
                    DbgPrint("数值: %hu, %hd\n", *(USHORT*)si->u.precise.ptr2Value, *(SHORT*)si->u.precise.ptr2Value);
                    break;
                case TYPE_DWORD:
                    DbgPrint("数值: %u, %d\n", *(UINT*)si->u.precise.ptr2Value, *(INT*)si->u.precise.ptr2Value);
                    break;
                case TYPE_QWORD:
                    DbgPrint("数值: %llu, %lld\n", *(ULONG64*)si->u.precise.ptr2Value, *(LONG64*)si->u.precise.ptr2Value);
                    break;
                default:
                    break;
            }
            break;
        }
        case UNION_MEMBER_REGION:
        {
            switch (si->valueType)
            {
                case TYPE_BYTE:
                    DbgPrint("小数值: %hhu, %hhd\n", *(UCHAR*)si->u.region.ptr2LowerBound, *(CHAR*)si->u.region.ptr2LowerBound);
                    DbgPrint("大数值: %hhu, %hhd\n", *(UCHAR*)si->u.region.ptr2HigherBound, *(CHAR*)si->u.region.ptr2HigherBound);
                    break;
                case TYPE_WORD:
                    DbgPrint("小数值: %hu, %hd\n", *(USHORT*)si->u.region.ptr2LowerBound, *(SHORT*)si->u.region.ptr2LowerBound);
                    DbgPrint("大数值: %hu, %hd\n", *(USHORT*)si->u.region.ptr2HigherBound, *(SHORT*)si->u.region.ptr2HigherBound);
                    break;
                case TYPE_DWORD:
                    DbgPrint("小数值: %u, %d\n", *(UINT*)si->u.region.ptr2LowerBound, *(INT*)si->u.region.ptr2LowerBound);
                    DbgPrint("大数值: %u, %d\n", *(UINT*)si->u.region.ptr2HigherBound, *(INT*)si->u.region.ptr2HigherBound);
                    break;
                case TYPE_QWORD:
                    DbgPrint("小数值: %llu, %lld\n", *(ULONG64*)si->u.region.ptr2LowerBound, *(LONG64*)si->u.region.ptr2LowerBound);
                    DbgPrint("大数值: %llu, %lld\n", *(ULONG64*)si->u.region.ptr2HigherBound, *(LONG64*)si->u.region.ptr2HigherBound);
                    break;
                case TYPE_FLOAT:
                {
                    INT integer = 0;
                    ULONG64 fraction = 0;
                    DbgPrint("小数值: \n");
                    DbgPrintF((float*)si->u.region.ptr2LowerBound, &integer, &fraction);
                    DbgPrint("大数值: \n");
                    DbgPrintF((float*)si->u.region.ptr2HigherBound, &integer, &fraction);
                    break;
                }
                case TYPE_DOUBLE:
                {
                    INT integer = 0;
                    ULONG64 fraction = 0;
                    DbgPrint("小数值: \n");
                    DbgPrintD((double*)si->u.region.ptr2LowerBound, &integer, &fraction);
                    DbgPrint("大数值: \n");
                    DbgPrintD((double*)si->u.region.ptr2HigherBound, &integer, &fraction);
                    break;
                }
                default:
                    break;
            }
            break;
        }
        case UNION_MEMBER_PATTERN:
        {
            switch (si->valueType)
            {
                case TYPE_PATTERN:
                {
                    DbgPrint("字符串:\n");
                    for (size_t j = 0; j < si->u.pattern.patternLen; j++)
                    {
                        DbgPrint("%c", ((UCHAR*)si->u.pattern.ptr2Pattern)[j]);
                    }
                    break;
                }
                default:
                    break;
            }
            break;
        }
        default:
        {
            break;
        }
    }
    return;
}
VOID freeSI(
    IN PSI* si
)
{
    switch ((*si)->memberType)
    {
        case UNION_MEMBER_PRECISE:
        {
            if((*si)->u.precise.ptr2Value)
            {
                ExFreePool((*si)->u.precise.ptr2Value);
                (*si)->u.precise.ptr2Value = NULL;
            }
            break;
        }
        case UNION_MEMBER_REGION:
        {
            if((*si)->u.region.ptr2LowerBound)
            {
                ExFreePool((*si)->u.region.ptr2LowerBound);
                (*si)->u.region.ptr2LowerBound = NULL;
            }
            if((*si)->u.region.ptr2HigherBound)
            {
                ExFreePool((*si)->u.region.ptr2HigherBound);
                (*si)->u.region.ptr2HigherBound = NULL;
            }
            break;
        }
        case UNION_MEMBER_PATTERN:
        {
            if((*si)->u.pattern.ptr2Pattern)
            {
                ExFreePool((*si)->u.pattern.ptr2Pattern);
                (*si)->u.pattern.ptr2Pattern = NULL;
            }
            break;
        }
        default:
        {
            break;
        }
    }
    ExFreePool((*si));
    *si = NULL;
    return;
}
BOOLEAN checkAllRSLAddressLenValid(
    IN PRSL headRSL
)
{
    PRSL temp = headRSL;
    while (temp->ResultAddressEntry.Flink != &headRSL->ResultAddressEntry)
    {
        if (temp->targetAddressBufferLen == 0)
        {
            return 0;
        }
        else
        {
            temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
        }
    }
    if (temp->targetAddressBufferLen == 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
VOID printListVAL(
    IN PVAL headVAL
)
{
    PVAL temp = headVAL;
    SIZE_T cnt = 0;
    if (headVAL == NULL)
    {
        DbgPrint("empty list!");
        return;
    }
    while (temp->ValidAddressEntry.Next != NULL)
    {
        DbgPrint("ListNodeIndex: 0x%zu, begin: 0x%p\t end: 0x%p\t regionGap: 0x%llx\t pageNums: 0x%llx\t memState: %lx\t memProtect: %lx\t executeFlag: %hhx\t", cnt++, (PVOID)temp->beginAddress, (PVOID)temp->endAddress, temp->regionGap, temp->pageNums, temp->memoryState, temp->memoryProtectAttributes, temp->executeFlag);
        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    DbgPrint("ListNodeIndex: 0x%zu, begin: 0x%p\t end: 0x%p\t regionGap: 0x%llx\t pageNums: 0x%llx\t memState: %lx\t memProtect: %lx\t executeFlag: %hhx\t", cnt, (PVOID)temp->beginAddress, (PVOID)temp->endAddress, temp->regionGap, temp->pageNums, temp->memoryState, temp->memoryProtectAttributes, temp->executeFlag);
    return;
}
VOID printListRSL(
    IN_OPT ULONG64 pid,
    IN PRSL* headRSL
)
{
    SIZE_T resultsNum = 0;
    SIZE_T threshold = 200;
    if (pid == 0)
    {
        PRSL temp = *headRSL;
        if (temp == NULL || temp->buffer == NULL)
        {
            log(空结果链表，无法打印结果.);
            return;
        }
        while (temp->ResultAddressEntry.Flink != &(*headRSL)->ResultAddressEntry)
        {
            resultsNum++;
            temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
        }
        resultsNum++;
        if (resultsNum <= threshold)
        {
            DbgPrint("[sYsHacker By AYF @HEU] 目标地址个数：%zu全部打印如下\n", resultsNum);
            temp = *headRSL;
            while (temp->ResultAddressEntry.Flink != &(*headRSL)->ResultAddressEntry)
            {
                DbgPrint("[sYsHacker By AYF @HEU] 访问次数: %lu, 目标地址: %p\n", temp->times, (PVOID)temp->targetAddress);
                temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
            }
            DbgPrint("[sYsHacker By AYF @HEU] 访问次数: %lu, 目标地址: %p\n", temp->times, (PVOID)temp->targetAddress);
        }
        else
        {
            SIZE_T printNum = threshold / 2;
            DbgPrint("[sYsHacker By AYF @HEU] 目标地址个数：%zu过多，只打印前后%zu个地址\n", resultsNum, printNum);

            SIZE_T loopNum = 0;

            temp = *headRSL;
            loopNum = printNum;
            while (temp->ResultAddressEntry.Flink != &(*headRSL)->ResultAddressEntry && loopNum-- != 0)
            {
                DbgPrint("[sYsHacker By AYF @HEU] 访问次数: %lu, 前数第%zu个目标地址: %p\n", temp->times, printNum - loopNum, (PVOID)temp->targetAddress);
                temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
            }

            temp = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
            loopNum = printNum;
            while (temp->ResultAddressEntry.Blink != &(*headRSL)->ResultAddressEntry && loopNum-- != 0)
            {
                DbgPrint("[sYsHacker By AYF @HEU] 访问次数: %lu, 后数第%zu个目标地址: %p\n", temp->times, printNum - loopNum, (PVOID)temp->targetAddress);
                temp = CONTAINING_RECORD(temp->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
            }
        }
    }
    else
    {
        PRSL temp = *headRSL;
        if (temp == NULL || temp->buffer == NULL)
        {
            log(空结果链表，无法打印结果.);
            return;
        }
        while (temp->ResultAddressEntry.Flink != &(*headRSL)->ResultAddressEntry)
        {
            resultsNum++;
            temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
        }
        resultsNum++;

        PEPROCESS pe = NULL;
        KAPC_STATE apc = { 0 };
        PMDL mdl = NULL;
        PsLookupProcessByProcessId((HANDLE)pid, &pe);
        KeStackAttachProcess(pe, &apc);
        if (resultsNum <= threshold)
        {            
            DbgPrint("[sYsHacker By AYF @HEU] 目标地址个数：%zu全部打印如下\n", resultsNum);

            temp = *headRSL;
            while (temp->ResultAddressEntry.Flink != &(*headRSL)->ResultAddressEntry)
            {
                mdl = IoAllocateMdl((PVOID)((ULONG_PTR)temp->targetAddress & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
                __try
                {
                    MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
                    DbgPrint("[sYsHacker By AYF @HEU] 访问次数: %lu, 目标地址: %p -> [UCHAR]: %hhu\t[USHORT]: %hu\t[UINT]: %u\t[ULONG64]: %llu\t[FLOAT]: %f\t[DOUBLE]: %lf\n", temp->times, (PVOID)temp->targetAddress, *(UCHAR*)temp->targetAddress, *(USHORT*)temp->targetAddress, *(UINT*)temp->targetAddress, *(ULONG64*)temp->targetAddress, *(float*)temp->targetAddress, *(double*)temp->targetAddress);
                    MmUnlockPages(mdl);
                    temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
                }
                __except (1)
                {
                    //log(读取时页面不在物理页，删除);
                    PRSL prev = CONTAINING_RECORD(temp->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    prev->ResultAddressEntry.Flink = prev->ResultAddressEntry.Flink->Flink;
                    prev->ResultAddressEntry.Flink->Blink = &prev->ResultAddressEntry;
                    temp->ResultAddressEntry.Flink = NULL;
                    temp->ResultAddressEntry.Blink = NULL;
                    if (temp->buffer)
                    {
                        ExFreePool(temp->buffer);
                        temp->buffer = NULL;
                    }
                    if (temp)
                    {
                        ExFreePool(temp);
                        temp = NULL;
                    }
                    temp = CONTAINING_RECORD(prev->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
                }
                IoFreeMdl(mdl);
            }
            DbgPrint("[sYsHacker By AYF @HEU] 访问次数: %lu, 目标地址: %p -> [UCHAR]: %hhu\t[USHORT]: %hu\t[UINT]: %u\t[ULONG64]: %llu\t[FLOAT]: %f\t[DOUBLE]: %lf\n", temp->times, (PVOID)temp->targetAddress, *(UCHAR*)temp->targetAddress, *(USHORT*)temp->targetAddress, *(UINT*)temp->targetAddress, *(ULONG64*)temp->targetAddress, *(float*)temp->targetAddress, *(double*)temp->targetAddress);
        }
        else
        {
            SIZE_T printNum = threshold / 2;
            DbgPrint("[sYsHacker By AYF @HEU] 目标地址个数：%zu过多，只打印前后%zu个地址\n", resultsNum, printNum);

            SIZE_T loopNum = 0;

            temp = *headRSL;
            loopNum = printNum;
            while (temp->ResultAddressEntry.Flink != &(*headRSL)->ResultAddressEntry && loopNum-- != 0)
            {
                mdl = IoAllocateMdl((PVOID)((ULONG_PTR)temp->targetAddress & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
                __try
                {
                    MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
                    DbgPrint("[sYsHacker By AYF @HEU] 【前】 访问次数: %lu, 目标地址: %p -> [UCHAR]: %hhu\t[USHORT]: %hu\t[UINT]: %u\t[ULONG64]: %llu\t[FLOAT]: %f\t[DOUBLE]: %lf\n", temp->times, (PVOID)temp->targetAddress, *(UCHAR*)temp->targetAddress, *(USHORT*)temp->targetAddress, *(UINT*)temp->targetAddress, *(ULONG64*)temp->targetAddress, *(float*)temp->targetAddress, *(double*)temp->targetAddress);
                    MmUnlockPages(mdl);
                    temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
                }
                __except (1)
                {
                    //log(读取时页面不在物理页，删除);
                    PRSL prev = CONTAINING_RECORD(temp->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    prev->ResultAddressEntry.Flink = prev->ResultAddressEntry.Flink->Flink;
                    prev->ResultAddressEntry.Flink->Blink = &prev->ResultAddressEntry;
                    temp->ResultAddressEntry.Flink = NULL;
                    temp->ResultAddressEntry.Blink = NULL;
                    if (temp->buffer)
                    {
                        ExFreePool(temp->buffer);
                        temp->buffer = NULL;
                    }
                    if (temp)
                    {
                        ExFreePool(temp);
                        temp = NULL;
                    }
                    temp = CONTAINING_RECORD(prev->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
                }
                IoFreeMdl(mdl);
            }

            temp = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
            loopNum = printNum;
            while (temp->ResultAddressEntry.Blink != &(*headRSL)->ResultAddressEntry && loopNum-- != 0)
            {
                mdl = IoAllocateMdl((PVOID)((ULONG_PTR)temp->targetAddress & ~0xFFFull), PAGE_SIZE, FALSE, FALSE, NULL);
                __try
                {
                    MmProbeAndLockPages(mdl, UserMode, IoReadAccess);
                    DbgPrint("[sYsHacker By AYF @HEU] 【后】 访问次数: %lu, 目标地址: %p -> [UCHAR]: %hhu\t[USHORT]: %hu\t[UINT]: %u\t[ULONG64]: %llu\t[FLOAT]: %f\t[DOUBLE]: %lf\n", temp->times, (PVOID)temp->targetAddress, *(UCHAR*)temp->targetAddress, *(USHORT*)temp->targetAddress, *(UINT*)temp->targetAddress, *(ULONG64*)temp->targetAddress, *(float*)temp->targetAddress, *(double*)temp->targetAddress);
                    MmUnlockPages(mdl);
                    temp = CONTAINING_RECORD(temp->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                }
                __except (1)
                {
                    //log(读取时页面不在物理页，删除);
                    PRSL prev = CONTAINING_RECORD(temp->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    prev->ResultAddressEntry.Flink = prev->ResultAddressEntry.Flink->Flink;
                    prev->ResultAddressEntry.Flink->Blink = &prev->ResultAddressEntry;
                    temp->ResultAddressEntry.Flink = NULL;
                    temp->ResultAddressEntry.Blink = NULL;
                    if (temp->buffer)
                    {
                        ExFreePool(temp->buffer);
                        temp->buffer = NULL;
                    }
                    if (temp)
                    {
                        ExFreePool(temp);
                        temp = NULL;
                    }
                    temp = CONTAINING_RECORD(prev->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                }
                IoFreeMdl(mdl);
            }
        }
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(pe);
    }
    return;
}
ULONG64 getMaxRegionPages(
    IN PVAL head
)
{
    PVAL temp = head;
    ULONG64 ret = 0x0;
    while (temp->ValidAddressEntry.Next != NULL)
    {
        if (temp->pageNums >= ret)
        {
            ret = temp->pageNums;
        }
        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    return ret;
}
SIZE_T getNodeNumsForDoubleLinkedList(
    IN PRSL headRSL
)
{
    PRSL temp = headRSL;
    SIZE_T cnt = 0x0;
    while (temp->ResultAddressEntry.Flink != &headRSL->ResultAddressEntry)
    {
        cnt++;
        temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
    }
    return cnt;
}
UCHAR farBytesDiffer(
    IN PUCHAR oldPattern,
    IN PUCHAR newPattern,
    IN SIZE_T minSize
)
{
    for (SSIZE_T j = minSize - 1; j >= 0; j--)
    {
        if (*(UCHAR*)((ULONG_PTR)oldPattern + j) == *(UCHAR*)((ULONG_PTR)newPattern + j))
        {
            continue;
        }
        else
        {
            return ((*(UCHAR*)((ULONG_PTR)oldPattern + j)) >= *((UCHAR*)((ULONG_PTR)newPattern + j))) ? 1 : 2;
        }
    }
    return 0;
}
VOID ExFreeResultSavedLink(
    OUT PRSL* headRSL
)
{
    PRSL tempRSL = *headRSL;
    while (tempRSL != NULL && tempRSL->ResultAddressEntry.Flink != NULL)
    {
        PRSL tempX = CONTAINING_RECORD(tempRSL->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
        tempRSL->ResultAddressEntry.Flink = NULL;
        tempRSL->ResultAddressEntry.Blink = NULL;
        //这里，PSI初始化的时候没有ZEROMEMORY，导致虽然没分配buffer但是其值非零，导致了释放野指针蓝屏.
        if (tempRSL->buffer != NULL && tempRSL->targetAddressBufferLen != 0)
        {
            ExFreePool(tempRSL->buffer);
            tempRSL->buffer = NULL;
        }
        ExFreePool(tempRSL);
        tempRSL = tempX;
    }
}
VOID ExFreeValidAddressLink(
    OUT PVAL* headVAL
)
{
    PVAL temp = *headVAL;
    while (temp->ValidAddressEntry.Next != NULL)
    {
        PVAL tempX = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
        ExFreePool(temp);
        temp = tempX;
    }
    ExFreePool(temp);
    temp = NULL;
}

/*
    内存泄露问题！
    while (temp->ValidAddressEntry.Next != NULL)
    {
        PVAL tempX = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
        ExFreePool(temp); temp = NULL;
        temp = tempX;
    }
    这段代码发现标头为VVVV的内存有泄露，链表构建一次就泄露一块内存
    原因在于temp->ValidAddressEntry.Next == NULL的时候最后一块内存没释放
    所以导致了内存泄漏
*/
