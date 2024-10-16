#include "MemoryScannerHeader.h"

#pragma warning(disable:6387)
#pragma warning(disable:6011)
#pragma warning(disable:4702)

float mabs_float(
    float x
)
{
    return x >= (float)0.0 ? x : -x;
}

double mabs_double(
    double x
)
{
    return x >= (double)0.0 ? x : -x;
}

PVAL createValidAddressNode(
    IN ULONG64 begin,
    IN ULONG64 end,
    IN ULONG memState,
    IN ULONG memProtectAttributes,
    IN BOOLEAN executeFlag
)
{
    PVAL newNode = (PVAL)ExAllocatePoolWithTag(PagedPool, sizeof(VAL), 'vvvv');
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
        temp->pageNums = (temp->regionGap / 0x1000) + 1;
        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    return;
}
VOID buildValidAddressSingleList(
    IN PHANDLE phProcess,
    IN PMEMORY_INFORMATION_CLASS pMIC,
    IN PMEMORY_BASIC_INFORMATION pmbi,
    OUT PVAL* headVAL,
    IN ULONG64 addressMaxLimit
)
{
    ULONG64 currentAddress = 0x0;
    PVAL temp = NULL;
    ULONG64 writeAddressLen = 0x0;
    while (currentAddress <= addressMaxLimit)
    {
        if (NT_SUCCESS(ZwQueryVirtualMemory(*phProcess, (PVOID)currentAddress, *pMIC, pmbi, sizeof(MEMORY_BASIC_INFORMATION), &writeAddressLen)))
        {
            if (pmbi->Protect != 0x00 && pmbi->Protect != 0x01 && pmbi->Protect != 0x104 && pmbi->Protect != 0x100)
            {
                if (*headVAL == NULL)
                {
                    if (pmbi->Protect == 0x10 || pmbi->Protect == 0x20)
                    {
                        PVAL newNode = createValidAddressNode((UL64)pmbi->BaseAddress, (UL64)pmbi->BaseAddress + (UL64)pmbi->RegionSize - 1, (UL64)pmbi->State, (UL64)pmbi->Protect, 1);
                        *headVAL = newNode;
                    }
                    else
                    {
                        PVAL newNode = createValidAddressNode((UL64)pmbi->BaseAddress, (UL64)pmbi->BaseAddress + (UL64)pmbi->RegionSize - 1, (UL64)pmbi->State, (UL64)pmbi->Protect, 0);
                        *headVAL = newNode;
                    }
                }
                else
                {
                    temp = *headVAL;
                    while (temp->ValidAddressEntry.Next != NULL)
                    {
                        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
                    }
                    if (pmbi->Protect == 0x10 || pmbi->Protect == 0x20)
                    {
                        PVAL newNode = createValidAddressNode((UL64)pmbi->BaseAddress, (UL64)pmbi->BaseAddress + (UL64)pmbi->RegionSize - 1, (UL64)pmbi->State, (UL64)pmbi->Protect, 1);
                        temp->ValidAddressEntry.Next = &newNode->ValidAddressEntry;
                    }
                    else
                    {
                        if (temp->endAddress + 0x1 == (UL64)pmbi->BaseAddress)
                        {
                            temp->endAddress += pmbi->RegionSize;
                        }
                        else
                        {
                            PVAL newNode = createValidAddressNode((UL64)pmbi->BaseAddress, (UL64)pmbi->BaseAddress + (UL64)pmbi->RegionSize - 1, (UL64)pmbi->State, (UL64)pmbi->Protect, 0);
                            temp->ValidAddressEntry.Next = &newNode->ValidAddressEntry;
                        }
                    }
                }
            }
        }
        currentAddress = (ULONG64)pmbi->BaseAddress + pmbi->RegionSize;
    }
}

PRSL createResultSavedNode(
    IN ULONG times,
    IN ULONG64 address,
    IN ULONG64 addressBufferLen,
    IN PVAL headVAL
)
{
    PRSL newNode = (PRSL)ExAllocatePoolWithTag(PagedPool, sizeof(RSL), 'uuuu');
    if (newNode)
    {
        newNode->times = times;
        newNode->address = address;
        newNode->rslAddressBufferLen = addressBufferLen;
        PVAL tempVAL = headVAL;
        while (tempVAL->ValidAddressEntry.Next != NULL)
        {
            if (newNode->address <= tempVAL->endAddress && newNode->address >= tempVAL->beginAddress)
            {
                newNode->thisNodeAddressPageMaxValidAddress = tempVAL->endAddress;
                break;
            }
            else
            {
                tempVAL = CONTAINING_RECORD(tempVAL->ValidAddressEntry.Next, VAL, ValidAddressEntry);
            }
        }
        if (newNode->rslAddressBufferLen)
        {
            if (newNode->address + newNode->rslAddressBufferLen <= newNode->thisNodeAddressPageMaxValidAddress)
            {
                newNode->buffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, newNode->rslAddressBufferLen, 'tttt');
                for (size_t j = 0; j < newNode->rslAddressBufferLen && newNode->buffer; j++)
                {
                    newNode->buffer[j] = *(UCHAR*)((ULONG64)address + j);
                }
            }
            else
            {
                DbgPrint("Warning: This address attach %llu length will touch this page's valid address max limit!", newNode->rslAddressBufferLen);
                DbgPrint("Warning: For safety, set this node's buffer as NULL!");
                newNode->buffer = NULL;
            }
        }
        else
        {
            newNode->buffer = NULL;
        }
        newNode->ResultAddressEntry.Flink = NULL;
        newNode->ResultAddressEntry.Blink = NULL;
    }
    return newNode;
}
VOID initializePreciseSearchModeInput(
    OUT PSMI* smi,
    IN SIZE_T valueLen,
    IN PVOID pointerToIntegerValue
)
{
    *smi = (PSMI)ExAllocatePoolWithTag(PagedPool, sizeof(SMI), 'ziiz');
    if (*smi)
    {
        (*smi)->preciseMode.dataLen = valueLen;
        (*smi)->preciseMode.value_hexBytePointer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, (*smi)->preciseMode.dataLen, 'zbbz');
        for (SIZE_T j = 0; j < (*smi)->preciseMode.dataLen; j++)
        {
            (*smi)->preciseMode.value_hexBytePointer[j] = ((UCHAR*)pointerToIntegerValue)[j];
        }
    }
}
VOID initializeFuzzySearchModeInput(
    OUT PSMI* smi,
    IN SIZE_T valueLen,
    IN PVOID pointerToLowerValue,
    IN PVOID pointerToHigherValue
)
{
    *smi = (PSMI)ExAllocatePoolWithTag(PagedPool, sizeof(SMI), 'zffz');
    if (*smi)
    {
        (*smi)->fuzzyMode.dataLen = valueLen;
        (*smi)->fuzzyMode.lowLimit_hexBytePointer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, (*smi)->fuzzyMode.dataLen, 'zbbz');
        (*smi)->fuzzyMode.highLimit_hexBytePointer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, (*smi)->fuzzyMode.dataLen, 'zbbz');
        for (SIZE_T j = 0; j < (*smi)->fuzzyMode.dataLen; j++)
        {
            (*smi)->fuzzyMode.lowLimit_hexBytePointer[j] = ((UCHAR*)pointerToLowerValue)[j];
            (*smi)->fuzzyMode.highLimit_hexBytePointer[j] = ((UCHAR*)pointerToHigherValue)[j];
        }
    }
}
VOID initializePatternMatchTypeSearchModeInput(
    OUT PSMI* smi,
    IN PUCHAR pattern,
    IN SIZE_T patternLen
)
{
    *smi = (PSMI)ExAllocatePoolWithTag(PagedPool, sizeof(SMI), 'zppz');
    if (*smi)
    {
        (*smi)->patternMode.patternLen = patternLen;
        for (SIZE_T j = 0; j < (*smi)->patternMode.patternLen; j++)
        {
            (*smi)->patternMode.pattern[j] = pattern[j];
        }
    }
    return;
}
VOID KMP_computeLPSArray(
    CONST PUCHAR pattern,
    SIZE_T patLen,
    LONG* lps
)
{
    LONG length = 0;
    lps[0] = 0;
    LONG i = 1;

    while (i < patLen)
    {
        if (pattern[i] == pattern[length])
        {
            length++;
            lps[i] = length;
            i++;
        }
        else
        {
            if (length != 0)
            {
                length = lps[length - 1];
            }
            else
            {
                lps[i] = 0;
                i++;
            }
        }
    }
}
VOID KMP_searchPattern(
    IN CONST PUCHAR des,
    IN CONST PUCHAR pattern,
    IN SIZE_T desLen,
    IN SIZE_T patLen,
    IN ULONG64 pageBeginAddress,
    IN PVAL headVAL,
    OUT ULONG64* addressWannaFreed,
    OUT PRSL* headRSL
)
{
    PLONG lps = (PLONG)ExAllocatePool(NonPagedPool, patLen * sizeof(LONG));
    if (!lps)
    {
        DbgPrint("Memory allocation failed for LPS array\n");
        return;
    }
    KMP_computeLPSArray(pattern, patLen, lps);
    SIZE_T i = 0;
    SIZE_T j = 0;
    while (i < desLen)
    {
        if (pattern[j] == des[i])
        {
            i++;
            j++;
            if (j == patLen)
            {
                ULONG64 matchAddress = pageBeginAddress + (i - j);
                //DbgPrint("Pattern found at address: 0x%llx\n", matchAddress);
                if (*headRSL == NULL)
                {
                    *headRSL = createResultSavedNode(0, matchAddress, patLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createResultSavedNode(0, matchAddress, patLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
                j = lps[j - 1];
            }
        }
        else
        {
            if (j != 0)
            {
                j = lps[j - 1];
            }
            else
            {
                i++;
            }
        }
    }
    *addressWannaFreed = (ULONG64)lps;
}
VOID FUZZY_searchRegion(
    IN CONST PUCHAR des,
    IN SIZE_T desLen,
    IN UCHAR dataType, //[0]: 1b [1]: 2b [2]: 4b [3]: 8b [4]: float [5]: double
    IN PUCHAR lowHexPointer,
    IN PUCHAR highHexPointer,
    IN ULONG64 pageBeginAddress,
    IN PVAL headVAL,
    OUT PRSL* headRSL
)
{
    if (dataType == __TYPE_BYTE__)
    {
        SIZE_T dataLen = 1;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(PCHAR)(des + j) >= *(PCHAR)lowHexPointer && *(PCHAR)(des + j) <= *(PCHAR)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
            }
        }
    }
    else if (dataType == __TYPE_WORD__)
    {
        SIZE_T dataLen = 2;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(PSHORT)(des + j) >= *(PSHORT)lowHexPointer && *(PSHORT)(des + j) <= *(PSHORT)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
            }
        }
    }
    else if (dataType == __TYPE_DWORD__)
    {
        SIZE_T dataLen = 4;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(PINT)(des + j) >= *(PINT)lowHexPointer && *(PINT)(des + j) <= *(PINT)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
            }
        }
    }
    else if (dataType == __TYPE_QWORD__)
    {
        SIZE_T dataLen = 8;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(PULONG64)(des + j) >= *(PULONG64)lowHexPointer && *(PULONG64)(des + j) <= *(PULONG64)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
            }
        }
    }
    else if (dataType == __TYPE_FLOAT__)
    {
        SIZE_T dataLen = 4;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(float*)(des + j) >= *(float*)lowHexPointer && *(float*)(des + j) <= *(float*)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
            }
        }
    }
    else if (dataType == __TYPE_DOUBLE__)
    {
        SIZE_T dataLen = 8;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(double*)(des + j) >= *(double*)lowHexPointer && *(double*)(des + j) <= *(double*)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createResultSavedNode(0, pageBeginAddress + j, dataLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
            }
        }
    }
    else
    {
        return;
    }
}
VOID buildDoubleLinkedAddressListForScaningResult( //APC attach inline
    IN ULONG64 pid,
    IN UCHAR firstSearchMode,
    IN PSMI smi,
    IN UCHAR dataType,
    IN PVAL headVAL,
    OUT PRSL* headRSL
)
{
    if (pid == 0 || smi == NULL || headVAL == NULL)
    {
        DbgPrint("探测到空指针或者非法零值，已驳回.");
        return;
    }
    if (*headRSL != NULL)
    {
        DbgPrint("继上次搜索后，结果链表仍有残余，表明没释放干净，已驳回.");
        return;
    }
    PUCHAR cpyBuffer = NULL;
    PVAL tempVAL = headVAL;
    if (firstSearchMode == __FIRST_PRECISE_SCAN__)
    {
        if (dataType == __TYPE_FLOAT__ || dataType == __TYPE_DOUBLE__)
        {
            DbgPrint("精确搜索不支持(IEEE754)标准浮点.");
            return;
        }
        else if (dataType == __TYPE_BYTE__ || dataType == __TYPE_WORD__ || dataType == __TYPE_DWORD__ || dataType == __TYPE_QWORD__)
        {
            if (smi->preciseMode.dataLen == 0 || smi->preciseMode.value_hexBytePointer == NULL)
            {
                DbgPrint("探测到空指针或者非法零值，已驳回.");
                return;
            }
            while (tempVAL->ValidAddressEntry.Next != NULL)
            {
                PEPROCESS pe = NULL;
                KAPC_STATE apc = { 0 };
                ULONG64 addressWannaFreed = 0x0;
                cpyBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, tempVAL->regionGap, 'zyyz');
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
                {
                    KeStackAttachProcess(pe, &apc);
                    memcpy(cpyBuffer, (PVOID)tempVAL->beginAddress, tempVAL->regionGap);
                    KMP_searchPattern(
                        cpyBuffer,
                        smi->preciseMode.value_hexBytePointer,
                        tempVAL->regionGap,
                        smi->preciseMode.dataLen,
                        tempVAL->beginAddress,
                        headVAL,
                        &addressWannaFreed,
                        headRSL
                    );
                    KeUnstackDetachProcess(&apc);
                    ObDereferenceObject(pe);
                    ExFreePool(cpyBuffer);
                    cpyBuffer = NULL;
                    ExFreePool((PVOID)addressWannaFreed);
                    addressWannaFreed = 0;
                    tempVAL = CONTAINING_RECORD(tempVAL->ValidAddressEntry.Next, VAL, ValidAddressEntry);
                }
                else
                {
                    DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                    ExFreePool(cpyBuffer);
                    return;
                }
            }
        }
        else if(dataType == __TYPE_PATTERN__)
        {
            if (smi->patternMode.patternLen == 0|| smi->patternMode.pattern == NULL)
            {
                DbgPrint("探测到空指针或者非法零值，已驳回.");
                return;
            }
            while (tempVAL->ValidAddressEntry.Next != NULL)
            {
                PEPROCESS pe = NULL;
                KAPC_STATE apc = { 0 };
                ULONG64 addressWannaFreed = 0x0;
                cpyBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, tempVAL->regionGap, 'zyyz');
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
                {
                    KeStackAttachProcess(pe, &apc);
                    memcpy(cpyBuffer, (PVOID)tempVAL->beginAddress, tempVAL->regionGap);
                    KMP_searchPattern(
                        cpyBuffer,
                        smi->patternMode.pattern,
                        tempVAL->regionGap,
                        smi->patternMode.patternLen,
                        tempVAL->beginAddress,
                        headVAL,
                        &addressWannaFreed,
                        headRSL
                    );
                    KeUnstackDetachProcess(&apc);
                    ObDereferenceObject(pe);
                    ExFreePool(cpyBuffer);
                    ExFreePool((PVOID)addressWannaFreed);
                    tempVAL = CONTAINING_RECORD(tempVAL->ValidAddressEntry.Next, VAL, ValidAddressEntry);
                }
                else
                {
                    DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                    ExFreePool(cpyBuffer);
                    return;
                }
            }
        }
        else
        {
            DbgPrint("非法请求，已驳回.");
            return;
        }
    }
    else if (firstSearchMode == __FIRST_FUZZY_SCAN__)
    {
        if (dataType == __TYPE_PATTERN__)
        {
            DbgPrint("模糊搜索不支持模式串匹配.");
            return;
        }
        else if (dataType == __TYPE_BYTE__ || dataType == __TYPE_WORD__ || dataType == __TYPE_DWORD__ || dataType == __TYPE_QWORD__ || dataType == __TYPE_FLOAT__ || dataType == __TYPE_DOUBLE__)
        {
            while (tempVAL->ValidAddressEntry.Next != NULL)
            {
                PEPROCESS pe = NULL;
                KAPC_STATE apc = { 0 };
                if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
                {
                    KeStackAttachProcess(pe, &apc);
                    cpyBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, tempVAL->regionGap, 'zxxz');
                    memcpy(cpyBuffer, (PVOID)tempVAL->beginAddress, tempVAL->regionGap);
                    FUZZY_searchRegion(
                        cpyBuffer,
                        tempVAL->regionGap,
                        dataType,
                        smi->fuzzyMode.lowLimit_hexBytePointer,
                        smi->fuzzyMode.highLimit_hexBytePointer,
                        tempVAL->beginAddress,
                        headVAL,
                        headRSL
                    );
                    tempVAL = CONTAINING_RECORD(tempVAL->ValidAddressEntry.Next, VAL, ValidAddressEntry);
                    KeUnstackDetachProcess(&apc);
                    ObDereferenceObject(pe);
                }
                else
                {
                    DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                    ExFreePool(cpyBuffer);
                    return;
                }
            }
        }
        else
        {
            DbgPrint("非法请求，已驳回.");
            return;
        }
    }
    else
    {
        DbgPrint("非法请求，已驳回.");
        return;
    }
    return;
}

VOID continueSearch(
    IN ULONG64 pid,
    IN UCHAR continueSearchType,
    IN UCHAR dataType,
    IN PSMI searchInput,
    IN_OUT PRSL* headRSL
)
{
    if (*headRSL == NULL)
    {
        DbgPrint("空链表头输入，已驳回.");
        return;
    }
    LIST_ENTRY virtualListHead = { 0 };
    PLIST_ENTRY tempHead = &virtualListHead;
    PRSL Tail = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
    (*headRSL)->ResultAddressEntry.Blink = tempHead;
    tempHead->Blink = &Tail->ResultAddressEntry;
    Tail->ResultAddressEntry.Flink = tempHead;
    tempHead->Flink = &(*headRSL)->ResultAddressEntry;
    PLIST_ENTRY loopHead = tempHead;
    if (continueSearchType == __Continue_PRECISE__)
    {
        //不需要以前的buffer.需要新指针输入
        if (searchInput == NULL)
        {
            DbgPrint("[%hhx]探测到空指针，已驳回请求.", __Continue_PRECISE__);
            return;
        }
        if (dataType == __TYPE_BYTE__ || dataType == __TYPE_WORD__ || dataType == __TYPE_DWORD__ || dataType == __TYPE_QWORD__ || dataType == __TYPE_FLOAT__ || dataType == __TYPE_DOUBLE__)
        {
            if (searchInput->preciseMode.value_hexBytePointer == NULL || searchInput->preciseMode.dataLen == 0)
            {
                DbgPrint("探测到空指针或者非法零值，已驳回.");
                return;
            }
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (strncmp((CONST CHAR*)curr->address, (CONST CHAR*)searchInput->preciseMode.value_hexBytePointer, searchInput->preciseMode.dataLen) != 0)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_PATTERN__)
        {
            if (searchInput->patternMode.pattern == NULL || searchInput->patternMode.patternLen == 0)
            {
                DbgPrint("探测到空指针或者非法零值，已驳回.");
                return;
            }
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (strncmp((CONST CHAR*)curr->address, (CONST CHAR*)searchInput->patternMode.pattern, searchInput->patternMode.patternLen) != 0)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else
        {
            DbgPrint("非法请求，已驳回.");
        }
    }
    else if (continueSearchType == __Continue_LARGER__)
    {
        //需要以前的buffer.不需要新指针输入
        if (dataType == __TYPE_BYTE__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(CHAR*)curr->address <= *(CHAR*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_WORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(SHORT*)curr->address <= *(SHORT*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_DWORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(INT*)curr->address <= *(INT*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL(*headRSL);
                }
                else
                {
                    DbgPrint("empty");
                    *headRSL = NULL;
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_QWORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(LONG64*)curr->address <= *(LONG64*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_FLOAT__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(float*)curr->address <= *(float*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_DOUBLE__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(double*)curr->address <= *(double*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
    }
    else if (continueSearchType == __Continue_LOWER__)
    {
        //需要以前的buffer.不需要新指针输入
        if (dataType == __TYPE_BYTE__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(CHAR*)curr->address >= *(CHAR*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_WORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(SHORT*)curr->address >= *(SHORT*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_DWORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(INT*)curr->address >= *(INT*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL(*headRSL);
                }
                else
                {
                    DbgPrint("empty");
                    *headRSL = NULL;
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_QWORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(LONG64*)curr->address >= *(LONG64*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_FLOAT__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(float*)curr->address >= *(float*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_DOUBLE__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(double*)curr->address >= *(double*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
    }
    else if (continueSearchType == __Continue_UNCHANGED__)
    {
        //需要以前的buffer.不需要新指针输入
        if (dataType == __TYPE_BYTE__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(CHAR*)curr->address != *(CHAR*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_WORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(SHORT*)curr->address != *(SHORT*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_DWORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(INT*)curr->address != *(INT*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL(*headRSL);
                }
                else
                {
                    DbgPrint("empty");
                    *headRSL = NULL;
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_QWORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (*(LONG64*)curr->address != *(LONG64*)curr->buffer)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_FLOAT__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (mabs_float(*(float*)curr->address - *(float*)curr->buffer) > 0.1)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_DOUBLE__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (mabs_double(*(double*)curr->address - *(double*)curr->buffer) > 0.1)
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
    }
    else if (continueSearchType == __Continue_REGION__)
    {
        //不需要以前的buffer.需要新指针输入
        if (searchInput == NULL || searchInput->fuzzyMode.highLimit_hexBytePointer == NULL || searchInput->fuzzyMode.lowLimit_hexBytePointer == NULL)
        {
            DbgPrint("[%hhx]探测到空指针，已驳回请求.", __Continue_REGION__);
        }
        if (dataType == __TYPE_BYTE__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (
                        *(CHAR*)curr->address < *(CHAR*)searchInput->fuzzyMode.lowLimit_hexBytePointer
                        ||
                        *(CHAR*)curr->address > *(CHAR*)searchInput->fuzzyMode.highLimit_hexBytePointer
                        )
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_WORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (
                        *(SHORT*)curr->address < *(SHORT*)searchInput->fuzzyMode.lowLimit_hexBytePointer
                        ||
                        *(SHORT*)curr->address > *(SHORT*)searchInput->fuzzyMode.highLimit_hexBytePointer
                        )
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_DWORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (
                        *(INT*)curr->address < *(INT*)searchInput->fuzzyMode.lowLimit_hexBytePointer
                        ||
                        *(INT*)curr->address > *(INT*)searchInput->fuzzyMode.highLimit_hexBytePointer
                        )
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL(*headRSL);
                }
                else
                {
                    DbgPrint("empty");
                    *headRSL = NULL;
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_QWORD__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (
                        *(LONG64*)curr->address < *(LONG64*)searchInput->fuzzyMode.lowLimit_hexBytePointer
                        ||
                        *(LONG64*)curr->address > *(LONG64*)searchInput->fuzzyMode.highLimit_hexBytePointer
                        )
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_FLOAT__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (
                        *(float*)curr->address < *(float*)searchInput->fuzzyMode.lowLimit_hexBytePointer
                        ||
                        *(float*)curr->address > *(float*)searchInput->fuzzyMode.highLimit_hexBytePointer
                        )
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
        else if (dataType == __TYPE_DOUBLE__)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            if(NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pid, &pe)))
            {
                KeStackAttachProcess(pe, &apc);
                while (tempHead->Flink != loopHead)
                {
                    PRSL curr = CONTAINING_RECORD(tempHead->Flink, RSL, ResultAddressEntry);
                    if (
                        *(double*)curr->address < *(double*)searchInput->fuzzyMode.lowLimit_hexBytePointer
                        ||
                        *(double*)curr->address > *(double*)searchInput->fuzzyMode.highLimit_hexBytePointer
                        )
                    {
                        tempHead->Flink = tempHead->Flink->Flink;
                        tempHead->Flink->Blink = tempHead;
                        curr->ResultAddressEntry.Flink = NULL;
                        curr->ResultAddressEntry.Blink = NULL;
                        ExFreePool(curr->buffer);
                        curr->buffer = NULL;
                        ExFreePool(curr);
                        curr = NULL;
                    }
                    else
                    {
                        tempHead = tempHead->Flink;
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                if (loopHead->Flink != loopHead)
                {
                    DbgPrint("exist");
                    (*headRSL) = CONTAINING_RECORD(loopHead->Flink, RSL, ResultAddressEntry);
                    loopHead->Blink->Flink = loopHead->Flink;
                    loopHead->Flink->Blink = loopHead->Blink;
                    loopHead->Flink = NULL;
                    loopHead->Blink = NULL;
                    printListRSL((*headRSL));
                }
                else
                {
                    DbgPrint("empty");
                }
            }
            else
            {
                DbgPrint("进程寻找失败，PsLookupProcessByProcessId未成功.");
                return;
            }
        }
    }
    else
    {
        return;
    }
    return;
}

VOID checkSMI(
    IN PSMI smi
)
{
    if (smi->modeJudge == __MODE_JUDGE_PRECISE__)
    {
        for (SIZE_T j = 0; j < smi->preciseMode.dataLen; j++)
        {
            DbgPrint("%hhx", smi->preciseMode.value_hexBytePointer[j]);
        }
    }
    else if (smi->modeJudge == __MODE_JUDGE_FUZZY__)
    {
        for (SIZE_T j = 0; j < smi->fuzzyMode.dataLen; j++)
        {
            DbgPrint("%hhx", smi->fuzzyMode.lowLimit_hexBytePointer[j]);
        }
        for (SIZE_T j = 0; j < smi->fuzzyMode.dataLen; j++)
        {
            DbgPrint("%hhx", smi->fuzzyMode.highLimit_hexBytePointer[j]);
        }
    }
    else if (smi->modeJudge == __MODE_JUDGE_PATTERN__)
    {
        for (SIZE_T j = 0; j < smi->patternMode.patternLen; j++)
        {
            DbgPrint("%hhx", smi->patternMode.pattern[j]);
        }
    }
    else
    {
        DbgPrint("Non matched.");
    }
}

BOOLEAN checkAllRSLAddressLenValid(
    IN PRSL headRSL
)
{
    PRSL temp = headRSL;
    while (temp->ResultAddressEntry.Flink != &headRSL->ResultAddressEntry)
    {
        if (temp->rslAddressBufferLen == 0)
        {
            return 0;
        }
        else
        {
            temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
        }
    }
    if (temp->rslAddressBufferLen == 0)
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
    size_t cnt = 0;
    PVAL temp = headVAL;
    if (headVAL == NULL)
    {
        DbgPrint("empty list!");
        return;
    }
    while (temp->ValidAddressEntry.Next != NULL)
    {
        cnt++;
        DbgPrint("ListNodeIndex: 0x%llx, begin: 0x%p\t end: 0x%p\t regionGap: 0x%llx\t pageNums: 0x%llx\t memState: %lx\t memProtect: %lx\t executeFlag: %hhx\t", cnt, (PVOID)temp->beginAddress, (PVOID)temp->endAddress, temp->regionGap, temp->pageNums, temp->memoryState, temp->memoryProtectAttributes, temp->executeFlag);
        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    DbgPrint("ListNodeIndex: 0x%llx, begin: 0x%p\t end: 0x%p\t regionGap: 0x%llx\t pageNums: 0x%llx\t memState: %lx\t memProtect: %lx\t executeFlag: %hhx\t", cnt, (PVOID)temp->beginAddress, (PVOID)temp->endAddress, temp->regionGap, temp->pageNums, temp->memoryState, temp->memoryProtectAttributes, temp->executeFlag);
    return;
}
VOID printListRSL(
    IN PRSL headRSL
)
{
    PRSL temp = headRSL;
    if (temp == NULL || temp->buffer == NULL)
    {
        DbgPrint("empty list!");
        return;
    }
    while (temp->ResultAddressEntry.Flink != &headRSL->ResultAddressEntry)
    {
        DbgPrint("times: %ld, address: %p", temp->times, (PVOID)temp->address);
        temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
    }
    DbgPrint("times: %ld, address: %p", temp->times, (PVOID)temp->address);
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
        if (*(UCHAR*)((ULONG64)oldPattern + j) == *(UCHAR*)((ULONG64)newPattern + j))
        {
            continue;
        }
        else
        {
            return ((*(UCHAR*)((ULONG64)oldPattern + j)) >= *((UCHAR*)((ULONG64)newPattern + j))) ? 1 : 2;
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
        if (tempRSL->buffer)
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
/*内存泄露问题！
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
