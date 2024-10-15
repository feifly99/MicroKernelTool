#include "MemoryScannerHeader.h"

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
PRSL createSavedResultNode(
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
                    *headRSL = createSavedResultNode(0, matchAddress, patLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createSavedResultNode(0, matchAddress, patLen, headVAL);
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
    if (dataType == 0)
    {
        SIZE_T dataLen = 1;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(PCHAR)(des + j) >= *(PCHAR)lowHexPointer && *(PCHAR)(des + j) <= *(PCHAR)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
            }
        }
    }
    else if (dataType == 1)
    {
        SIZE_T dataLen = 2;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(PSHORT)(des + j) >= *(PSHORT)lowHexPointer && *(PSHORT)(des + j) <= *(PSHORT)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
            }
        }
    }
    else if (dataType == 2)
    {
        SIZE_T dataLen = 4;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(PINT)(des + j) >= *(PINT)lowHexPointer && *(PINT)(des + j) <= *(PINT)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
            }
        }
    }
    else if (dataType == 3)
    {
        SIZE_T dataLen = 8;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(PULONG64)(des + j) >= *(PULONG64)lowHexPointer && *(PULONG64)(des + j) <= *(PULONG64)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
            }
        }
    }
    else if (dataType == 4)
    {
        SIZE_T dataLen = 4;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(float*)(des + j) >= *(float*)lowHexPointer && *(float*)(des + j) <= *(float*)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
                    tempRSL->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Blink = &tempRSL->ResultAddressEntry;
                }
            }
        }
    }
    else if (dataType == 5)
    {
        SIZE_T dataLen = 8;
        for (SIZE_T j = 0; j < desLen - dataLen + 1; j++)
        {
            if (*(double*)(des + j) >= *(double*)lowHexPointer && *(double*)(des + j) <= *(double*)highHexPointer)
            {
                if (*headRSL == NULL)
                {
                    *headRSL = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
                    if (*headRSL)
                    {
                        (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                        (*headRSL)->ResultAddressEntry.Blink = &((*headRSL)->ResultAddressEntry);
                    }
                }
                else
                {
                    PRSL tempRSL = CONTAINING_RECORD((*headRSL)->ResultAddressEntry.Blink, RSL, ResultAddressEntry);
                    PRSL newNode = createSavedResultNode(0, pageBeginAddress + j, dataLen, headVAL);
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
    while (temp->ResultAddressEntry.Flink != &headRSL->ResultAddressEntry)
    {
        DbgPrint("times: %ld, address: %p", temp->times, (PVOID)temp->address);
        /*for (size_t j = 0; j < temp->rslAddressBufferLen; j++)
        {
            DbgPrint("%hhx", temp->buffer[j]);
        }*/
        temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
    }
    DbgPrint("times: %ld, address: %p", temp->times, (PVOID)temp->address);
    /*for (size_t j = 0; j < temp->rslAddressBufferLen; j++)
    {
        DbgPrint("%hhx", temp->buffer[j]);
    }*/
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
VOID buildDoubleLinkedAddressListForScaningResult(
    IN UCHAR searchMode, //[0]: precise search [1]: fuzzy search
    IN ULONG64 pid,
    IN PVAL headVAL,
    IN PSMI searchInput,
    OUT PRSL* headRSL
)
{
    PUCHAR cpyBuffer = NULL;
    PVAL tempVAL = headVAL;
    if (searchMode == 0)
    {
        while (tempVAL->ValidAddressEntry.Next != NULL)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            PsLookupProcessByProcessId((HANDLE)pid, &pe);
            KeStackAttachProcess(pe, &apc);
            ULONG64 addressWannaFreed = 0x0;
            cpyBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, tempVAL->regionGap, 'zyyz');
            memcpy(cpyBuffer, (PVOID)tempVAL->beginAddress, tempVAL->regionGap);
            KMP_searchPattern(
                cpyBuffer,
                searchInput->preciseMode.value_hexBytePointer,
                tempVAL->regionGap,
                searchInput->preciseMode.dataLen,
                tempVAL->beginAddress,
                headVAL,
                &addressWannaFreed,
                headRSL
            );
            tempVAL = CONTAINING_RECORD(tempVAL->ValidAddressEntry.Next, VAL, ValidAddressEntry);
            ExFreePool(cpyBuffer);
            ExFreePool((PVOID)addressWannaFreed);
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(pe);
        }
    }
    else if (searchMode == 1)
    {
        while (tempVAL->ValidAddressEntry.Next != NULL)
        {
            PEPROCESS pe = NULL;
            KAPC_STATE apc = { 0 };
            PsLookupProcessByProcessId((HANDLE)pid, &pe);
            KeStackAttachProcess(pe, &apc);
            cpyBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, tempVAL->regionGap, 'zxxz');
            memcpy(cpyBuffer, (PVOID)tempVAL->beginAddress, tempVAL->regionGap);
            FUZZY_searchRegion(
                cpyBuffer,
                tempVAL->regionGap,
                2,
                searchInput->fuzzyMode.lowLimit_hexBytePointer,
                searchInput->fuzzyMode.highLimit_hexBytePointer,
                tempVAL->beginAddress,
                headVAL,
                headRSL
            );
            tempVAL = CONTAINING_RECORD(tempVAL->ValidAddressEntry.Next, VAL, ValidAddressEntry);
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(pe);
        }
    }
    else
    {
        return;
    }
}
VOID ExFreeResultSavedLink(
    OUT PRSL* headRSL
)
{
    PRSL tempRSL = *headRSL;
    while (tempRSL != NULL && tempRSL->ResultAddressEntry.Flink != NULL)
    {
        //[!]一定要有tempRSL != NULL这句！因为当temp == NULL的时候，tempRSL->ResultAddressEntry.Flink != NULL隐含了一个指针访问操作，会蓝屏！！
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
