#include "DebugeeHeader.h"

#pragma warning(disable:6387)

VOID KernelDriverThreadSleep(
    IN LONG msec
)
{
    LARGE_INTEGER my_interval;
    my_interval.QuadPart = DELAY_ONE_MILLISECOND;
    my_interval.QuadPart *= msec;
    KeDelayExecutionThread(KernelMode, 0, &my_interval);
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
PHPL createHiddenProcessNode(
    IN ULONG64 pidOfHiddenProcess,
    IN PEPROCESS eprocessHeaderOfHiddenProcess,
    IN PLIST_ENTRY prevEntryAddress,
    IN PLIST_ENTRY nextEntryAddress
)
{
    PHPL newNode = (PHPL)ExAllocatePoolWithTag(PagedPool, sizeof(HPL), 'ssss');
    if (newNode)
    {
        newNode->pidAlreadyHidden = pidOfHiddenProcess;
        newNode->eprocessHeaderAddressOfHiddenProcess = eprocessHeaderOfHiddenProcess;
        newNode->prevProcessEntry = prevEntryAddress;
        newNode->nextProcessEntry = nextEntryAddress;
        newNode->HiddenProcessEntry.Flink = NULL;
        newNode->HiddenProcessEntry.Blink = NULL;
    }
    return newNode;
}
PPPL createPretentProcessNode(
    IN ULONG64 dirtyPID,
    IN ULONG64 parasitePID
)
{
    PPPL newNode = (PPPL)ExAllocatePoolWithTag(PagedPool, sizeof(PPL), 'rrrr');
    if (newNode)
    {
        newNode->dirtyPID = dirtyPID;
        newNode->parasitePID = parasitePID;
        newNode->PretentProcessEntry.Flink = NULL;
        newNode->PretentProcessEntry.Blink = NULL;
    }
    return newNode;
}
VOID computeLPSArray(
    IN CONST UCHAR* pattern,
    IN UL64 M,
    OUT UL64* lps
)
{
    UL64 len = 0;
    lps[0] = 0;
    SIZE_T i = 1;
    while (i < M)
    {
        if (pattern[i] == pattern[len])
        {
            len++;
            lps[i] = len;
            i++;
        }
        else
        {
            if (len != 0)
            {
                len = lps[len - 1];
            }
            else
            {
                lps[i] = len;
                i++;
            }
        }
    }
}
VOID KMP_searchPattern(
    IN CONST UCHAR* des,
    IN CONST UCHAR* pattern,
    IN SIZE_T desLen,
    IN SIZE_T patLen,
    IN ULONG64 pageBeginAddress,
    IN PVAL headVAL,
    OUT UL64* lpsAddress,
    OUT PRSL* headRSL
)
{
    UL64 M = patLen;
    UL64 N = desLen;
    UL64* lps = (UL64*)ExAllocatePoolWithTag(PagedPool, M * sizeof(UL64), 'wwww');
    UL64 j = 0;
    computeLPSArray(pattern, M, lps);
    SIZE_T i = 0;
    while (i < N)
    {
        if (pattern[j] == des[i])
        {
            j++;
            i++;
        }
        if (j == M && lps)
        {
            //DbgPrint("在地址%llx匹配成功\n", (ULONG64)(pageBeginAddress + i - j));
            if (*headRSL == NULL)
            {
                *headRSL = createSavedResultNode(1, (ULONG64)(pageBeginAddress + i - j), patLen, headVAL);
                if (*headRSL)
                {
                    (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    (*headRSL)->ResultAddressEntry.Blink = (*headRSL)->ResultAddressEntry.Flink;
                }
            }
            else
            {
                PRSL temp = *headRSL;
                while (temp->ResultAddressEntry.Flink != &((*headRSL)->ResultAddressEntry))
                {
                    temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
                }
                PRSL newNode = createSavedResultNode(1, (ULONG64)(pageBeginAddress + i - j), patLen, headVAL);
                if (newNode)
                {
                    temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                    newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                    (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                }
            }
            j = lps[j - 1];
        }
        else if (i < N && pattern[j] != des[i])
        {
            if (j != 0 && lps)
            {
                j = lps[j - 1];
            }
            else
            {
                i = i + 1;
            }
        }
    }
    *lpsAddress = (UL64)lps;
}
BOOLEAN isSame(
    IN PUCHAR A,
    IN PUCHAR B,
    IN SIZE_T size
)
{
    for (size_t j = 0; j < size; j++)
    {
        if (A[j] != B[j])
        {
            return 0;
        }
        else
        {
            continue;
        }
    }
    return 1;
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
        DbgPrint("ListNodeIndex: 0x%llx, begin: 0x%p\t end: 0x%p\t regionGap: 0x%llx\t pageNums: 0x%llx\t memState: %lx\t memProtect: %lx\t", cnt, (PVOID)temp->beginAddress, (PVOID)temp->endAddress, temp->regionGap, temp->pageNums, temp->memoryState, temp->memoryProtectAttributes);
        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    DbgPrint("ListNodeIndex: 0x%llx, begin: 0x%p\t end: 0x%p\t regionGap: 0x%llx\t pageNums: 0x%llx\t memState: %lx\t memProtect: %lx\t", cnt, (PVOID)temp->beginAddress, (PVOID)temp->endAddress, temp->regionGap, temp->pageNums, temp->memoryState, temp->memoryProtectAttributes);
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
        temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
    }
    DbgPrint("times: %ld, address: %p", temp->times, (PVOID)temp->address);
    for (size_t j = 0; j < temp->rslAddressBufferLen; j++)
    {
        DbgPrint("%hhx", temp->buffer[j]);
    }
}
VOID printListHPL(
    IN PHPL headHPL
)
{
    PHPL temp = headHPL;
    while (temp->HiddenProcessEntry.Flink != &headHPL->HiddenProcessEntry)
    {
        DbgPrint("Hidden processes pid: %llx, eprocess header address: 0x%p, prevEntryAddress: 0x%p, nextEntryAddress: 0x%p", (ULONG64)temp->pidAlreadyHidden, (PVOID)temp->eprocessHeaderAddressOfHiddenProcess, (PVOID)temp->prevProcessEntry, (PVOID)temp->nextProcessEntry);
        temp = CONTAINING_RECORD(temp->HiddenProcessEntry.Flink, HPL, HiddenProcessEntry);
    }
    DbgPrint("Hidden processes pid: %llx, eprocess header address: 0x%p, prevEntryAddress: 0x%p, nextEntryAddress: 0x%p", (ULONG64)temp->pidAlreadyHidden, (PVOID)temp->eprocessHeaderAddressOfHiddenProcess, (PVOID)temp->prevProcessEntry, (PVOID)temp->nextProcessEntry);
}
VOID printListPPL(
    IN PPPL headPPL
)
{
    PPPL temp = headPPL;
    while (temp->PretentProcessEntry.Flink != &headPPL->PretentProcessEntry)
    {
        DbgPrint("Pretent process pid: %llu, parasite process pid: %llu", temp->dirtyPID, temp->parasitePID);
        temp = CONTAINING_RECORD(temp->PretentProcessEntry.Flink, PPL, PretentProcessEntry);
    }
    DbgPrint("Pretent process pid: %llu, parasite process pid: %llu", temp->dirtyPID, temp->parasitePID);
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
                    if (pmbi->Protect == 0x10)
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
                    if (pmbi->Protect == 0x10)
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
VOID buildDoubleLinkedAddressListForPatternStringByKMPAlgorithm(
    IN ULONG64 pid,
    IN PVAL headVAL,
    IN PUCHAR pattern,
    IN SIZE_T patternLen,
    OUT PRSL* headRSL
)
{
    PVAL temp = headVAL;
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KAPC_STATE apc = { 0 };
    KeStackAttachProcess(pe, &apc);
    while (temp->ValidAddressEntry.Next != NULL)
    {
        UCHAR* bufferReceive = (UCHAR*)ExAllocatePoolWithTag(PagedPool, temp->pageNums * 4096, 'qqqq');
        UL64 addressNeedFree = 0x0;
        __try
        {
            memcpy(bufferReceive, (PVOID)temp->beginAddress, temp->pageNums * 4096);
        }
        __except (1)
        {
            ExFreePool(bufferReceive);
            temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
            continue; //此时出现bugcheck导致KMP搜索不会执行，因此也不会分配next数组内存，因此不用ExFreePool(addressNeedFree)，直接进行下一个链表节点就行了。
            //[!]【在except结束后，要么加上return STATUS_UNSUCCESSFUL！要么goto到下一块！双重detachAPC会蓝屏，而且此BUG不是次次都有，不定时出现！】
        }
        KMP_searchPattern((CONST UCHAR*)bufferReceive, (CONST UCHAR*)pattern, temp->pageNums * 4096, patternLen, temp->beginAddress, headVAL, &addressNeedFree, headRSL);
        ExFreePool((PVOID)bufferReceive); bufferReceive = NULL;
        ExFreePool((PVOID)addressNeedFree); addressNeedFree = (UL64)NULL;
        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
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
VOID writeProcessMemory(
    IN ULONG64 pid,
    IN PVOID targetAddress,
    IN PVOID content,
    IN SIZE_T size
)
{
    ULONG64 oldCR0 = 0x0;
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId((HANDLE)pid, &pe);
    KAPC_STATE apc = { 0 };
    KeStackAttachProcess(pe, &apc);
    __asm__WRbreak(&oldCR0);
    RtlCopyMemory(targetAddress, content, size);
    __asm__WRrestore(oldCR0);
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    return;
}
VOID processHiddenProcedure(
    IN ULONG64 pid,
    IN PHPL* headHPL
)
{
    PEPROCESS pe = IoGetCurrentProcess();
    ULONG64 UniqueProcessIdOffset = 0x440;
    ULONG64 ActiveProcessLinksOffset = 0x448;
    PLIST_ENTRY thisPeNode = NULL;
    while (*(ULONG64*)((ULONG64)pe + UniqueProcessIdOffset) != pid)
    {
        thisPeNode = (PLIST_ENTRY)((ULONG64)pe + ActiveProcessLinksOffset);
        pe = (PEPROCESS)((UL64)thisPeNode->Flink - ActiveProcessLinksOffset);
    }
    //DbgPrint("***%p***", *(HANDLE*)((ULONG64)pe + UniqueProcessIdOffset));
    //这个pe就是目标pid的进程，接下来是断链隐藏
    PLIST_ENTRY currPeListEntryAddress = (PLIST_ENTRY)((UL64)pe + ActiveProcessLinksOffset);
    PLIST_ENTRY prevPeListEntryAddress = currPeListEntryAddress->Blink;
    PLIST_ENTRY nextPeListEntryAddress = currPeListEntryAddress->Flink;
    prevPeListEntryAddress->Flink = nextPeListEntryAddress;
    nextPeListEntryAddress->Blink = prevPeListEntryAddress;
    if (*headHPL == NULL)
    {
        PHPL newNode = createHiddenProcessNode((ULONG64)pid, pe, prevPeListEntryAddress, nextPeListEntryAddress);
        (*headHPL) = newNode;
        (*headHPL)->HiddenProcessEntry.Flink = &((*headHPL)->HiddenProcessEntry);
        (*headHPL)->HiddenProcessEntry.Blink = (*headHPL)->HiddenProcessEntry.Flink;
    }
    else
    {
        PHPL temp = *headHPL;
        while (temp->HiddenProcessEntry.Flink != &((*headHPL)->HiddenProcessEntry))
        {
            temp = CONTAINING_RECORD(temp->HiddenProcessEntry.Flink, HPL, HiddenProcessEntry);
        }
        PHPL newNode = createHiddenProcessNode((ULONG64)pid, pe, prevPeListEntryAddress, nextPeListEntryAddress);
        if (newNode)
        {
            temp->HiddenProcessEntry.Flink = &newNode->HiddenProcessEntry;
            newNode->HiddenProcessEntry.Flink = &((*headHPL)->HiddenProcessEntry);
            newNode->HiddenProcessEntry.Blink = &temp->HiddenProcessEntry;
            (*headHPL)->HiddenProcessEntry.Blink = &newNode->HiddenProcessEntry;
        }
    }
    DbgPrint("进程0x%p(%llu)已经断链隐藏.", (PVOID)pid, pid);
    return;
}
VOID restoreHiddenProcess(
    IN PHPL headHPL
)
{
    PHPL temp = headHPL;
    ULONG64 activeProcessLinksAddress = 0x448;
    PLIST_ENTRY thisNodePrevNodeEntryAddress = temp->prevProcessEntry;
    PLIST_ENTRY thisNodeEntryAddress = (PLIST_ENTRY)((ULONG64)temp->eprocessHeaderAddressOfHiddenProcess + activeProcessLinksAddress);
    PLIST_ENTRY thisNodeNextNodeEntryAddress = temp->nextProcessEntry;
    while (temp->HiddenProcessEntry.Flink != &headHPL->HiddenProcessEntry)
    {
        temp->prevProcessEntry->Flink = thisNodeEntryAddress;
        thisNodeEntryAddress->Flink = thisNodeNextNodeEntryAddress;
        thisNodeNextNodeEntryAddress->Blink = thisNodeEntryAddress;
        thisNodeEntryAddress->Blink = thisNodePrevNodeEntryAddress;
        temp = CONTAINING_RECORD(temp->HiddenProcessEntry.Flink, HPL, HiddenProcessEntry);
    }
    temp->prevProcessEntry->Flink = thisNodeEntryAddress;
    thisNodeEntryAddress->Flink = thisNodeNextNodeEntryAddress;
    thisNodeNextNodeEntryAddress->Blink = thisNodeEntryAddress;
    thisNodeEntryAddress->Blink = thisNodePrevNodeEntryAddress;
}
VOID processPretentProcedure(
    IN HANDLE dirtyPID,
    IN HANDLE parasitePID,
    OUT PPPL* headPPL
)
{
    ULONG64 uniqueProcessIDOffset = 0x440;
    PEPROCESS dirtyPE = NULL;
    PsLookupProcessByProcessId((HANDLE)dirtyPID, &dirtyPE);
    ULONG64 dirtyPIDAddress = (ULONG64)dirtyPE + uniqueProcessIDOffset;
    ULONG64 tempParasitePid = (ULONG64)parasitePID;
    ULONG64 oldCR0 = 0x0;
    __asm__WRbreak(&oldCR0);
    memcpy((PVOID)dirtyPIDAddress, (PVOID)&tempParasitePid, sizeof(HANDLE));
    __asm__WRrestore(oldCR0);
    if (*headPPL == NULL)
    {
        *headPPL = createPretentProcessNode(
            (ULONG64)dirtyPID,
            (ULONG64)parasitePID
        );
        (*headPPL)->PretentProcessEntry.Flink = &((*headPPL)->PretentProcessEntry);
        (*headPPL)->PretentProcessEntry.Blink = (*headPPL)->PretentProcessEntry.Flink;
    }
    else
    {
        PPPL temp = *headPPL;
        while (temp->PretentProcessEntry.Flink != &((*headPPL)->PretentProcessEntry))
        {
            temp = CONTAINING_RECORD(temp->PretentProcessEntry.Flink, PPL, PretentProcessEntry);
        }
        PPPL newNode = createPretentProcessNode(
            (ULONG64)dirtyPID,
            (ULONG64)parasitePID
        );
        if (newNode)
        {
            temp->PretentProcessEntry.Flink = &newNode->PretentProcessEntry;
            newNode->PretentProcessEntry.Flink = &((*headPPL)->PretentProcessEntry);
            newNode->PretentProcessEntry.Blink = &temp->PretentProcessEntry;
            (*headPPL)->PretentProcessEntry.Blink = &newNode->PretentProcessEntry;
        }
    }
    return;
}
VOID restorePretentProcess(
    IN PPPL headPPL
)
{
    PPPL temp = headPPL;
    while (temp->PretentProcessEntry.Flink != &headPPL->PretentProcessEntry)
    {
        PEPROCESS dirtyPE = NULL;
        PsLookupProcessByProcessId((HANDLE)temp->dirtyPID, &dirtyPE);
        ULONG64 tempDirtyPid = temp->dirtyPID;
        ULONG64 oldCR0 = 0x0;
        __asm__WRbreak(&oldCR0);
        //KeBugCheckEx(0x22222222, 0, 0, 0, 0);
        memcpy((PVOID)((ULONG64)dirtyPE + 0x440), (PVOID)&tempDirtyPid, sizeof(HANDLE));
        //KeBugCheckEx(0x33333333, 0, 0, 0, 0);
        __asm__WRrestore(oldCR0);
        ObDereferenceObject(dirtyPE);
        temp = CONTAINING_RECORD(temp->PretentProcessEntry.Flink, PPL, PretentProcessEntry);
    }
    PEPROCESS dirtyPE = NULL;
    PsLookupProcessByProcessId((HANDLE)temp->dirtyPID, &dirtyPE);
    ULONG64 tempDirtyPid = temp->dirtyPID;
    ULONG64 oldCR0 = 0x0;
    __asm__WRbreak(&oldCR0);
    //KeBugCheckEx(0x22222222, 0, 0, 0, 0);
    memcpy((PVOID)((ULONG64)dirtyPE + 0x440), (PVOID)&tempDirtyPid, sizeof(HANDLE));
    //KeBugCheckEx(0x33333333, 0, 0, 0, 0);
    __asm__WRrestore(oldCR0);
    ObDereferenceObject(dirtyPE);
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
NTSTATUS MyNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
)
{
    if (ClientId->UniqueProcess == (HANDLE)4132)
    {
        *ProcessHandle = NULL;
        return STATUS_UNSUCCESSFUL;
    }
    else
    {
        return NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
}
VOID protectProcessProcedure(
)
{
    ULONG NtOpenProcessFunctionIndex = 38; //0x26
    ULONG64 KiSystemCall64ShadowAddress = __asm__readMSR(0xC0000082);
    ULONG64 KiSystemServiceStart = KiSystemCall64ShadowAddress - 0x6073C0 + 0x370; //Windows10 x64 22H2 Only.
    ULONG64 KiSystemServiceRepeat = KiSystemServiceStart + 0x14;
    ULONG64 currentRIPAddress = KiSystemServiceRepeat + 14; //注意是加14，因为RIP存着该指令的下一条指令所在的地址而不是此指令的地址！
    ULONG keyOffset = *(ULONG*)(KiSystemServiceRepeat + 10); //取得0x008ea8ae这个关键偏移，此偏移加上此指令的地址就可以得到SSDT表的地址.
    //KiSystemServiceRepeat      : 4c 8d 15 35 f7 9e 00  
    //--->4c 8d 15 35 f7 9e 00    lea    r10,[rip+0x9ef735]        # nt!KeServiceDescriptorTable (0xfffff807512018c0)
    //KiSystemServiceRepeat + 0x7: 4c 8d 1d ae a8 8e 00  
    //--->4c 8d 1d ae a8 8e 00    lea    r11,[rip+0x8ea8ae]        # nt!KeServiceDescriptorTableShadow (0xfffff807510fca40)
    ULONG64 SSDT_Address = currentRIPAddress + keyOffset;
    /*typedef struct _SYSTEM_SERVICE_DISCRIPTION_TABLE 
    {
        + 0x00 -> ServiceTableBase;
        + 0x08 -> ServiceCounterTableBase;
        + 0x10 -> NumberOfServices;
        +0x18  -> ParamTableBase;
    };*/
    ULONG64 SSDT_ServiceTableBase = *(ULONG64*)SSDT_Address;
    //算法：ServiceTableBase[index] >> 4 + ServiceTableBase = "第index个导出函数的首地址".
    ULONG64 NtOpenProcessAddress = (ULONG64)(((*(ULONG*)(SSDT_ServiceTableBase + NtOpenProcessFunctionIndex * 4)) >> 4) + SSDT_ServiceTableBase);
    ULONG64 MyNtOpenProcessAddress = (ULONG64)MyNtOpenProcess;
    UCHAR* pointer = (UCHAR*)&MyNtOpenProcessAddress; //把地址转化成八个单独的字节，存入shellCode
    UCHAR shellCode[12] =
    {
        0x48, 0xB8, pointer[0], pointer[1], pointer[2], pointer[3], pointer[4], pointer[5], pointer[6], pointer[7],
        //mov rax, qword ptr [(_longlong64)pointer_(MyNtOpenProcessAddress)]
        0xFF, 0xE0
        //jmp rax
    };
    SIZE_T shellCodeSize = 12;
    ULONG64 oldCR0 = 0x0;
    __asm__WRbreak(&oldCR0);
    memcpy((PVOID)(NtOpenProcessAddress - shellCodeSize - 1), shellCode, shellCodeSize); //仅在本机器上可用，本机器上确实在NTOPENPROCESS上方存在13个0xCC字节！
    __asm__WRrestore(oldCR0);
    ULONG64 differ = NtOpenProcessAddress - shellCodeSize - 1 - SSDT_ServiceTableBase;
    //本机能保证differ（也就是NtOpenProcessAddress和SSDT_ServiceTableBase的差值）一定不能高于四字节能存储的最大值！
    ULONG targetIndexOffset = (*(ULONG*)&differ) << 4; //0x05B48B30 (0x005B48B3 << 4)
    UCHAR* pointer2targetIndexOffset = (UCHAR*) & targetIndexOffset;
    //pointer2targetIndexOffset -> 30 8B B4 05 00 00 00 00
    UCHAR myNtOpenProcessOffset[4] =
    {
        pointer2targetIndexOffset[0],
        pointer2targetIndexOffset[1],
        pointer2targetIndexOffset[2],
        pointer2targetIndexOffset[3]
    };
    SIZE_T __Nt__Type__FunctionUniformSize = 4;
    oldCR0 = 0x0;
    __asm__WRbreak(&oldCR0);
    memcpy((PVOID)(SSDT_ServiceTableBase + (ULONG64)(NtOpenProcessFunctionIndex * __Nt__Type__FunctionUniformSize)), myNtOpenProcessOffset, __Nt__Type__FunctionUniformSize);
    __asm__WRrestore(oldCR0);
    return;
}
VOID protectProcessRestore(
)
{
    ULONG NtOpenProcessFunctionIndex = 38; 
    ULONG64 KiSystemCall64ShadowAddress = __asm__readMSR(0xC0000082);
    ULONG64 KiSystemServiceStart = KiSystemCall64ShadowAddress - 0x6073C0 + 0x370; 
    ULONG64 KiSystemServiceRepeat = KiSystemServiceStart + 0x14;
    ULONG64 currentRIPAddress = KiSystemServiceRepeat + 14; 
    ULONG keyOffset = *(ULONG*)(KiSystemServiceRepeat + 10); 
    ULONG64 SSDT_Address = currentRIPAddress + keyOffset;
    ULONG64 SSDT_ServiceTableBase = *(ULONG64*)SSDT_Address;
    ULONG64 NtOpenProcessAddress = (ULONG64)(((*(ULONG*)(SSDT_ServiceTableBase + NtOpenProcessFunctionIndex * 4)) >> 4) + SSDT_ServiceTableBase);
    UCHAR restoreINT3Code[12] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
    SIZE_T shellCodeSize = 12;
    ULONG64 oldCR0 = 0x0;
    __asm__WRbreak(&oldCR0);
    memcpy((PVOID)(NtOpenProcessAddress), restoreINT3Code, shellCodeSize); 
    __asm__WRrestore(oldCR0);
    UCHAR restoreNtOpenProcessOffset[4] =
    {
        0x00, 0x8c, 0xb4, 0x05
    };
    SIZE_T __Nt__Type__FunctionUniformSize = 4;
    oldCR0 = 0x0;
    __asm__WRbreak(&oldCR0);
    memcpy((PVOID)(SSDT_ServiceTableBase + (ULONG64)(NtOpenProcessFunctionIndex * __Nt__Type__FunctionUniformSize)), restoreNtOpenProcessOffset, __Nt__Type__FunctionUniformSize);
    __asm__WRrestore(oldCR0);
    return;
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
VOID ExFreeHiddenProcessLink(
    OUT PHPL* headHPL
)
{
    PHPL tempHPL = *headHPL;
    while (tempHPL != NULL && tempHPL->HiddenProcessEntry.Flink != NULL)
    {
        PHPL tempX = CONTAINING_RECORD(tempHPL->HiddenProcessEntry.Flink, HPL, HiddenProcessEntry);
        tempHPL->HiddenProcessEntry.Flink = NULL;
        tempHPL->HiddenProcessEntry.Blink = NULL;
        ExFreePool(tempHPL);
        tempHPL = tempX;
    }
}
VOID ExFreePretentProcessLink(
    OUT PPPL* headPPL
)
{
    PPPL tempPPL = *headPPL;
    while (tempPPL != NULL && tempPPL->PretentProcessEntry.Flink != NULL)
    {
        PPPL tempX = CONTAINING_RECORD(tempPPL->PretentProcessEntry.Flink, PPL, PretentProcessEntry);
        tempPPL->PretentProcessEntry.Flink = NULL;
        tempPPL->PretentProcessEntry.Blink = NULL;
        ExFreePool(tempPPL);
        tempPPL = tempX;
    }
}
