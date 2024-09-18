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
    PVAL newNode = (PVAL)ExAllocatePoolWithTag(PagedPool, sizeof(VAL), 'WWWW');
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
PRSL createSavedResultNode(
    IN ULONG times,
    IN ULONG64 address,
    IN ULONG64 addressBufferLen,
    IN PVAL headVAL
)
{
    PRSL newNode = (PRSL)ExAllocatePoolWithTag(PagedPool, sizeof(RSL), 'VVVV');
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
            if(newNode->address + newNode->rslAddressBufferLen <= newNode->thisNodeAddressPageMaxValidAddress)
            {
                newNode->buffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, newNode->rslAddressBufferLen, 'DDDD');
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
    PRSL headRSL
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
VOID ReadBuffer(
    IN PVOID bufferHead,
    IN SIZE_T size
)
{
    ULONG64 temp = (ULONG64)bufferHead;
    for (size_t j = 0; j < size - 16; j += 16)
    {
        DbgPrint("%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t%hhx\t",
            *(UCHAR*)(temp + j + 0),
            *(UCHAR*)(temp + j + 1),
            *(UCHAR*)(temp + j + 2),
            *(UCHAR*)(temp + j + 3),
            *(UCHAR*)(temp + j + 4),
            *(UCHAR*)(temp + j + 5),
            *(UCHAR*)(temp + j + 6),
            *(UCHAR*)(temp + j + 7),
            *(UCHAR*)(temp + j + 8),
            *(UCHAR*)(temp + j + 9),
            *(UCHAR*)(temp + j + 10),
            *(UCHAR*)(temp + j + 11),
            *(UCHAR*)(temp + j + 12),
            *(UCHAR*)(temp + j + 13),
            *(UCHAR*)(temp + j + 14),
            *(UCHAR*)(temp + j + 15)
        );
    }
}
UCHAR farBytesDiffer(
    PUCHAR oldPattern,
    PUCHAR newPattern,
    SIZE_T minSize
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
        UCHAR* bufferReceive = (UCHAR*)ExAllocatePoolWithTag(PagedPool, temp->pageNums * 4096, 'TTTT');
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
VOID processHiddenProcedure(
    IN ULONG64 pid
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
    DbgPrint("***%p***", *(HANDLE*)((ULONG64)pe + UniqueProcessIdOffset));
    //这个pe就是目标pid的进程，接下来是断链隐藏
    PLIST_ENTRY currPeListEntryAddress = (PLIST_ENTRY)((UL64)pe + ActiveProcessLinksOffset);
    PLIST_ENTRY prevPeListEntryAddress = currPeListEntryAddress->Blink;
    PLIST_ENTRY nextPeListEntryAddress = currPeListEntryAddress->Flink;
    prevPeListEntryAddress->Flink = nextPeListEntryAddress;
    nextPeListEntryAddress->Blink = prevPeListEntryAddress;
    DbgPrint("进程0x%p(%llu)已经断链隐藏.", (PVOID)pid, pid);
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
    while((UL64)temp != (ULONG64)initialEntryAddress->Blink)
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
        DbgPrint("%p", ((PCLIENT_ID)cidAddress)->UniqueThread);
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
VOID processPretent(
    IN HANDLE pid_dirty,
    IN HANDLE pid_clean,
    OUT PEPROCESS* dirtyPEmark
)
{
    PEPROCESS pe = NULL;
    PsLookupProcessByProcessId((HANDLE)pid_dirty, &pe);
    *dirtyPEmark = pe;
    ULONG64 uniqueProcessIDOffset = 0x440;
    ULONG64 pidDirtyAddress = (ULONG64)pe + uniqueProcessIDOffset;
    ULONG64 pidCleanSaved = (ULONG64)pid_clean;
    ULONG64 oldCR0 = 0x0; 
    __asm__WRbreak(&oldCR0); 
    memcpy((PVOID)pidDirtyAddress, (PVOID)&pidCleanSaved, sizeof(HANDLE)); 
    __asm__WRrestore(oldCR0);
    return;
}
VOID processPretentRestore(
    IN PEPROCESS dirtyPE,
    IN HANDLE pid_dirty
)
{
    ULONG64 pid = (ULONG64)pid_dirty;
    ULONG64 oldCR0 = 0x0;
    __asm__WRbreak(&oldCR0);
    memcpy((PVOID)((ULONG64)dirtyPE + 0x440), (PVOID)&pid, sizeof(HANDLE));
    DbgPrint("%p", *(HANDLE*)((ULONG64)dirtyPE + 0x440));
    __asm__WRrestore(oldCR0);
    return;
}
VOID readImagePathNameAndCommandLine(
    HANDLE pid
)
{
    //有时应该蓝屏但是没蓝屏：看看下没下内核断点KdBreakPoint！！
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
