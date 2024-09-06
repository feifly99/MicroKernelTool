#include <ntifs.h> 
#include <ntddk.h>
#include <wdm.h>
#include <vadefs.h>

#pragma warning(disable:6387)
#pragma warning(disable:6011)

typedef ULONG64 UL64;

#define onceReadPagesCount 64

#define DELAY_ONE_MICROSECOND     (-10)
#define DELAY_ONE_MILLISECOND    (DELAY_ONE_MICROSECOND*1000)

VOID KernelDriverThreadSleep(LONG msec)
{
    LARGE_INTEGER my_interval;
    my_interval.QuadPart = DELAY_ONE_MILLISECOND;
    my_interval.QuadPart *= msec;
    KeDelayExecutionThread(KernelMode, 0, &my_interval);
}
typedef struct _ValidAddressLink
{
    ULONG64 beginAddress;
    ULONG64 endAddress;
    ULONG memoryState;
    ULONG memoryProtectAttributes;
    BOOLEAN executeFlag;
    ULONG64 regionGap;
    ULONG64 pageNums;
    SINGLE_LIST_ENTRY ValidAddressEntry;
}VAL, * PVAL;

typedef struct _ResultSavedLink
{
    ULONG times;
    ULONG64 address;
    LIST_ENTRY ResultAddressEntry;
}RSL, *PRSL, **PPRSL;

PVAL createNode(ULONG64 begin, ULONG64 end, ULONG memState, ULONG memProtectAttributes, BOOLEAN executeFlag)
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

PRSL createResultNode(ULONG times, ULONG64 address)
{
    PRSL newNode = (PRSL)ExAllocatePoolWithTag(PagedPool, sizeof(RSL), 'VVVV');
    if(newNode)
    {
        newNode->times = times;
        newNode->address = address;
        newNode->ResultAddressEntry.Flink = NULL;
        newNode->ResultAddressEntry.Blink = NULL;
    }
    return newNode;
}

VOID getRegionGapAndPages(PVAL head)
{
    PVAL temp = head;
    while (temp->ValidAddressEntry.Next != NULL)
    {
        temp->regionGap = temp->endAddress - temp->beginAddress;
        temp->pageNums = (temp->regionGap / 0x1000) + 1;
        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    return;
}

BOOLEAN isSame(PUCHAR A, PUCHAR B, SIZE_T size)
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

VOID printList(PVAL head)
{
    size_t cnt = 0;
    PVAL temp = head;
    while (temp->ValidAddressEntry.Next != NULL)
    {
        cnt++;
        DbgPrint("ListNodeIndex: 0x%llx, begin: 0x%p\t end: 0x%p\t regionGap: 0x%llx\t pageNums: 0x%llx\t memState: %lx\t memProtect: %lx\t", cnt, (PVOID)temp->beginAddress, (PVOID)temp->endAddress, temp->regionGap, temp->pageNums, temp->memoryState, temp->memoryProtectAttributes);
        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    return;
}

ULONG64 getMaxRegionPages(PVAL head)
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

VOID ReadBuffer(PVOID bufferHead, SIZE_T size)
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

VOID computeLPSArray(CONST UCHAR* pattern, UL64 M, UL64* lps)
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

VOID KMP_searchPattern(CONST UCHAR* des, CONST UCHAR* pattern, SIZE_T desLen, SIZE_T patLen, ULONG64 pageBeginAddress, UL64* lpsAddress, PRSL* headRSL)
{
    UL64 M = patLen;
    UL64 N = desLen;
    UL64* lps = (UL64*)ExAllocatePoolWithTag(PagedPool, M * sizeof(UL64),'wwww');
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
                *headRSL = createResultNode(1, (ULONG64)(pageBeginAddress + i - j));
                (*headRSL)->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                (*headRSL)->ResultAddressEntry.Blink = (*headRSL)->ResultAddressEntry.Flink;
            }
            else
            {
                PRSL temp = *headRSL;
                while (temp->ResultAddressEntry.Flink != &((*headRSL)->ResultAddressEntry))
                {
                    temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
                }
                PRSL newNode = createResultNode(1, (ULONG64)(pageBeginAddress + i - j));
                temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                newNode->ResultAddressEntry.Flink = &((*headRSL)->ResultAddressEntry);
                newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                (*headRSL)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
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

VOID printResultLink(PRSL head)
{
    PRSL temp = head;
    while (temp->ResultAddressEntry.Flink != &head->ResultAddressEntry)
    {
        DbgPrint("times: %ld, address: %p", temp->times, (PVOID)temp->address);
        temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
    }
    DbgPrint("times: %ld, address: %p", temp->times, (PVOID)temp->address);
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    HANDLE hProcess = NULL;
    NTSTATUS status;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objAttrs;
    clientId.UniqueProcess = (HANDLE)0x228;
    clientId.UniqueThread = NULL;
    InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenProcess(&hProcess, GENERIC_ALL, &objAttrs, &clientId)))
    {
        return STATUS_UNSUCCESSFUL;
    }
    MEMORY_INFORMATION_CLASS MIC = MemoryBasicInformation;
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    ULONG64 currentAddress = 0x0;
    PVAL temp = NULL, head = NULL;
    PRSL tempRSL = NULL, headRSL = NULL;
    size_t cnt = 0x0, writeAddressLen = 0x0;
    while (currentAddress <= 0x00007FFF00000000)
    {
        if (NT_SUCCESS(ZwQueryVirtualMemory(hProcess, currentAddress, MIC, &mbi, sizeof(MEMORY_BASIC_INFORMATION), &writeAddressLen)))
        {
            if (mbi.Protect != 0x00 && mbi.Protect != 0x01 && mbi.Protect != 0x104 && mbi.Protect != 0x100)
            {
                if (head == NULL)
                {
                    if (mbi.Protect == 0x10)
                    {
                        PVAL newNode = createNode((UL64)mbi.BaseAddress, (UL64)mbi.BaseAddress + (UL64)mbi.RegionSize - 1, (UL64)mbi.State, (UL64)mbi.Protect, 1);
                        head = newNode;
                    }
                    else
                    {
                        PVAL newNode = createNode((UL64)mbi.BaseAddress, (UL64)mbi.BaseAddress + (UL64)mbi.RegionSize - 1, (UL64)mbi.State, (UL64)mbi.Protect, 0);
                        head = newNode;
                    }
                }
                else
                {
                    temp = head;
                    while (temp->ValidAddressEntry.Next != NULL)
                    {
                        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
                    }
                    if (mbi.Protect == 0x10)
                    {
                        PVAL newNode = createNode((UL64)mbi.BaseAddress, (UL64)mbi.BaseAddress + (UL64)mbi.RegionSize - 1, (UL64)mbi.State, (UL64)mbi.Protect, 1);
                        temp->ValidAddressEntry.Next = &newNode->ValidAddressEntry;
                    }
                    else
                    {
                        if (temp->endAddress + 0x1 == (UL64)mbi.BaseAddress)
                        {
                            temp->endAddress += mbi.RegionSize;
                        }
                        else
                        {
                            PVAL newNode = createNode((UL64)mbi.BaseAddress, (UL64)mbi.BaseAddress + (UL64)mbi.RegionSize - 1, (UL64)mbi.State, (UL64)mbi.Protect, 0);
                            temp->ValidAddressEntry.Next = &newNode->ValidAddressEntry;
                        }
                    }
                }
            }
        }
        currentAddress = (ULONG64)mbi.BaseAddress + mbi.RegionSize;
    }
    getRegionGapAndPages(head);
    //printList(head);
    ZwClose(hProcess);
    PEPROCESS pe = NULL;
    ULONG64 maxPagesNum = getMaxRegionPages(head);
    DbgPrint("maxPages: %llu", maxPagesNum);
    UCHAR pattern[13] = { 0x32,0x30, 0x31, 0x39, 0x33, 0x30, 0x39, 0x30, 0x31, 0x30, 0x31, 0x32, 0x30 };
    PsLookupProcessByProcessId((HANDLE)clientId.UniqueProcess, &pe);
    KAPC_STATE apc = { 0 };
    temp = head;
    while(temp->ValidAddressEntry.Next != NULL)
    {
        KeStackAttachProcess(pe, &apc);
        UCHAR* bufferReceive = (UCHAR*)ExAllocatePoolWithTag(PagedPool, temp->pageNums * 4096, 'TTTT');
        UL64 addressNeedFree = 0x0;
        __try
        {
            memcpy(bufferReceive, temp->beginAddress, temp->pageNums * 4096);
        }
        __except (1)
        {
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(pe);
            ExFreePool(bufferReceive);
        }
        KeUnstackDetachProcess(&apc);
        ObDereferenceObject(pe);
        KMP_searchPattern(bufferReceive, pattern, temp->pageNums * 4096, 13, temp->beginAddress, &addressNeedFree, &headRSL);
        ExFreePool(addressNeedFree); addressNeedFree = NULL;
        ExFreePool(bufferReceive); bufferReceive = NULL;
        temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
    }
    printResultLink(headRSL);
    //free double-linked list
    tempRSL = headRSL;
    while (temp != NULL && tempRSL->ResultAddressEntry.Flink != NULL)
    {
        //一定要有temp != NULL这句！因为当temp == NULL的时候，tempRSL->ResultAddressEntry.Flink != NULL隐含了一个指针访问操作，会蓝屏！！
        PRSL tempX = CONTAINING_RECORD(tempRSL->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
        tempRSL->ResultAddressEntry.Flink = NULL;
        tempRSL->ResultAddressEntry.Blink = NULL;
        ExFreePool(tempRSL); tempRSL = NULL;
        tempRSL = tempX;
    }
    temp = head;
    //free single-linked list
    while (temp != NULL && temp->ValidAddressEntry.Next != NULL)
    {
        PVAL tempX = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
        ExFreePool(temp); temp = NULL;
        temp = tempX;
    }
    return STATUS_SUCCESS;
}