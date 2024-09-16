#include "DriverUserInteraction.h"

#pragma warning(disable:6387)
#pragma warning(disable:6011)

__INIT_GLOBAL__DEFINES__;
static CLIENT_ID g_cid = { 0 };
static OBJECT_ATTRIBUTES g_kernelProcessObjAttributes = { 0 };
static HANDLE g_kernelProcess = NULL;
static PVAL g_headVAL = NULL;
static MEMORY_INFORMATION_CLASS g_MIC = MemoryBasicInformation;
static MEMORY_BASIC_INFORMATION g_mbi = { 0 };
__INIT_GLOBAL__DEFINES__;

__SEARCH_OUTCOME_DEFINES__;
static PRSL g_headRSL = NULL;
static PUCHAR g_mostRecentPattern = NULL;
static SIZE_T g_mostRecentPatternLen = 0x0;
__SEARCH_OUTCOME_DEFINES__;

NTSTATUS myCreate(
    IN PDEVICE_OBJECT pDeviceObject,
    IN PIRP pIrp
)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    NTSTATUS status = STATUS_SUCCESS;
    DbgPrint("Routine: MyCreate successful!\n");
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}
NTSTATUS myClose(
    IN PDEVICE_OBJECT pDeviceObject,
    IN PIRP pIrp
)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    NTSTATUS status = STATUS_SUCCESS;
    DbgPrint("Routine: MyClose successful!\n");
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}
NTSTATUS Driver_User_IO_Interaction_Entry(
    IN PDEVICE_OBJECT devObj,
    IN PIRP pIrp
)
{
    __DRIVER_USER_IO_ENTRY_PUBLIC_SETTINGS__;
    NTSTATUS status = STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(devObj);
    PIO_STACK_LOCATION irpSL = IoGetCurrentIrpStackLocation(pIrp);
    ULONG controlCode = irpSL->Parameters.DeviceIoControl.IoControlCode;
    __DRIVER_USER_IO_ENTRY_PUBLIC_SETTINGS__;
    if (controlCode == ____$_INITIALIZE_DRIVER_SETTINGS_$____)
    {
        ULONG64 pid = *(ULONG64*)pIrp->AssociatedIrp.SystemBuffer; //由用户层输入：&ULONG64.
        DbgPrint("%llx", pid);
        g_cid.UniqueProcess = (HANDLE)pid;
        g_cid.UniqueThread = NULL;
        InitializeObjectAttributes(&g_kernelProcessObjAttributes, NULL, 0, NULL, NULL);
        ZwOpenProcess(&g_kernelProcess, GENERIC_ALL, &g_kernelProcessObjAttributes, &g_cid);
        if (NT_SUCCESS(status))
        {
            buildValidAddressSingleList(
                &g_kernelProcess,
                &g_MIC,
                &g_mbi,
                &g_headVAL,
                0x00007FFF00000000
            );
            getRegionGapAndPages(g_headVAL);
            //printListVAL(g_headVAL);
            DbgPrint("Driver Initialization Successfully");
            IOCTL_COMPLETE_MARK(status, 0);
            return STATUS_SUCCESS;
        }
        else
        {
            DbgPrint("Open File Failed!");
            IOCTL_COMPLETE_MARK(status, 0);
            return status;
        }
    }
    else if (controlCode == ____$_SEARCH_PATTERN_$____)
    {
        PPSI receiveStructPointer = (PPSI)pIrp->AssociatedIrp.SystemBuffer;
        if (receiveStructPointer->isFirstScan)
        {
            PUCHAR tempBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, receiveStructPointer->patternLen, 'PPPP');
            SIZE_T tempBufferLen = receiveStructPointer->patternLen;
            for (size_t j = 0; j < receiveStructPointer->patternLen; j++)
            {
                tempBuffer[j] = receiveStructPointer->pattern[j];
            }
            g_mostRecentPattern = tempBuffer;
            g_mostRecentPatternLen = tempBufferLen;
            buildDoubleLinkedAddressListForPatternStringByKMPAlgorithm(
                (ULONG64)g_cid.UniqueProcess,
                g_headVAL,
                g_mostRecentPattern,
                g_mostRecentPatternLen,
                &g_headRSL
            );
            printListRSL(g_headRSL);
            IOCTL_COMPLETE_MARK(status, 0);
            return status;
        }
        else 
        {
            if (receiveStructPointer->scanMode == 0)
            {
                PRSL tempRSL = g_headRSL;
                PRSL newRSLhead = NULL;
                PUCHAR tempBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, receiveStructPointer->patternLen, 'LLLL');
                SIZE_T tempBufferLen = receiveStructPointer->patternLen;
                for (size_t j = 0; j < receiveStructPointer->patternLen; j++)
                {
                    tempBuffer[j] = receiveStructPointer->pattern[j];
                }
                PEPROCESS pe = NULL;
                KAPC_STATE apc = { 0 };
                PsLookupProcessByProcessId((HANDLE)g_cid.UniqueProcess, &pe);
                KeStackAttachProcess(pe, &apc);
                while (tempRSL->ResultAddressEntry.Flink != &g_headRSL->ResultAddressEntry)
                {
                    if (isSame((PUCHAR)tempRSL->address, tempBuffer, tempBufferLen))
                    {
                        if (newRSLhead == NULL)
                        {
                            newRSLhead = createSavedResultNode(2, tempRSL->address);
                            if (newRSLhead)
                            {
                                (newRSLhead)->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                                (newRSLhead)->ResultAddressEntry.Blink = (newRSLhead)->ResultAddressEntry.Flink;
                            }
                        }
                        else
                        {
                            PRSL temp = newRSLhead;
                            while (temp->ResultAddressEntry.Flink != &((newRSLhead)->ResultAddressEntry))
                            {
                                temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
                            }
                            PRSL newNode = createSavedResultNode(2, tempRSL->address);
                            if (newNode)
                            {
                                temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                                newNode->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                                newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                                (newRSLhead)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                            }
                        }
                    }
                    tempRSL = CONTAINING_RECORD(tempRSL->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
                }
                if (isSame((PUCHAR)tempRSL->address, tempBuffer, tempBufferLen))
                {
                    if (newRSLhead == NULL)
                    {
                        newRSLhead = createSavedResultNode(3, tempRSL->address);
                        if (newRSLhead)
                        {
                            (newRSLhead)->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                            (newRSLhead)->ResultAddressEntry.Blink = (newRSLhead)->ResultAddressEntry.Flink;
                        }
                    }
                    else
                    {
                        PRSL temp = newRSLhead;
                        while (temp->ResultAddressEntry.Flink != &((newRSLhead)->ResultAddressEntry))
                        {
                            temp = CONTAINING_RECORD(temp->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
                        }
                        PRSL newNode = createSavedResultNode(33333, tempRSL->address);
                        if (newNode)
                        {
                            temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                            newNode->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                            newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                            (newRSLhead)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                        }
                    }
                }
                KeUnstackDetachProcess(&apc);
                ObDereferenceObject(pe);
                ExFreeResultSavedLink(&g_headRSL);
                g_headRSL = newRSLhead;
                if (g_headRSL)
                {
                    printListRSL(g_headRSL);
                }
                else
                {
                    DbgPrint("空链表！");
                }
                IOCTL_COMPLETE_MARK(status, 0);
                return status;
            }
            else
            {
                IOCTL_COMPLETE_MARK(status, 0);
                return status;
            }
        }
    }
    IOCTL_COMPLETE_MARK(status, 0);
    return status;
}
ULONG checkProtectAttributesForTargetAddress(
    PVAL headVAL,
    PVOID targetAddress
)
{
    PVAL temp = headVAL;
    while (temp->ValidAddressEntry.Next != NULL)
    {
        if(
            (ULONG64)temp->beginAddress < (ULONG64)targetAddress 
            &&
            (ULONG64)((CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry)->beginAddress)) > (ULONG64)targetAddress
            )
        {
            return temp->memoryProtectAttributes;
        }
        else
        {
            temp = CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry);
        }
    }
    return 0;
}
/*
/*PRSL tempRSL = g_headRSL;
                PRSL newRSLhead = NULL;
                PUCHAR tempBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, receiveStructPointer->patternLen, 'LLLL');
                SIZE_T tempBufferLen = receiveStructPointer->patternLen;
                for (size_t j = 0; j < receiveStructPointer->patternLen; j++)
                {
                    tempBuffer[j] = receiveStructPointer->pattern[j];
                }
                while (tempRSL->ResultAddressEntry.Flink != &g_headRSL->ResultAddressEntry)
                {
                    if (strncmp((CONST CHAR*)tempRSL->address, (CONST CHAR*)tempBuffer, tempBufferLen) == 0)
                    {
                        if (newRSLhead == NULL)
                        {
                            newRSLhead = createSavedResultNode(2, tempRSL->address);
                            if (newRSLhead)
                            {
                                newRSLhead->ResultAddressEntry.Flink = &(newRSLhead->ResultAddressEntry);
                                newRSLhead->ResultAddressEntry.Blink = newRSLhead->ResultAddressEntry.Flink;
                            }
                            tempRSL = CONTAINING_RECORD(tempRSL->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
                        }
                        else
                        {
                            PRSL tempLast = newRSLhead;
                            while (tempLast->ResultAddressEntry.Flink != &(newRSLhead->ResultAddressEntry))
                            {
                                tempLast = CONTAINING_RECORD(tempLast->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
                            }
                            PRSL newNode = createSavedResultNode(2, tempRSL->address);
                            if (newNode)
                            {
                                tempLast->ResultAddressEntry.Flink = &(newNode->ResultAddressEntry);
                                newNode->ResultAddressEntry.Flink = &(newRSLhead->ResultAddressEntry);
                                newNode->ResultAddressEntry.Blink = &(tempLast->ResultAddressEntry);
                                newRSLhead->ResultAddressEntry.Blink = &(newNode->ResultAddressEntry);
                            }
                        }
                    }
                }
                ExFreeResultSavedLink(&g_headRSL);
                g_headRSL = newRSLhead;
                if (g_headRSL == NULL)
                {
                    DbgPrint("空链表");
                    IOCTL_COMPLETE_MARK(status, 0);
                    return status;
                }
                else
                {
                    printListRSL(newRSLhead);
                    IOCTL_COMPLETE_MARK(status, 0);
                    return status;
                }
            }
            else
            {
                IOCTL_COMPLETE_MARK(status, 0);
                return status;
            }*/
