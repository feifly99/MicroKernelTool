#include "DriverUserInteractionHeader.h"

#pragma warning(disable:6387)
#pragma warning(disable:6011)
#pragma warning(disable:4702)

__INIT_GLOBAL__DEFINES__;
static CLIENT_ID g_cid = { 0 };
static OBJECT_ATTRIBUTES g_kernelProcessObjAttributes = { 0 };
static HANDLE g_kernelProcess = NULL;
__INIT_GLOBAL__DEFINES__;

__PROCESS_MEMORY_SPACE_DEFINES__;
static PVAL g_headVAL = NULL;
static MEMORY_INFORMATION_CLASS g_MIC = MemoryBasicInformation;
static MEMORY_BASIC_INFORMATION g_mbi = { 0 };
__PROCESS_MEMORY_SPACE_DEFINES__;

__SEARCH_OUTCOME_DEFINES__;
static PRSL g_headRSL = NULL;
__SEARCH_OUTCOME_DEFINES__;

__PROCESS_HIDEN_DEFINES__;
static PHPL g_headHPL = NULL;
__PROCESS_HIDEN_DEFINES__;

__PROCESS_PRETENT_DEFINES__;
static PPPL g_headPPL = NULL;
__PROCESS_PRETENT_DEFINES__;

______BASIC_MAJOR_FUNCTION______;
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
______BASIC_MAJOR_FUNCTION______;

NTSTATUS Driver_User_IO_Interaction_Entry(
    IN PDEVICE_OBJECT devObj,
    IN PIRP pIrp
)
{
    __DRIVER_USER_IO_ENTRY_PUBLIC_SETTINGS__;
    UNREFERENCED_PARAMETER(devObj);
    PIO_STACK_LOCATION irpSL = IoGetCurrentIrpStackLocation(pIrp);
    ULONG controlCode = irpSL->Parameters.DeviceIoControl.IoControlCode;
    __DRIVER_USER_IO_ENTRY_PUBLIC_SETTINGS__;
    if (controlCode == ____$_INITIZE_PROCESS_HANDLE_$____)
    {
        ULONG64 pid = *(ULONG64*)pIrp->AssociatedIrp.SystemBuffer; //由用户层输入：&ULONG64.
        g_cid.UniqueProcess = (HANDLE)pid;
        g_cid.UniqueThread = NULL;
        InitializeObjectAttributes(&g_kernelProcessObjAttributes, NULL, 0, NULL, NULL);
        if (NT_SUCCESS(ZwOpenProcess(&g_kernelProcess, GENERIC_ALL, &g_kernelProcessObjAttributes, &g_cid)))
        {
            DbgPrint("Driver Initialization Successfully");
            IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
            return STATUS_SUCCESS;
        }
        else
        {
            DbgPrint("Open File Failed!");
            IOCTL_COMPLETE_MARK(STATUS_UNSUCCESSFUL, 0);
            return STATUS_UNSUCCESSFUL;
        }
    }
    else if (controlCode == ____$_INITIALIZE_PROCESS_MEMORY_SPACE_$____)
    {
        buildValidAddressSingleList(
            &g_kernelProcess,
            &g_MIC,
            &g_mbi,
            &g_headVAL,
            0x00007FFF00000000
        );
        getRegionGapAndPages(g_headVAL);
        if (g_headVAL != NULL)
        {
            DbgPrint("Process Memory Loading Successfully");
            IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
            return STATUS_SUCCESS;
        }
        else
        {
            DbgPrint("Process Memory Loading Failed! Please Stop and Unloading Driver");
            IOCTL_COMPLETE_MARK(STATUS_UNSUCCESSFUL, 0);
            return STATUS_UNSUCCESSFUL;
        }
    }
    else if (controlCode == ____$_SEARCH_PROCEDURE_$____)
    {
        PD_U_SMI temp = (PD_U_SMI)pIrp->AssociatedIrp.SystemBuffer;
        PD_U_SMI res = (PD_U_SMI)ExAllocatePoolWithTag(PagedPool, sizeof(D_U_SMI), 'zppz');
        res->isFirstScan = temp->isFirstScan;
        res->dataType = temp->dataType;
        res->scanMode = temp->scanMode;
        if(temp->smi != NULL)
        {
            res->smi = (PSMI)ExAllocatePoolWithTag(PagedPool, sizeof(SMI), 'zuuz');
            res->smi->preciseMode.dataLen = temp->smi->preciseMode.dataLen;
            res->smi->preciseMode.value_hexBytePointer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, res->smi->preciseMode.dataLen, 'zggz');
            memcpy(res->smi->preciseMode.value_hexBytePointer, temp->smi->preciseMode.value_hexBytePointer, res->smi->preciseMode.dataLen);
            DbgPrint("%llu", res->smi->preciseMode.dataLen);
        }
        if (res->isFirstScan == 1)
        {
            buildDoubleLinkedAddressListForScaningResult(
                (ULONG64)g_cid.UniqueProcess,
                res->scanMode,
                res->smi,
                res->dataType,
                g_headVAL,
                &g_headRSL
            );
            printListRSL(g_headRSL);
        }
        else
        {
            continueSearch(
                (ULONG64)g_cid.UniqueProcess,
                res->scanMode,
                res->dataType,
                res->smi,
                &g_headRSL
            );
        }
        IOCTL_COMPLETE_MARK(STATUS_UNSUCCESSFUL, 0);
        return STATUS_UNSUCCESSFUL;
    }
    else if (controlCode == ____$_STOP_SEARCH_PATTERN_$____)
    {
        if (g_headRSL != NULL)
        {
            ExFreeResultSavedLink(&g_headRSL);
            g_headRSL = NULL;
        }
        IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    else if (controlCode == ____$_LIST_PROCESS_MODULE_$____)
    {
        displayAllModuleInfomationByProcessId((ULONG64)g_cid.UniqueProcess);
        IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    else if (controlCode == ____$_LIST_PROCESS_THREAD_$____)
    {
        displayAllThreadInfomationByProcessId((ULONG64)g_cid.UniqueProcess);
        IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    else if (controlCode == ____$_WRITE_PROCESS_MEMORY_$____)
    {
        PWPMI inputBuffer = (PWPMI)pIrp->AssociatedIrp.SystemBuffer;
        if (inputBuffer)
        {
            PUCHAR tempBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, inputBuffer->writeMemoryLength * sizeof(UCHAR), 'wwww');
            for (SIZE_T j = 0; j < inputBuffer->writeMemoryLength && tempBuffer; j++)
            {
                tempBuffer[j] = *(UCHAR*)((ULONG64)(inputBuffer->writeBuffer) + j);
            }
            writeProcessMemory((ULONG64)g_cid.UniqueProcess, inputBuffer->writeBeginAddress, (PVOID)tempBuffer, inputBuffer->writeMemoryLength);
            ExFreePool(tempBuffer);
            IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
            return STATUS_SUCCESS;
        }
        else
        {
            DbgPrint("Null input, driver close.");
            IOCTL_COMPLETE_MARK(STATUS_INVALID_ADDRESS, 0);
            return STATUS_INVALID_ADDRESS;
        }
    }
    else if (controlCode == ____$_PROCESS_HIDEN_PROCEDURE_$____)
    {
        ULONG64 pid = *(ULONG64*)pIrp->AssociatedIrp.SystemBuffer;
        processHiddenProcedure(pid, &g_headHPL);
        printListHPL(g_headHPL);
        IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    else if (controlCode == ____$_PROCESS_PRETENT_PROCEDURE_$____)
    {
        PPPI inputBuffer = (PPPI)pIrp->AssociatedIrp.SystemBuffer;
        processPretentProcedure(inputBuffer->ditryPID, inputBuffer->parasitePID, &g_headPPL);
        printListPPL(g_headPPL);
        IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    else if (controlCode == ____$_UNLOAD_DRIVER_PREPARE_$____)
    {
        //KeBugCheckEx(0X9ABCDEF0, 0, 0, 0, 0);
        DbgPrint("here!");
        if (g_headVAL != NULL)
        {
            ExFreeValidAddressLink(&g_headVAL);
            g_headVAL = NULL;
        }
        if (g_headRSL != NULL)
        {
            ExFreeResultSavedLink(&g_headRSL);
            g_headRSL = NULL;
        }
        if (g_headHPL != NULL)
        {
            ExFreeHiddenProcessLink(&g_headHPL);
            g_headHPL = NULL;
        }
        if (g_headPPL != NULL)
        {
            ExFreePretentProcessLink(&g_headPPL);
            g_headPPL = NULL;
        }
        if (g_kernelProcess != NULL)
        {
            ZwClose(g_kernelProcess);
            g_kernelProcess = NULL;
        }
        IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    else
    {
        IOCTL_COMPLETE_MARK(STATUS_INVALID_LABEL, 0);
        return STATUS_INVALID_LABEL;
    }
}
ULONG checkProtectAttributesForTargetAddress(
    PVAL headVAL,
    PVOID targetAddress
)
{
    PVAL temp = headVAL;
    while (temp->ValidAddressEntry.Next != NULL)
    {
        if (
            (ULONG64)temp->beginAddress < (ULONG64)targetAddress
            &&
            (ULONG64)((CONTAINING_RECORD(temp->ValidAddressEntry.Next, VAL, ValidAddressEntry)->beginAddress)) >(ULONG64)targetAddress
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
