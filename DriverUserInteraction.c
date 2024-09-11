#include "DriverUserInteraction.h"

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
    DbgPrint("Here!");
    UNREFERENCED_PARAMETER(devObj);
    PIO_STACK_LOCATION irpSL = IoGetCurrentIrpStackLocation(pIrp);
    ULONG IOCTL_CODE = irpSL->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_SUCCESS;
    if (pIrp->AssociatedIrp.SystemBuffer == NULL)
    {
        DbgPrint("NULL memory!");
        return STATUS_UNSUCCESSFUL;
    }
    if (IOCTL_CODE == ____$_LIST_MEMORY_$____)
    {
        DbgPrint("____$_LIST_MEMORY_$____");
        __PLACE_HOLDER__;
        /*
            Current pIrp->AssociatedIrp.SystemBuffer struct be like:
            typedef struct _ValidAddressList_DriverUserInteraction
            {
                USER_IN HANDLE pid;
            }VAL_DUI, *PVAL_DUI;
        */
        PVAL_DUI buffer_LIST_MEMORY = (PVAL_DUI)pIrp->AssociatedIrp.SystemBuffer;
        __PLACE_HOLDER__;
        HANDLE kernel_hProcess = NULL;
        CLIENT_ID cid = { 0 };
        cid.UniqueProcess = (HANDLE)buffer_LIST_MEMORY->pid;
        cid.UniqueThread = NULL;
        OBJECT_ATTRIBUTES objAttrs;
        InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);
        ZwOpenProcess(&kernel_hProcess, GENERIC_ALL, &objAttrs, &cid);
        __PLACE_HOLDER__;
        PVAL headVAL = NULL;
        MEMORY_INFORMATION_CLASS MIC = MemoryBasicInformation;
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        buildValidAddressSingleList(
            &kernel_hProcess,
            &MIC,
            &mbi,
            &headVAL,
            0x00007FFF00000000
        );
        getRegionGapAndPages(headVAL);
        printListVAL(headVAL);
        ExFreeValidAddressLink(&headVAL);
        ZwClose(kernel_hProcess);
        IOCTL_COMPLETE_MARK(status, 0);
        __PLACE_HOLDER__;
        return STATUS_SUCCESS;
    }
    else if (IOCTL_CODE == ____$_SEARCH_PATTERN_$____)
    {
        DbgPrint("____$_SEARCH_PATTERN_$____");
        __PLACE_HOLDER__;
        /*
            Current pIrp->AssociatedIrp.SystemBuffer struct be like:
            typedef struct _ResultSavedList_DriverUserInteraction
            {
                USER_IN HANDLE pid;
                USER_IN PUCHAR pattern;
                USER_IN SIZE_T patternLen;
            }RSL_DUI, *PRSL_DUI;
        */
        PRSL_DUI buffer_SEARCH_PATTERN = (PRSL_DUI)pIrp->AssociatedIrp.SystemBuffer;
        __PLACE_HOLDER__;
        HANDLE kernel_hProcess = NULL;
        CLIENT_ID cid = { 0 };
        cid.UniqueProcess = (HANDLE)buffer_SEARCH_PATTERN->pid;
        cid.UniqueThread = NULL;
        OBJECT_ATTRIBUTES objAttrs;
        InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);
        ZwOpenProcess(&kernel_hProcess, GENERIC_ALL, &objAttrs, &cid);
        __PLACE_HOLDER__;
        PVAL headVAL = NULL;
        MEMORY_INFORMATION_CLASS MIC = MemoryBasicInformation;
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        buildValidAddressSingleList(
            &kernel_hProcess,
            &MIC,
            &mbi,
            &headVAL,
            0x00007FFF00000000
        );
        getRegionGapAndPages(headVAL);
        ZwClose(kernel_hProcess);
        printListVAL(headVAL);
        PRSL headRSL = NULL;
        PUCHAR tempBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, buffer_SEARCH_PATTERN->patternLen, 'ABCD');
        for (size_t j = 0; j < buffer_SEARCH_PATTERN->patternLen && tempBuffer; j++)
        {
            tempBuffer[j] = buffer_SEARCH_PATTERN->pattern[j];
        }
        buildDoubleLinkedAddressListForPatternStringByKMPAlgorithm(
            (ULONG64)buffer_SEARCH_PATTERN->pid,
            headVAL,
            (PUCHAR)tempBuffer,
            (SIZE_T)buffer_SEARCH_PATTERN->patternLen,
            &headRSL
        );
        if(tempBuffer)
        {
            ExFreePool(tempBuffer);
        }
        printListRSL(headRSL);
        ExFreeResultSavedLink(&headRSL);
        ExFreeValidAddressLink(&headVAL);
        IOCTL_COMPLETE_MARK(status, 0);
        __PLACE_HOLDER__;
        return STATUS_SUCCESS;
    }
    else if (IOCTL_CODE == ____$_LIST_PROCESS_MODULE_$____)
    {
        DbgPrint("____$_LIST_PROCESS_MODULE_$____");
        __PLACE_HOLDER__;
        /*
            Current pIrp->AssociatedIrp.SystemBuffer struct be like:
            typedef struct _ListProcessModule_DriverUserInteraction
            {
                USER_IN HANDLE pid;
            }LPM_DUI, *PLPM_DUI;
        */
        PLPM_DUI buffer_LIST_PROCESS_MODULE = (PLPM_DUI)pIrp->AssociatedIrp.SystemBuffer;
        __PLACE_HOLDER__;
        HANDLE kernel_hProcess = NULL;
        CLIENT_ID cid = { 0 };
        cid.UniqueProcess = (HANDLE)buffer_LIST_PROCESS_MODULE->pid;
        cid.UniqueThread = NULL;
        OBJECT_ATTRIBUTES objAttrs;
        InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);
        ZwOpenProcess(&kernel_hProcess, GENERIC_ALL, &objAttrs, &cid);
        __PLACE_HOLDER__;
        displayAllModuleInfomationByProcessId((ULONG64)buffer_LIST_PROCESS_MODULE->pid);
        ZwClose(kernel_hProcess);
        IOCTL_COMPLETE_MARK(status, 0);
        __PLACE_HOLDER__;
        return STATUS_SUCCESS;
    }
    else if (IOCTL_CODE == ____$_LIST_PROCESS_THREAD_$____)
    {
        DbgPrint("____$_LIST_PROCESS_THREAD_$____");
        __PLACE_HOLDER__;
        /*
            Current pIrp->AssociatedIrp.SystemBuffer struct be like:
            typedef struct _ListProcessThread_DriverUserInteraction
            {
                USER_IN HANDLE pid;
            }LPT_DUI, * PLPT_DUI;
        */
        PLPT_DUI buffer_LIST_PROCESS_THREAD = (PLPT_DUI)pIrp->AssociatedIrp.SystemBuffer;
        __PLACE_HOLDER__;
        HANDLE kernel_hProcess = NULL;
        CLIENT_ID cid = { 0 };
        cid.UniqueProcess = (HANDLE)buffer_LIST_PROCESS_THREAD->pid;
        cid.UniqueThread = NULL;
        OBJECT_ATTRIBUTES objAttrs;
        InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);
        ZwOpenProcess(&kernel_hProcess, GENERIC_ALL, &objAttrs, &cid);
        __PLACE_HOLDER__;
        displayAllThreadInfomationByProcessId((ULONG64)buffer_LIST_PROCESS_THREAD->pid);
        ZwClose(kernel_hProcess);
        IOCTL_COMPLETE_MARK(status, 0);
        __PLACE_HOLDER__;
        return STATUS_SUCCESS;
    }
    else if (IOCTL_CODE == ____$_WRITE_PROCESS_MEMORY_$____)
    {
        __PLACE_HOLDER__;
        /*
            Current pIrp->AssociatedIrp.SystemBuffer struct be like:
            typedef struct _WriteProcessMemory_DriverUserInteraction
            {
                USER_IN HANDLE pid;
                USER_IN PVOID targetAddress;
                USER_IN PVOID content;
                USER_IN SIZE_T writeLen;
            }WPM_DUI, * PWPM_DUI;
        */
        PWPM_DUI buffer_WRITE_PROCESS_MEMORY = (PWPM_DUI)pIrp->AssociatedIrp.SystemBuffer;
        __PLACE_HOLDER__;
        HANDLE kernel_hProcess = NULL;
        CLIENT_ID cid = { 0 };
        cid.UniqueProcess = (HANDLE)buffer_WRITE_PROCESS_MEMORY->pid;
        cid.UniqueThread = NULL;
        OBJECT_ATTRIBUTES objAttrs;
        InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);
        ZwOpenProcess(&kernel_hProcess, GENERIC_ALL, &objAttrs, &cid);
        __PLACE_HOLDER__;
        writeProcessMemory(
            (ULONG64)buffer_WRITE_PROCESS_MEMORY->pid,
            (PVOID)buffer_WRITE_PROCESS_MEMORY->targetAddress,
            (PVOID)buffer_WRITE_PROCESS_MEMORY->content,
            (SIZE_T)buffer_WRITE_PROCESS_MEMORY->writeLen
        );
        ZwClose(kernel_hProcess);
        IOCTL_COMPLETE_MARK(status, 0);
        __PLACE_HOLDER__;
        return STATUS_SUCCESS;
    }
    else
    {
        return STATUS_UNSUCCESSFUL;
    }
}