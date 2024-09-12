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
        PVAL_UI buffer_LIST_MEMORY = (PVAL_UI)pIrp->AssociatedIrp.SystemBuffer;
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
        //printListVAL(headVAL);
        ExFreeValidAddressLink(&headVAL);
        ZwClose(kernel_hProcess);
        IOCTL_COMPLETE_MARK(status, 0);
        __PLACE_HOLDER__;
        return STATUS_SUCCESS;
    }
    else if (IOCTL_CODE == ____$_GET_PATTERN_NUM_$____)
    {
        DbgPrint("____$_GET_PATTERN_NUM_$____");
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
        PRSL_UI buffer_SEARCH_PATTERN = (PRSL_UI)pIrp->AssociatedIrp.SystemBuffer;
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
        PRSL headRSL = NULL;
        PUCHAR tempBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, buffer_SEARCH_PATTERN->patternLen, 'ABCD');
        //【完全释放】
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
        //printListRSL(headRSL);
        SIZE_T cnt = getNodeNumsForDoubleLinkedList(headRSL);
        memcpy(pIrp->AssociatedIrp.SystemBuffer, &cnt, sizeof(SIZE_T));
        if (tempBuffer)
        {
            ExFreePool(tempBuffer);
        }
        ExFreeResultSavedLink(&headRSL);
        ExFreeValidAddressLink(&headVAL);
        IOCTL_COMPLETE_MARK(status, sizeof(SIZE_T));
        //IOCTL_COMPLETE_MARK要诚实地返回应当返回多少的字节数！
        //用户驱动交互出现IRQL问题：看看用户空间给的返回缓冲区够不够大，不够大就会出现IRQL！
        //用户空间不够大除了IRQL问题之外还可能出现SYSTEM_THREAD_NOT_HANDLED蓝屏代码。
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
        PRSL_UI buffer_SEARCH_PATTERN = (PRSL_UI)pIrp->AssociatedIrp.SystemBuffer;
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
        PRSL headRSL = NULL;
        PUCHAR tempBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, buffer_SEARCH_PATTERN->patternLen, 'ABCD');
        //【完全释放】
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
        //printListRSL(headRSL);
        SIZE_T cnt = getNodeNumsForDoubleLinkedList(headRSL);
        PRSL_DO ret = (PRSL_DO)ExAllocatePoolWithTag(PagedPool, cnt * sizeof(RSL_DO), 'FFYA');
        PRSL tempRSL = headRSL;
        for (size_t j = 0; j < cnt && ret; j++)
        {
            ret[j].times = tempRSL->times;
            ret[j].address = tempRSL->address;
            ret[j].protect = checkProtectAttributesForTargetAddress(headVAL, (PVOID)tempRSL->address);
            tempRSL = CONTAINING_RECORD(tempRSL->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
        }
        if(ret)
        {
            memcpy(pIrp->AssociatedIrp.SystemBuffer, ret, cnt * sizeof(RSL_DO));
        }
        if(ret && tempBuffer)
        {
            ExFreePool(tempBuffer);
            ExFreePool(ret);
        }
        ExFreeResultSavedLink(&headRSL);
        ExFreeValidAddressLink(&headVAL);
        IOCTL_COMPLETE_MARK(status, cnt * sizeof(RSL_DO));
        //IOCTL_COMPLETE_MARK要诚实地返回应当返回多少的字节数！
        //用户驱动交互出现IRQL问题：看看用户空间给的返回缓冲区够不够大，不够大就会出现IRQL！
        //用户空间不够大除了IRQL问题之外还可能出现SYSTEM_THREAD_NOT_HANDLED蓝屏代码。
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
        PLPM_UI buffer_LIST_PROCESS_MODULE = (PLPM_UI)pIrp->AssociatedIrp.SystemBuffer;
        displayAllModuleInfomationByProcessId((ULONG64)buffer_LIST_PROCESS_MODULE->pid);
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
        PLPT_UI buffer_LIST_PROCESS_THREAD = (PLPT_UI)pIrp->AssociatedIrp.SystemBuffer;
        displayAllThreadInfomationByProcessId((ULONG64)buffer_LIST_PROCESS_THREAD->pid);
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
        PWPM_UI buffer_WRITE_PROCESS_MEMORY = (PWPM_UI)pIrp->AssociatedIrp.SystemBuffer;
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
