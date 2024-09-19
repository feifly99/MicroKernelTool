#include "DriverUserInteraction.h"

#pragma warning(disable:6387)
#pragma warning(disable:6011)

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
static SIZE_T g_mostRecentPatternLen = 0x0;
__SEARCH_OUTCOME_DEFINES__;

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

______LONG_FUNCTION_EXTRACT______;
NTSTATUS continueSearchMode_Precise(
    // Inner using GLOBAL DEFINITIONS: 
    // g_mostRecentPatternLen 
    // g_headRSL
    LOCAL PUCHAR newReceivedPattern,
    LOCAL SIZE_T newReceivedPatternLen
)
{
    //输入参数：isFirstScan:0 // pattern: valid address // patternLen: valid number // scanMode: 0 //
    //走到这儿是准确搜索，用不到上一次最近的字符串信息
    //直接更新新字符串长度到全局变量：
    g_mostRecentPatternLen = newReceivedPatternLen;
    //链表遍历，定义一个临时虚拟双链表头：
    LIST_ENTRY virtualListHead = { 0 };
    //置虚拟链表头为真正的链表头：
    virtualListHead.Flink = &g_headRSL->ResultAddressEntry;
    CONTAINING_RECORD(g_headRSL->ResultAddressEntry.Blink, RSL, ResultAddressEntry)->ResultAddressEntry.Flink = &virtualListHead;
    virtualListHead.Blink = &CONTAINING_RECORD(g_headRSL->ResultAddressEntry.Blink, RSL, ResultAddressEntry)->ResultAddressEntry;
    g_headRSL->ResultAddressEntry.Blink = &virtualListHead;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    //定义循环变量temp：
    PLIST_ENTRY temp = &virtualListHead;
    PsLookupProcessByProcessId((HANDLE)g_cid.UniqueProcess, &pe);
    KeStackAttachProcess(pe, &apc);
    while (temp->Flink != &virtualListHead)
    {
        //如果temp的下一个对应节点的地址和条件不匹配，那么断链：
        PRSL curr = CONTAINING_RECORD(temp->Flink, RSL, ResultAddressEntry);
        if (strncmp((PVOID)curr->address, (PVOID)newReceivedPattern, newReceivedPatternLen) != 0)
        {
            //注意：断链时，只是把temp后面那个节点删除并释放掉，temp循环变量是不动的。
            curr->ResultAddressEntry.Blink->Flink = curr->ResultAddressEntry.Flink;
            curr->ResultAddressEntry.Flink->Blink = curr->ResultAddressEntry.Blink;
            ExFreePool(curr);
            curr = NULL;
        }
        else
        {
            //如果不断链才会移动temp循环变量。
            temp = temp->Flink;
        }
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    //如果虚拟头的Flink不指向自己，那么证明存在有效的RSL节点：
    if (virtualListHead.Flink != &virtualListHead)
    {
        //根据虚拟头找到真正的链表头尾：
        PRSL newHead = CONTAINING_RECORD(virtualListHead.Flink, RSL, ResultAddressEntry);
        PRSL newTail = CONTAINING_RECORD(virtualListHead.Blink, RSL, ResultAddressEntry);
        //排除掉虚拟链表头：
        newHead->ResultAddressEntry.Blink = &newTail->ResultAddressEntry;
        newTail->ResultAddressEntry.Flink = &newHead->ResultAddressEntry;
        g_headRSL = newHead;
        //拨除废弃的链表链接：
        virtualListHead.Flink = NULL;
        virtualListHead.Blink = NULL;
        //打印有效双链表：
        printListRSL(g_headRSL);
        return STATUS_SUCCESS;
    }
    //如果虚拟头的Flink指向自己，那么证明不存在有效的RSL节点：
    else
    {
        //直接置空：
        g_headRSL = NULL;
        //报告日志：
        DbgPrint("精确搜索结果：空链表！");
        //并把g_mostRecentPatternLen置零。
        g_mostRecentPatternLen = 0x0;
        return STATUS_UNSUCCESSFUL;
    }
}
NTSTATUS continueSearchMode_Larger(
    // Inner using GLOBAL DEFINITIONS: 
    // g_mostRecentPatternLen 
    // g_headRSL
)
{
    //不用验证g_headRSL有效性，走到这个逻辑之前已经验过了：
    LIST_ENTRY virtualListHead = { 0 };
    virtualListHead.Flink = &g_headRSL->ResultAddressEntry;
    CONTAINING_RECORD(g_headRSL->ResultAddressEntry.Blink, RSL, ResultAddressEntry)->ResultAddressEntry.Flink = &virtualListHead;
    virtualListHead.Blink = &CONTAINING_RECORD(g_headRSL->ResultAddressEntry.Blink, RSL, ResultAddressEntry)->ResultAddressEntry;
    g_headRSL->ResultAddressEntry.Blink = &virtualListHead;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PLIST_ENTRY temp = &virtualListHead;
    PsLookupProcessByProcessId((HANDLE)g_cid.UniqueProcess, &pe);
    KeStackAttachProcess(pe, &apc);
    while (temp->Flink != &virtualListHead)
    {
        PRSL curr = CONTAINING_RECORD(temp->Flink, RSL, ResultAddressEntry);
        if (farBytesDiffer(curr->buffer, (PUCHAR)curr->address, g_mostRecentPatternLen) != 2)
        {
            curr->ResultAddressEntry.Blink->Flink = curr->ResultAddressEntry.Flink;
            curr->ResultAddressEntry.Flink->Blink = curr->ResultAddressEntry.Blink;
            ExFreePool(curr);
            curr = NULL;
        }
        else
        {
            temp = temp->Flink;
        }
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    if (virtualListHead.Flink != &virtualListHead)
    {
        PRSL newHead = CONTAINING_RECORD(virtualListHead.Flink, RSL, ResultAddressEntry);
        PRSL newTail = CONTAINING_RECORD(virtualListHead.Blink, RSL, ResultAddressEntry);
        newHead->ResultAddressEntry.Blink = &newTail->ResultAddressEntry;
        newTail->ResultAddressEntry.Flink = &newHead->ResultAddressEntry;
        g_headRSL = newHead;
        virtualListHead.Flink = NULL;
        virtualListHead.Blink = NULL;
        printListRSL(g_headRSL);
        return STATUS_SUCCESS;
    }
    else
    {
        //如果继续搜索没找到，那么置NULL报空：
        g_headRSL = NULL;
        DbgPrint("变大搜索结果：空链表！");
        //并把g_mostRecentPatternLen置零。
        g_mostRecentPatternLen = 0x0;
        return STATUS_UNSUCCESSFUL;
    }
}
NTSTATUS continueSearchMode_Lower(
    // Inner using GLOBAL DEFINITIONS: 
    // g_mostRecentPatternLen 
    // g_headRSL
)
{
    //不用验证g_headRSL有效性，走到这个逻辑之前已经验过了：
    LIST_ENTRY virtualListHead = { 0 };
    virtualListHead.Flink = &g_headRSL->ResultAddressEntry;
    CONTAINING_RECORD(g_headRSL->ResultAddressEntry.Blink, RSL, ResultAddressEntry)->ResultAddressEntry.Flink = &virtualListHead;
    virtualListHead.Blink = &CONTAINING_RECORD(g_headRSL->ResultAddressEntry.Blink, RSL, ResultAddressEntry)->ResultAddressEntry;
    g_headRSL->ResultAddressEntry.Blink = &virtualListHead;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PLIST_ENTRY temp = &virtualListHead;
    PsLookupProcessByProcessId((HANDLE)g_cid.UniqueProcess, &pe);
    KeStackAttachProcess(pe, &apc);
    while (temp->Flink != &virtualListHead)
    {
        PRSL curr = CONTAINING_RECORD(temp->Flink, RSL, ResultAddressEntry);
        if (farBytesDiffer(curr->buffer, (PUCHAR)curr->address, g_mostRecentPatternLen) != 1)
        {
            curr->ResultAddressEntry.Blink->Flink = curr->ResultAddressEntry.Flink;
            curr->ResultAddressEntry.Flink->Blink = curr->ResultAddressEntry.Blink;
            ExFreePool(curr);
            curr = NULL;
        }
        else
        {
            temp = temp->Flink;
        }
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    if (virtualListHead.Flink != &virtualListHead)
    {
        PRSL newHead = CONTAINING_RECORD(virtualListHead.Flink, RSL, ResultAddressEntry);
        PRSL newTail = CONTAINING_RECORD(virtualListHead.Blink, RSL, ResultAddressEntry);
        newHead->ResultAddressEntry.Blink = &newTail->ResultAddressEntry;
        newTail->ResultAddressEntry.Flink = &newHead->ResultAddressEntry;
        g_headRSL = newHead;
        virtualListHead.Flink = NULL;
        virtualListHead.Blink = NULL;
        printListRSL(g_headRSL);
        return STATUS_SUCCESS;
    }
    else
    {
        //如果继续搜索没找到，那么置NULL报空：
        g_headRSL = NULL;
        DbgPrint("变小搜索结果：空链表！");
        //并把g_mostRecentPatternLen置零。
        g_mostRecentPatternLen = 0x0;
        return STATUS_UNSUCCESSFUL;
    }
}
NTSTATUS continueSearchMode_Unchanged(
    // Inner using GLOBAL DEFINITIONS: 
    // g_mostRecentPatternLen 
    // g_headRSL
)
{
    //不用验证g_headRSL有效性，走到这个逻辑之前已经验过了：
    LIST_ENTRY virtualListHead = { 0 };
    virtualListHead.Flink = &g_headRSL->ResultAddressEntry;
    CONTAINING_RECORD(g_headRSL->ResultAddressEntry.Blink, RSL, ResultAddressEntry)->ResultAddressEntry.Flink = &virtualListHead;
    virtualListHead.Blink = &CONTAINING_RECORD(g_headRSL->ResultAddressEntry.Blink, RSL, ResultAddressEntry)->ResultAddressEntry;
    g_headRSL->ResultAddressEntry.Blink = &virtualListHead;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PLIST_ENTRY temp = &virtualListHead;
    PsLookupProcessByProcessId((HANDLE)g_cid.UniqueProcess, &pe);
    KeStackAttachProcess(pe, &apc);
    while (temp->Flink != &virtualListHead)
    {
        PRSL curr = CONTAINING_RECORD(temp->Flink, RSL, ResultAddressEntry);
        if (farBytesDiffer(curr->buffer, (PUCHAR)curr->address, g_mostRecentPatternLen) != 0)
        {
            curr->ResultAddressEntry.Blink->Flink = curr->ResultAddressEntry.Flink;
            curr->ResultAddressEntry.Flink->Blink = curr->ResultAddressEntry.Blink;
            ExFreePool(curr);
            curr = NULL;
        }
        else
        {
            temp = temp->Flink;
        }
    }
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    if (virtualListHead.Flink != &virtualListHead)
    {
        PRSL newHead = CONTAINING_RECORD(virtualListHead.Flink, RSL, ResultAddressEntry);
        PRSL newTail = CONTAINING_RECORD(virtualListHead.Blink, RSL, ResultAddressEntry);
        newHead->ResultAddressEntry.Blink = &newTail->ResultAddressEntry;
        newTail->ResultAddressEntry.Flink = &newHead->ResultAddressEntry;
        g_headRSL = newHead;
        virtualListHead.Flink = NULL;
        virtualListHead.Blink = NULL;
        printListRSL(g_headRSL);
        return STATUS_SUCCESS;
    }
    else
    {
        //如果继续搜索没找到，那么置NULL报空：
        g_headRSL = NULL;
        DbgPrint("未变动搜索结果：空链表！");
        //并把g_mostRecentPatternLen置零。
        g_mostRecentPatternLen = 0x0;
        return STATUS_UNSUCCESSFUL;
    }
}
______LONG_FUNCTION_EXTRACT______;
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
        if(g_headVAL != NULL)
        {
            DbgPrint("Process Memoty Loading Successfully");
            IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
            return STATUS_SUCCESS;
        }
        else
        {
            DbgPrint("Process Memoty Loading Failed! Please Stop and Unloading Driver");
            IOCTL_COMPLETE_MARK(STATUS_UNSUCCESSFUL, 0);
            return STATUS_UNSUCCESSFUL;
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
            g_mostRecentPatternLen = tempBufferLen;
            buildDoubleLinkedAddressListForPatternStringByKMPAlgorithm(
                (ULONG64)g_cid.UniqueProcess,
                g_headVAL,
                tempBuffer,
                g_mostRecentPatternLen,
                &g_headRSL
            );
            if (g_headRSL == NULL)
            {
                DbgPrint("第一次没搜到");
                //没搜到，把最近一次的长度置0：
                g_mostRecentPatternLen = 0x0;
                IOCTL_COMPLETE_MARK(STATUS_UNSUCCESSFUL, 0);
                return STATUS_UNSUCCESSFUL;
            }
            DbgPrint("第一次搜索结果：");
            printListRSL(g_headRSL);
            //第一次搜到了！此时，g_headRSL/g_mostRecentPattern是有效值，g_mostRecentPatternLen非零。
            //请求完成，释放内存：
            ExFreePool(tempBuffer);
            IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
            return STATUS_SUCCESS;
        }
        else //继续搜索逻辑
        {
            //如果执行到继续搜索，那么此时g_headRSL/g_mostRecentPatternLen应当都是有效值；
            //它们保存了第一次搜索后的地址结果链表和第一次搜索的模式串长度；
            //这一步验证两值是否有效。只要有一个无效就直接不加处理驳回请求。
            if (g_headRSL == NULL || g_mostRecentPatternLen == 0)
            {
                DbgPrint("结果链表为空，请进行首次搜索.");
                IOCTL_COMPLETE_MARK(STATUS_INVALID_ADDRESS, 0);
                return STATUS_UNSUCCESSFUL;
            }
            ______FURTHER_SEARCH_OPTIONS______
            //接下来是详细搜索模式判断：
            if (receiveStructPointer->scanMode == 0)
            {
                // isFirstScan:0 // pattern: valid address // patternLen: valid number // scanMode: 0 //
                PUCHAR tempBuffer = (PUCHAR)ExAllocatePoolWithTag(PagedPool, receiveStructPointer->patternLen, 'LLLL');
                SIZE_T tempBufferLen = receiveStructPointer->patternLen;
                for (size_t j = 0; j < receiveStructPointer->patternLen && tempBuffer; j++)
                {
                    tempBuffer[j] = receiveStructPointer->pattern[j];
                }
                NTSTATUS retStatus = continueSearchMode_Precise(tempBuffer, tempBufferLen);
                ExFreePool(tempBuffer);
                IOCTL_COMPLETE_MARK(retStatus, 0);
                return retStatus;
            }
            else if (receiveStructPointer->scanMode == 1)
            {
                // isFirstScan:0 // pattern: NULL // patternLen: 0 // scanMode: 1 //
                NTSTATUS retStatus = continueSearchMode_Larger();
                IOCTL_COMPLETE_MARK(retStatus, 0);
                return retStatus;
            }
            else if (receiveStructPointer->scanMode == 2)
            {
                // isFirstScan:0 // pattern: NULL // patternLen: 0 // scanMode: 2 //
                NTSTATUS retStatus = continueSearchMode_Lower();
                IOCTL_COMPLETE_MARK(retStatus, 0);
                return retStatus;
            }
            else if (receiveStructPointer->scanMode == 3)
            {
                // isFirstScan:0 // pattern: NULL // patternLen: 0 // scanMode: 3 //
                NTSTATUS retStatus = continueSearchMode_Unchanged();
                IOCTL_COMPLETE_MARK(retStatus, 0);
                return retStatus;
            }
            ______FURTHER_SEARCH_OPTIONS______
            else
            {
                IOCTL_COMPLETE_MARK(STATUS_INVALID_LABEL, 0);
                return STATUS_INVALID_LABEL;
            }
        }
    }
    else if (controlCode == ____$_STOP_SEARCH_PATTERN_$____)
    {
        if (g_headRSL)
        {
            ExFreeResultSavedLink(&g_headRSL);
            g_headRSL = NULL;
        }
        g_mostRecentPatternLen = 0x0;
        IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    else if (controlCode == ____$_UNLOAD_DRIVER_PREPARE_$____)
    {
        if (g_headVAL)
        {
            ExFreeValidAddressLink(&g_headVAL);
            g_headVAL = NULL;
        }
        if (g_headRSL)
        {
            ExFreeResultSavedLink(&g_headRSL);
            g_headRSL = NULL;
        }
        if (g_kernelProcess)
        {
            ZwClose(g_kernelProcess);
        }
        g_mostRecentPatternLen = 0x0;
        IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    else
    {
        IOCTL_COMPLETE_MARK(STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
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
