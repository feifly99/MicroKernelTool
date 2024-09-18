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
    //链表遍历：
    PRSL tempRSL = g_headRSL;
    PRSL newRSLhead = NULL;
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PsLookupProcessByProcessId((HANDLE)g_cid.UniqueProcess, &pe);
    KeStackAttachProcess(pe, &apc);
    while (tempRSL->ResultAddressEntry.Flink != &g_headRSL->ResultAddressEntry)
    {
        if (isSame((PUCHAR)tempRSL->address, newReceivedPattern, newReceivedPatternLen))
        {
            if (newRSLhead == NULL)
            {
                newRSLhead = createSavedResultNode(2, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
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
                PRSL newNode = createSavedResultNode(2, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
                if (newNode)
                {
                    temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                    newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                    (newRSLhead)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                }
            }
        }
        memcpy((PVOID)tempRSL->buffer, (PVOID)tempRSL->address, g_mostRecentPatternLen);
        tempRSL = CONTAINING_RECORD(tempRSL->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
    }
    //上面的while不会遍历到最后一个节点。这是对链表的最后一个节点进行判断。重复逻辑，不用管：
    if (isSame((PUCHAR)tempRSL->address, newReceivedPattern, newReceivedPatternLen))
    {
        if (newRSLhead == NULL)
        {
            newRSLhead = createSavedResultNode(2, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
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
            PRSL newNode = createSavedResultNode(2, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
            if (newNode)
            {
                temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                newNode->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                (newRSLhead)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
            }
        }
    }
    memcpy((PVOID)tempRSL->buffer, (PVOID)tempRSL->address, g_mostRecentPatternLen);
    //链表最后一个节点也处理完毕，接下来解除挂靠：
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    //释放老链表：
    ExFreeResultSavedLink(&g_headRSL);
    //把新链表头赋值给g_headRSL：
    g_headRSL = newRSLhead;
    //如果继续搜索搜到了，那么打印链表
    if (g_headRSL)
    {
        //注意此时g_mostRecentPatternLen非0！
        printListRSL(g_headRSL);
        return STATUS_SUCCESS;
    }
    else
    {
        //如果继续搜索没找到，那么报空：
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
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PRSL tempRSL = g_headRSL;
    PRSL newRSLhead = NULL;
    PsLookupProcessByProcessId(g_cid.UniqueProcess, &pe);
    KeStackAttachProcess(pe, &apc);
    while (tempRSL->ResultAddressEntry.Flink != &g_headRSL->ResultAddressEntry)
    {
        if (farBytesDiffer(tempRSL->buffer, (PUCHAR)tempRSL->address, g_mostRecentPatternLen) == 2)
        {
            if (newRSLhead == NULL)
            {
                newRSLhead = createSavedResultNode(3, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
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
                PRSL newNode = createSavedResultNode(3, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
                if (newNode)
                {
                    temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                    newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                    (newRSLhead)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                }
            }
        }
        memcpy((PVOID)tempRSL->buffer, (PVOID)tempRSL->address, g_mostRecentPatternLen);
        tempRSL = CONTAINING_RECORD(tempRSL->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
    }
    if (farBytesDiffer(tempRSL->buffer, (PUCHAR)tempRSL->address, g_mostRecentPatternLen) == 2)
    {
        if (newRSLhead == NULL)
        {
            newRSLhead = createSavedResultNode(3, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
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
            PRSL newNode = createSavedResultNode(3, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
            if (newNode)
            {
                temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                newNode->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                (newRSLhead)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
            }
        }
    }
    memcpy((PVOID)tempRSL->buffer, (PVOID)tempRSL->address, g_mostRecentPatternLen);
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    ExFreeResultSavedLink(&g_headRSL);
    //把新链表头赋值给g_headRSL：
    g_headRSL = newRSLhead;
    //如果继续搜索搜到了，那么打印链表
    if (g_headRSL)
    {
        //注意此时g_mostRecentPatternLen非0！
        printListRSL(g_headRSL);
        return STATUS_SUCCESS;
    }
    else
    {
        //如果继续搜索没找到，那么报空：
        DbgPrint("变大数值搜索：空链表！");
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
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PRSL tempRSL = g_headRSL;
    PRSL newRSLhead = NULL;
    PsLookupProcessByProcessId(g_cid.UniqueProcess, &pe);
    KeStackAttachProcess(pe, &apc);
    while (tempRSL->ResultAddressEntry.Flink != &g_headRSL->ResultAddressEntry)
    {
        if (farBytesDiffer(tempRSL->buffer, (PUCHAR)tempRSL->address, g_mostRecentPatternLen) == 1)
        {
            if (newRSLhead == NULL)
            {
                newRSLhead = createSavedResultNode(4, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
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
                PRSL newNode = createSavedResultNode(4, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
                if (newNode)
                {
                    temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                    newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                    (newRSLhead)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                }
            }
        }
        memcpy((PVOID)tempRSL->buffer, (PVOID)tempRSL->address, g_mostRecentPatternLen);
        tempRSL = CONTAINING_RECORD(tempRSL->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
    }
    if (farBytesDiffer(tempRSL->buffer, (PUCHAR)tempRSL->address, g_mostRecentPatternLen) == 1)
    {
        if (newRSLhead == NULL)
        {
            newRSLhead = createSavedResultNode(4, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
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
            PRSL newNode = createSavedResultNode(4, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
            if (newNode)
            {
                temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                newNode->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                (newRSLhead)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
            }
        }
    }
    memcpy((PVOID)tempRSL->buffer, (PVOID)tempRSL->address, g_mostRecentPatternLen);
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    ExFreeResultSavedLink(&g_headRSL);
    //把新链表头赋值给g_headRSL：
    g_headRSL = newRSLhead;
    //如果继续搜索搜到了，那么打印链表
    if (g_headRSL)
    {
        //注意此时g_mostRecentPatternLen非0！
        printListRSL(g_headRSL);
        return STATUS_SUCCESS;
    }
    else
    {
        //如果继续搜索没找到，那么报空：
        DbgPrint("变小数值搜索：空链表！");
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
    PEPROCESS pe = NULL;
    KAPC_STATE apc = { 0 };
    PRSL tempRSL = g_headRSL;
    PRSL newRSLhead = NULL;
    PsLookupProcessByProcessId(g_cid.UniqueProcess, &pe);
    KeStackAttachProcess(pe, &apc);
    while (tempRSL->ResultAddressEntry.Flink != &g_headRSL->ResultAddressEntry)
    {
        if (farBytesDiffer(tempRSL->buffer, (PUCHAR)tempRSL->address, g_mostRecentPatternLen) == 0)
        {
            if (newRSLhead == NULL)
            {
                newRSLhead = createSavedResultNode(5, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
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
                PRSL newNode = createSavedResultNode(5, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
                if (newNode)
                {
                    temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                    newNode->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                    newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                    (newRSLhead)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
                }
            }
        }
        memcpy((PVOID)tempRSL->buffer, (PVOID)tempRSL->address, g_mostRecentPatternLen);
        tempRSL = CONTAINING_RECORD(tempRSL->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
    }
    if (farBytesDiffer(tempRSL->buffer, (PUCHAR)tempRSL->address, g_mostRecentPatternLen) == 0)
    {
        if (newRSLhead == NULL)
        {
            newRSLhead = createSavedResultNode(5, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
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
            PRSL newNode = createSavedResultNode(5, tempRSL->address, g_mostRecentPatternLen, g_headVAL);
            if (newNode)
            {
                temp->ResultAddressEntry.Flink = &newNode->ResultAddressEntry;
                newNode->ResultAddressEntry.Flink = &((newRSLhead)->ResultAddressEntry);
                newNode->ResultAddressEntry.Blink = &temp->ResultAddressEntry;
                (newRSLhead)->ResultAddressEntry.Blink = &newNode->ResultAddressEntry;
            }
        }
    }
    memcpy((PVOID)tempRSL->buffer, (PVOID)tempRSL->address, g_mostRecentPatternLen);
    tempRSL = CONTAINING_RECORD(tempRSL->ResultAddressEntry.Flink, RSL, ResultAddressEntry);
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(pe);
    ExFreeResultSavedLink(&g_headRSL);
    //把新链表头赋值给g_headRSL：
    g_headRSL = newRSLhead;
    //如果继续搜索搜到了，那么打印链表
    if (g_headRSL)
    {
        //注意此时g_mostRecentPatternLen非0！
        printListRSL(g_headRSL);
        return STATUS_SUCCESS;
    }
    else
    {
        //如果继续搜索没找到，那么报空：
        DbgPrint("未变动数值搜索：空链表！");
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
