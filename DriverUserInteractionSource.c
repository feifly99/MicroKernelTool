#include "DriverUserInteractionHeader.h"

#pragma warning(disable:6387)
#pragma warning(disable:6011)
#pragma warning(disable:4702)

__SEARCH_PROCEDURE_DEFINES__;
static CLIENT_ID g_cid = { 0 };
__SEARCH_PROCEDURE_DEFINES__;

__PROCESS_MEMORY_SPACE_DEFINES__;
static PVAL g_headVAL = NULL;
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
    log(最新.);
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
    irpSL->Parameters.Read.Length;
    ULONG controlCode = irpSL->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS retSt = STATUS_SUCCESS;
    __DRIVER_USER_IO_ENTRY_PUBLIC_SETTINGS__;
    switch (controlCode)
    {
        case ____$_PREPARE_SEARCH_PROCEDURE_$____:
        {
            ULONG64 pid = *(ULONG64*)pIrp->AssociatedIrp.SystemBuffer;
            g_cid.UniqueProcess = (HANDLE)pid;
            g_cid.UniqueThread = NULL;
            OBJECT_ATTRIBUTES obja = { 0 };
            InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
            log(开始初始化进程内存...);
            buildValidAddressSingleList(
                (ULONG64)g_cid.UniqueProcess,
                &g_headVAL,
                0x00007FFF00000000
            );
            getRegionGapAndPages(g_headVAL);
            if (g_headVAL != NULL)
            {
                log(进程内存初始化成功.);
                IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            }
            else
            {
                log(进程内存初始化失败！);
                IOCTL_COMPLETE_MARK(retSt, STATUS_UNSUCCESSFUL, 0);
            }
            break;
        }
        case ____$_ENTER_SEARCH_PROCEDURE_$____:
        {
            //在此case中内核可以借用SystemBuffer来临时访问用户层地址，即DbgPrint("%d", *(INT*)si->u.precise.ptr2Value); 可以成功打印用户层指针的内容.
            //1.(System)Buffer本地化; 2.地址内核化.
            PSI si = (PSI)ExAllocatePoolWithTag(NonPagedPool, sizeof(SI), 'z+aa');
            RtlZeroMemory(si, sizeof(SI));
            PSI nonStableSi = (PSI)pIrp->AssociatedIrp.SystemBuffer;
            RtlCopyMemory(si, nonStableSi, sizeof(SI));
            //用户地址内核化：
            switch (si->memberType)
            {
                case UNION_MEMBER_PRECISE:
                {
                    switch (si->valueType)
                    {
                        case TYPE_BYTE:
                        {
                            UCHAR* x = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, sizeof(UCHAR), 'z+aa');
                            RtlZeroMemory(x, sizeof(UCHAR));
                            RtlCopyMemory(x, si->u.precise.ptr2Value, sizeof(UCHAR));
                            si->u.precise.ptr2Value = x;
                            break;
                        }
                        case TYPE_WORD:
                        {
                            USHORT* x = (USHORT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(USHORT), 'z+aa');
                            RtlZeroMemory(x, sizeof(USHORT));
                            RtlCopyMemory(x, si->u.precise.ptr2Value, sizeof(USHORT));
                            si->u.precise.ptr2Value = x;
                            break;
                        }
                        case TYPE_DWORD:
                        {
                            UINT* x = (UINT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(UINT), 'z+aa');
                            RtlZeroMemory(x, sizeof(UINT));
                            RtlCopyMemory(x, si->u.precise.ptr2Value, sizeof(UINT));
                            si->u.precise.ptr2Value = x;
                            break;
                        }
                        case TYPE_QWORD:
                        {
                            ULONG64* x = (ULONG64*)ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG64), 'z+aa');
                            RtlZeroMemory(x, sizeof(ULONG64));
                            RtlCopyMemory(x, si->u.precise.ptr2Value, sizeof(ULONG64));
                            si->u.precise.ptr2Value = x;
                            break;
                        }
                        default:
                        {
                            break;
                        }
                    }
                    break;
                }
                case UNION_MEMBER_REGION:
                {
                    switch (si->valueType)
                    {
                        case TYPE_BYTE:
                        {
                            UCHAR* l = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, sizeof(UCHAR), 'z+aa');
                            RtlZeroMemory(l, sizeof(UCHAR));
                            RtlCopyMemory(l, si->u.region.ptr2LowerBound, sizeof(UCHAR));
                            si->u.region.ptr2LowerBound = l;
                            UCHAR* h = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, sizeof(UCHAR), 'z+aa');
                            RtlZeroMemory(h, sizeof(UCHAR));
                            RtlCopyMemory(h, si->u.region.ptr2HigherBound, sizeof(UCHAR));
                            si->u.region.ptr2HigherBound = h;
                            break;
                        }
                        case TYPE_WORD:
                        {
                            USHORT* l = (USHORT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(USHORT), 'z+aa');
                            RtlZeroMemory(l, sizeof(USHORT));
                            RtlCopyMemory(l, si->u.region.ptr2LowerBound, sizeof(USHORT));
                            si->u.region.ptr2LowerBound = l;
                            USHORT* h = (USHORT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(USHORT), 'z+aa');
                            RtlZeroMemory(h, sizeof(USHORT));
                            RtlCopyMemory(h, si->u.region.ptr2HigherBound, sizeof(USHORT));
                            si->u.region.ptr2HigherBound = h;
                            break;
                        }
                        case TYPE_DWORD:
                        {
                            UINT* l = (UINT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(UINT), 'z+aa');
                            RtlZeroMemory(l, sizeof(UINT));
                            RtlCopyMemory(l, si->u.region.ptr2LowerBound, sizeof(UINT));
                            si->u.region.ptr2LowerBound = l;
                            UINT* h = (UINT*)ExAllocatePoolWithTag(NonPagedPool, sizeof(UINT), 'z+aa');
                            RtlZeroMemory(h, sizeof(UINT));
                            RtlCopyMemory(h, si->u.region.ptr2HigherBound, sizeof(UINT));
                            si->u.region.ptr2HigherBound = h;
                            break;
                        }
                        case TYPE_QWORD:
                        {
                            ULONG64* l = (ULONG64*)ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG64), 'z+aa');
                            RtlZeroMemory(l, sizeof(ULONG64));
                            RtlCopyMemory(l, si->u.region.ptr2LowerBound, sizeof(ULONG64));
                            si->u.region.ptr2LowerBound = l;
                            ULONG64* h = (ULONG64*)ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG64), 'z+aa');
                            RtlZeroMemory(h, sizeof(ULONG64));
                            RtlCopyMemory(h, si->u.region.ptr2HigherBound, sizeof(ULONG64));
                            si->u.region.ptr2HigherBound = h;
                            break;
                        }
                        case TYPE_FLOAT:
                        {
                            float* l = (float*)ExAllocatePoolWithTag(NonPagedPool, sizeof(float), 'z+aa');
                            RtlZeroMemory(l, sizeof(float));
                            RtlCopyMemory(l, si->u.region.ptr2LowerBound, sizeof(float));
                            si->u.region.ptr2LowerBound = l;
                            float* h = (float*)ExAllocatePoolWithTag(NonPagedPool, sizeof(float), 'z+aa');
                            RtlZeroMemory(h, sizeof(float));
                            RtlCopyMemory(h, si->u.region.ptr2HigherBound, sizeof(float));
                            si->u.region.ptr2HigherBound = h;
                            break;
                        }
                        case TYPE_DOUBLE:
                        {
                            double* l = (double*)ExAllocatePoolWithTag(NonPagedPool, sizeof(double), 'z+aa');
                            RtlZeroMemory(l, sizeof(double));
                            RtlCopyMemory(l, si->u.region.ptr2LowerBound, sizeof(double));
                            si->u.region.ptr2LowerBound = l;
                            double* h = (double*)ExAllocatePoolWithTag(NonPagedPool, sizeof(double), 'z+aa');
                            RtlZeroMemory(h, sizeof(double));
                            RtlCopyMemory(h, si->u.region.ptr2HigherBound, sizeof(double));
                            si->u.region.ptr2HigherBound = h;
                            break;
                        }
                        default:
                        {
                            break;
                        }
                    }
                    break;
                }
                case UNION_MEMBER_PATTERN:
                {
                    switch (si->valueType)
                    {
                        case TYPE_PATTERN:
                        {
                            //【危险】在驱动程序中万万不可用%s输出此字符串,因为只截取了用户模式串在\0之前的部分！！！！！！
                            //【危险】必须用strncmp/循环 + %c + 长度等方式保守控制输出！！！
                            UCHAR* p = (UCHAR*)ExAllocatePoolWithTag(NonPagedPool, si->u.pattern.patternLen, 'z+aa');
                            RtlZeroMemory(p, si->u.pattern.patternLen);
                            RtlCopyMemory(p, si->u.pattern.ptr2Pattern, si->u.pattern.patternLen);
                            si->u.pattern.ptr2Pattern = p;
                            break;
                        }
                        default:
                        {
                            break;
                        }
                    }
                    break;
                }
                default:
                {
                    break;
                }
            }
            //checkSI(si);
            searchTargetBySearchInfo(si, (ULONG64)g_cid.UniqueProcess, g_headVAL, &g_headRSL);
            if (g_headRSL != NULL)
            {
                printListRSL((ULONG64)g_cid.UniqueProcess, &g_headRSL);
            }
            else
            {
                log(没东西！);
            }
            freeSI(&si);
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_STOP_SEARCH_PROCEDURE_$____:
        {
            if (g_headRSL != NULL)
            {
                ExFreeResultSavedLink(&g_headRSL);
                g_headRSL = NULL;
            }
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_GET_PROCESS_HANDLE_$____:
        {
            HANDLE pid = *(HANDLE*)pIrp->AssociatedIrp.SystemBuffer;
            CLIENT_ID cid = { 0 };
            cid.UniqueProcess = pid;
            cid.UniqueThread = NULL;
            OBJECT_ATTRIBUTES obja = { 0 };
            InitializeObjectAttributes(&obja, NULL, 0, NULL, NULL);
            HANDLE processHandle = NULL;
            ZwOpenProcess(&processHandle, GENERIC_ALL, &obja, &cid);
            *(HANDLE*)pIrp->AssociatedIrp.SystemBuffer = processHandle;
            DbgPrint("0x%p", processHandle);
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, sizeof(HANDLE));
            break;
        }
        case ____$_CLOSE_PROCESS_HANDLE_$____:
        {
            HANDLE processHandle = *(HANDLE*)pIrp->AssociatedIrp.SystemBuffer;
            if (processHandle)
            {
                ZwClose(processHandle);
                processHandle = NULL;
            }
            else
            {
                log(传入句柄为空！);
            }
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_LIST_PROCESS_MODULE_$____:
        {
            HANDLE pid = *(HANDLE*)pIrp->AssociatedIrp.SystemBuffer;
            displayAllModuleInfomationByProcessId((ULONG64)pid);
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_LIST_PROCESS_THREAD_$____:
        {
            HANDLE pid = *(HANDLE*)pIrp->AssociatedIrp.SystemBuffer;
            displayAllThreadInfomationByProcessId((ULONG64)pid);
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_READ_PROCESS_MEMORY_$____:
        {
            PRPMI inputBuffer = (PRPMI)pIrp->AssociatedIrp.SystemBuffer;
            PVOID receivedBuffer = (PVOID)ExAllocatePoolWithTag(NonPagedPool, (inputBuffer->readLength + 0xFFFull) & ~0xFFFull, 'z+aa');
            RtlZeroMemory(receivedBuffer, (inputBuffer->readLength + 0xFFFull) & ~0xFFFull);
            readProcessMemory((ULONG64)inputBuffer->pid, inputBuffer->baseAddress, inputBuffer->readLength, &receivedBuffer);
            RtlCopyMemory((PVOID)pIrp->AssociatedIrp.SystemBuffer, receivedBuffer, (inputBuffer->readLength + 0xFFFull) & ~0xFFFull);
            ExFreePool(receivedBuffer);
            receivedBuffer = NULL;
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, (inputBuffer->readLength + 0xFFFull) & ~0xFFFull);
            break;
        }
        case ____$_WRITE_PROCESS_MEMORY_$____:
        {
            PWPMI inputBuffer = (PWPMI)pIrp->AssociatedIrp.SystemBuffer;
            if (inputBuffer->accessMode == VIRTUAL_MODE)
            {
                writeProcessMemory((ULONG64)inputBuffer->pid, inputBuffer->baseAddress, inputBuffer->writeBuffer, inputBuffer->writeLength);
            }
            else
            {
                ULONG_PTR padd = getPhysicalAddressByCR3AndVirtualAddress(getCR3SaferByPID((ULONG64)inputBuffer->pid), (ULONG_PTR)inputBuffer->baseAddress);
                writePhysicalMemory(padd, inputBuffer->writeBuffer, inputBuffer->writeLength);
            }
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_PROCESS_HIDEN_PROCEDURE_$____:
        {
            ULONG64 pid = *(ULONG64*)pIrp->AssociatedIrp.SystemBuffer;
            processHiddenProcedure(pid, &g_headHPL);
            printListHPL(g_headHPL);
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_PROCESS_RESTORE_PROCEDURE_$____:
        {
            restoreHiddenProcess(&g_headHPL);
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_REBUILD_DEBUG_SYSTEM_$____:
        {
            USHORT newDebugPortOffset = *(USHORT*)pIrp->AssociatedIrp.SystemBuffer;
            USHORT oldDebugPortOffset = 0;
            rebuildDebugSystem(newDebugPortOffset, FALSE, &oldDebugPortOffset);
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_RESTORE_DEBUG_SYSTEM_$____:
        {
            USHORT oldDebugPortOffset = 0;
            rebuildDebugSystem(0x578, FALSE, &oldDebugPortOffset);
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_PROCESS_PRETENT_PROCEDURE_$____:
        {
            PPPI inputBuffer = (PPPI)pIrp->AssociatedIrp.SystemBuffer;
            processPretentProcedure(inputBuffer->ditryPID, inputBuffer->parasitePID, &g_headPPL);
            printListPPL(g_headPPL);
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_DLL_KERNELMODE_INJECTION_$____:
        {
            //demo:
            PUNICODE_STRING dllPath = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPool, sizeof(UNICODE_STRING), 'z+aa');
            RtlZeroMemory(dllPath, sizeof(UNICODE_STRING));
            UNICODE_STRING stackDllPath = RTL_CONSTANT_STRING(L"D:\\ss.dll");
            RtlCopyUnicodeString(dllPath, &stackDllPath);
            dllInjectionByRemoteThread((HANDLE)17568, dllPath);
            ExFreePool(dllPath);
            dllPath = NULL;
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        case ____$_UNLOAD_DRIVER_PREPARE_$____:
        {
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
            IOCTL_COMPLETE_MARK(retSt, STATUS_SUCCESS, 0);
            break;
        }
        default:
        {
            IOCTL_COMPLETE_MARK(retSt, STATUS_INVALID_LABEL, 0);
            break;
        }
    }
    return retSt;
}
