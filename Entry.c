#include "DebugeeHeader.h"
#include "DriverUserInteraction.h"

#define ntoskrnlBase 0xFFFFF80050000000

VOID driverUnload(PDRIVER_OBJECT DriverObject)
{
    DbgPrint("Unloading Driver...\n");
    /*UNICODE_STRING sybName = RTL_CONSTANT_STRING(L"\\??\\ANYIFEI_SYMBOLICLINK_NAME");
    IoDeleteDevice(DriverObject->DeviceObject);
    IoDeleteSymbolicLink(&sybName);*/
    //protectProcessRestore();
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    /*UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\ANYIFEI_DEVICE_NAME");
    PDEVICE_OBJECT devObj = NULL;
    IoCreateDevice(driverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &devObj);
    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\ANYIFEI_SYMBOLINK_NAME");
    IoCreateSymbolicLink(&symName, &devName);
    driverObject->Flags |= DO_BUFFERED_IO;
    driverObject->MajorFunction[IRP_MJ_CREATE] = myCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = myClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Driver_User_IO_Interaction_Entry;*/
    driverObject->DriverUnload = driverUnload;
    //displayAllModuleInfomationByProcessId(0x228);
    //displayAllThreadInfomationByProcessId(0x228);
    //protectProcessProcedure();
    //displayKernelModules(driverObject);
    SIZE_T numsTotal = 0x0, numsName = 0x0, numsDiffer = 0x0;
    __asm__getFuncNumsExportedTotal_Via_DllBase((PVOID)ntoskrnlBase, &numsTotal);
    __asm__getFuncNumsExportedByName_Via_DllBase((PVOID)ntoskrnlBase, &numsName);
    numsDiffer = numsTotal - numsName;
    ULONG64 nameAddress = 0x0;
    ULONG64 funcAddress = 0x0;
    DbgPrint("total: %zu, nameExported: %zu, diff: %zu", numsTotal, numsName, numsDiffer);
    for (SIZE_T j = 0; j < numsName; j++)
    {
        __asm__getFuncNameByIndex_Via_DllBase((PVOID)ntoskrnlBase, j, &nameAddress);
        __asm__getFuncAddressByIndex_Via_DllBase((PVOID)ntoskrnlBase, numsDiffer, j, &funcAddress);
        DbgPrint("index: %zu, name: %s", j, (CHAR*)nameAddress);
        DbgPrint("index: %zu, address: 0x%p", j, (PVOID)funcAddress);
    }
    return STATUS_SUCCESS;
}

//第一次走用户联立驱动发现停止驱动蓝屏报错SYSTEM_THREAD_XXX_NOT_HANDLED原因：设备和符号链接创建失败，导致删除了不存在的对象指针；
//创建失败原因：没加\\Device\\前缀

//链接不上，原因：名字
//设备名称前面是\\Device\\
//符号链接名称前面是\\??\\
//注意符号链接名字

//只显示那个但是没有遍历，因为忘了ZWOPENPROCESS。
//这里长记性：要记得加错误处理！

//OPENPROCESS之后build还是不显示，原因：第一个参数传错了！

//驱动停止走的是DRIVER_UNLOAD，在不交互用户的情况下记得清理DRIVER_UNLOAD的不必要的东西，比如根本就
//不存在的符号链接！！！

//    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, &threadObj, hProcess, &receiveCID, (PKSTART_ROUTINE)&testRoutine, (PVOID)inputArgs);
//    OBJECT_ATTRIBUTES threadObj = { 0 };
//    InitializeObjectAttributes(&threadObj, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);


//KiSystemServiceRepeat: 4c 8d 15 35 f7 9e 00  
//--->4c 8d 15 35 f7 9e 00    lea    r10,[rip+0x9ef735]        # nt!KeServiceDescriptorTable (0xfffff807512018c0)
//KiSystemServiceRepeat + 0x7: 4c 8d 1d ae a8 8e 00  
//--->4c 8d 1d ae a8 8e 00    lea    r11,[rip+0x8ea8ae]        # nt!KeServiceDescriptorTableShadow (0xfffff807510fca40)
