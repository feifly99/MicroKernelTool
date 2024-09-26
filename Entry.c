#include "DebugeeHeader.h"
#include "DriverUserInteraction.h"

#define processIDWantToProtect 13152

NTSTATUS MyNtOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
)
{
    if (ClientId->UniqueProcess == (HANDLE)processIDWantToProtect)
    {
        *ProcessHandle = NULL;
        return STATUS_UNSUCCESSFUL;
    }
    else
    {
        return NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
}

typedef struct _InputArgs
{
    PVOID newAddressToExecute;
    PVOID newAddressSavedDLLFullPath;
}IA, *PIA;

NTSTATUS testRoutine(PVOID inputArgs) //R3 memory avaliable
{
    UNREFERENCED_PARAMETER(inputArgs);
    return STATUS_SUCCESS;
}

VOID driverUnload(PDRIVER_OBJECT DriverObject)
{
    DbgPrint("Unloading Driver...\n");
    /*UNICODE_STRING sybName = RTL_CONSTANT_STRING(L"\\??\\ANYIFEI_SYMBOLICLINK_NAME");
    IoDeleteDevice(DriverObject->DeviceObject);
    IoDeleteSymbolicLink(&sybName);*/
    UCHAR newFucker[4] =
    {
        0x00, 0x8c, 0xb4, 0x05
    };
    ULONG64 oldCR0 = 0x0;
    __asm__WRbreak(&oldCR0);
    memcpy((PVOID)0xfffff806160c7c38, newFucker, 4);
    __asm__WRrestore(oldCR0);
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
    ULONG64 KiSystemCall64ShadowAddress = __asm__readMSR(0xC0000082);
    ULONG64 KiSystemServiceStart = KiSystemCall64ShadowAddress - 0x6073C0 + 0x370;
    DbgPrint("KiSystemServiceStart: %llx", KiSystemServiceStart);
    ULONG64 KiSystemServiceRepeat = KiSystemServiceStart + 0x14;
    ULONG64 currentRIPAddress = KiSystemServiceRepeat + 14;
    ULONG keyOffset = *(ULONG*)(KiSystemServiceRepeat + 0xA);
    ULONG64 SSDT_Address = currentRIPAddress + keyOffset;
    DbgPrint("%llx", SSDT_Address);
    ULONG64 SSDT_ServiceTableBase = *(ULONG64*)SSDT_Address;
    ULONG64 SSDT_NumberOfServices = *(ULONG64*)(SSDT_Address + 0x10);
    DbgPrint("SSDT_ServiceTableBase: %llx", SSDT_ServiceTableBase);
    DbgPrint("SSDT_NumberOfServices: %llx", SSDT_NumberOfServices);
    /*for (SIZE_T j = 0; j < SSDT_NumberOfServices - 1; j++)
    {
        DbgPrint("index: %llx, funcAddress: 0x%p", j, (PVOID)(((*(ULONG*)(SSDT_ServiceTableBase + j * 4)) >> 4) + SSDT_ServiceTableBase));
    }*/
    ULONG64 NtOpenProcessAddress = (ULONG64)(((*(ULONG*)(SSDT_ServiceTableBase + 38 * 4)) >> 4) + SSDT_ServiceTableBase);
    DbgPrint("NtOpenProcessAddress: 0x%p", (PVOID)NtOpenProcessAddress);
    ULONG64 MyNtOpenProcessAddress = (ULONG64)MyNtOpenProcess;
    DbgPrint("MyNtOpenProcessAddress: 0x%p", (PVOID)MyNtOpenProcessAddress);
    ULONG64 diff = MyNtOpenProcessAddress - SSDT_ServiceTableBase;
    DbgPrint("%llx", diff);
    UCHAR* pointer = (UCHAR*) & MyNtOpenProcessAddress;
    /*for (size_t j = 0; j < 8; j++)
    {
        DbgPrint("%hhx", *(pointer + j));
    }*/
    UCHAR shellCode[12] =
    {
        0x48, 0xB8, pointer[0], pointer[1], pointer[2], pointer[3], pointer[4], pointer[5], pointer[6], pointer[7],
        //mov rax, qword ptr [(_longlong64)pointer_(MyNtOpenProcessAddress)]
        0xFF, 0xE0
        //jmp rax
    };
    ULONG64 oldCR0 = 0x0;
    __asm__WRbreak(&oldCR0);
    memcpy((PVOID)(NtOpenProcessAddress - 13), shellCode, 12);
    __asm__WRrestore(oldCR0);
    ULONG64 newDiffer = NtOpenProcessAddress - 13 - SSDT_ServiceTableBase;
    DbgPrint("%llx", newDiffer);
    //SSDT_BASE[index] >> 4 + SSDT_BASE = (_longlong)funcBase[index];
    UCHAR fucker[4] =
    {
        0x30, 0x8B, 0xB4, 0x05 //0x05B48B3X >> 4 = 0x005B48B3, 加上SSDT偏移直接定位到上面的shellCode.
    };
    oldCR0 = 0x0;
    __asm__WRbreak(&oldCR0);
    memcpy((PVOID)(SSDT_ServiceTableBase + 0x90 + 0x8), fucker, 4);
    __asm__WRrestore(oldCR0);
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
