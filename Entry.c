#include "DebugeeHeader.h"
#include "DriverUserInteraction.h"

VOID driverUnload(PDRIVER_OBJECT DriverObject)
{
    DbgPrint("Unloading Driver...\n");
    UNICODE_STRING sybName = RTL_CONSTANT_STRING(L"\\??\\ANYIFEI_SYMBOLICLINK_NAME");
    IoDeleteDevice(DriverObject->DeviceObject);
    IoDeleteSymbolicLink(&sybName);
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    driverObject->Flags |= DO_BUFFERED_IO;
    PDEVICE_OBJECT devObj = NULL;
    UNICODE_STRING devName = { 0 };
    RtlInitUnicodeString(&devName, L"\\Device\\ANYIFEI_device_NAME");
    if (NT_SUCCESS(IoCreateDevice(driverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &devObj)))
    {
        DbgPrint("创建设备成功");
    }
    UNICODE_STRING sybName = { 0 };
    RtlInitUnicodeString(&sybName, L"\\??\\ANYIFEI_SYMBOLICLINK_NAME");
    if (NT_SUCCESS(IoCreateSymbolicLink(&sybName, &devName)))
    {
        DbgPrint("创建符号链接成功");
    }
    driverObject->DriverUnload = driverUnload;
    driverObject->MajorFunction[IRP_MJ_CREATE] = myCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = myClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Driver_User_IO_Interaction_Entry;
    DbgPrint("go");
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
