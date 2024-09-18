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
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\ANYIFEI_DEVICE_NAME");
    PDEVICE_OBJECT devObj = NULL;
    IoCreateDevice(driverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &devObj);
    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\??\\ANYIFEI_SYMBOLINK_NAME");
    IoCreateSymbolicLink(&symName, &devName);
    driverObject->Flags |= DO_BUFFERED_IO;
    driverObject->MajorFunction[IRP_MJ_CREATE] = myCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = myClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Driver_User_IO_Interaction_Entry;
    driverObject->DriverUnload = driverUnload;
    __PLACE_HOLDER__
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
