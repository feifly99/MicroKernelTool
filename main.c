#include "DriverUserInteractionHeader.h"

#pragma warning(disable: 28182)
#pragma warning(disable: 6011)

CONST INT _fltused = 0;

VOID driverUnload(PDRIVER_OBJECT driverObject)
{
    UNICODE_STRING deviceSymbolicName = { 0 };
    RtlInitUnicodeString(&deviceSymbolicName, L"\\??\\ANYIFEI_SYMBOLINK_NAME");
    IoDeleteSymbolicLink(&deviceSymbolicName);
    IoDeleteDevice(driverObject->DeviceObject);
    DbgPrint("Driver Unload");
    return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING reg_path)
{
    UNREFERENCED_PARAMETER(reg_path);
    driverObject->DriverUnload = driverUnload;
    driverObject->Flags |= DO_BUFFERED_IO;
    PDEVICE_OBJECT devObj = NULL;
    UNICODE_STRING deviceName = { 0 };
    RtlInitUnicodeString(&deviceName, L"\\Device\\ANYIFEI_device_NAME");
    UNICODE_STRING deviceSymbolicName = { 0 };
    RtlInitUnicodeString(&deviceSymbolicName, L"\\??\\ANYIFEI_SYMBOLINK_NAME");
    IoCreateDevice(driverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &devObj);
    IoCreateSymbolicLink(&deviceSymbolicName, &deviceName);
    driverObject->MajorFunction[IRP_MJ_CREATE] = myCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = myClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Driver_User_IO_Interaction_Entry;
    return STATUS_SUCCESS;
}
