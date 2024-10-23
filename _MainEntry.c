#include "DriverUserInteractionHeader.h"

CONST INT _fltused = 0;

ULONG64 targetFuncAddress = 0xfffff80077c17100;

VOID driverUnload(PDRIVER_OBJECT driverObject)
{
    /*UNICODE_STRING deviceSymbolicName = { 0 };
    RtlInitUnicodeString(&deviceSymbolicName, L"\\??\\ANYIFEI_SYMBOLINK_NAME");
    IoDeleteSymbolicLink(&deviceSymbolicName);
    IoDeleteDevice(driverObject->DeviceObject);*/
    /*UCHAR restoreCode[12] =
    {
        0xf6, 0x44, 0x24, 0x08, 0x01, 0x74, 0x67, 0x0f, 0x01, 0xf8, 0x0f, 0xae
    };
    CR0breakOperation(memcpy((PVOID)targetFuncAddress, restoreCode, 12););*/
	UNREFERENCED_PARAMETER(driverObject);
	return;
}

VOID testx()
{
    DbgPrint("here!");
    UCHAR restoreCode[12] =
    {
        0xf6, 0x44, 0x24, 0x08, 0x01, 0x74, 0x67, 0x0f, 0x01, 0xf8, 0x0f, 0xae
    };
    CR0breakOperation(memcpy((PVOID)targetFuncAddress, restoreCode, 12););
    __asm__jump(targetFuncAddress);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING reg_path)
{
	UNREFERENCED_PARAMETER(reg_path);
	driverObject->DriverUnload = driverUnload;
    /*driverObject->Flags |= DO_BUFFERED_IO;
    PDEVICE_OBJECT devObj = NULL;
    UNICODE_STRING deviceName = { 0 };
    RtlInitUnicodeString(&deviceName, L"\\Device\\ANYIFEI_device_NAME");
    UNICODE_STRING deviceSymbolicName = { 0 };
    RtlInitUnicodeString(&deviceSymbolicName, L"\\??\\ANYIFEI_SYMBOLINK_NAME");
    IoCreateDevice(driverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, TRUE, &devObj);
    IoCreateSymbolicLink(&deviceSymbolicName, &deviceName);
    driverObject->MajorFunction[IRP_MJ_CREATE] = myCreate;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = myClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Driver_User_IO_Interaction_Entry;*/
    //f6 44 24 08 01 74 67 0f-01 f8 0f ae
    /*ULONG64 tempFunc = (ULONG64)testx;
    UCHAR testsss[12] =
    {
        0x48, 0xB8,
        ((UCHAR*)&tempFunc)[0],
        ((UCHAR*)&tempFunc)[1],
        ((UCHAR*)&tempFunc)[2],
        ((UCHAR*)&tempFunc)[3],
        ((UCHAR*)&tempFunc)[4],
        ((UCHAR*)&tempFunc)[5],
        ((UCHAR*)&tempFunc)[6],
        ((UCHAR*)&tempFunc)[7],
        0xFF,0xE0
    };
    CR0breakOperation(memcpy((PVOID)targetFuncAddress, testsss, 12););*/
    ULONG64 cr3 = getCR3SaferByPID(0x3384);
    UCHAR x[8] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
    writePhysicalMemory(getPhysicalAddressByCR3AndVirtualAddress(cr3, 0x7FFC5843D1B8), x, 8);
    return STATUS_SUCCESS;
}
