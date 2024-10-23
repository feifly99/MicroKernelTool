#include "DriverUserInteractionHeader.h"

CONST INT _fltused = 0;

ULONG64 targetFuncAddress = 0xfffff80077c17100;

VOID driverUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING reg_path)
{
	UNREFERENCED_PARAMETER(reg_path);
	driverObject->DriverUnload = driverUnload;
    ULONG64 cr3 = getCR3SaferByPID(0x3384);
    UCHAR x[8] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
    writePhysicalMemory(getPhysicalAddressByCR3AndVirtualAddress(cr3, 0x7FFC5843D1B8), x, 8);
    return STATUS_SUCCESS;
}
