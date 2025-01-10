#include "DriverUserInteractionHeader.h"

#pragma warning(disable: 28182)
#pragma warning(disable: 6011)

CONST INT _fltused = 0;

VOID driverUnload(PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);
    DbgPrint("Driver Unload");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING reg_path)
{
    UNREFERENCED_PARAMETER(reg_path);
    driverObject->DriverUnload = driverUnload;

    UNICODE_STRING dllFullPath = RTL_CONSTANT_STRING(L"D:\\testDLL.dll");
    dllInjectionByRemoteThread((PUCHAR)"League of Legends.exe", &dllFullPath);
    return STATUS_SUCCESS;
}
