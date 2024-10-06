#include "DebugeeHeader.h"
#include "DriverUserInteraction.h"

typedef NTSTATUS(*typeNtQueryPerformanceCounter)(
    _Out_     PLARGE_INTEGER PerformanceCounter,
    _Out_opt_ PLARGE_INTEGER PerformanceFrequency
    );

ULONG g_oldRellocationOffset = 0x0;

LARGE_INTEGER g_initialStartTime = { 0 };

typeNtQueryPerformanceCounter g_originalNtQueryPerformanceCounter = NULL;

NTSTATUS myNtQueryPerformanceCounter(
    PLARGE_INTEGER PerformanceCounter,
    PLARGE_INTEGER PerformanceFrequency
)
{
    NTSTATUS status = g_originalNtQueryPerformanceCounter(PerformanceCounter, PerformanceFrequency);
    PerformanceCounter->QuadPart = g_initialStartTime.QuadPart + (PerformanceCounter->QuadPart - g_initialStartTime.QuadPart) * 30;
    return status;
}

VOID driverUnload(PDRIVER_OBJECT DriverObject)
{
    DbgPrint("Unloading Driver...\n");
    hookSSDTRestore(49, g_oldRellocationOffset);
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    driverObject->DriverUnload = driverUnload;
    g_originalNtQueryPerformanceCounter = (typeNtQueryPerformanceCounter)getSSDTFunctionAddressByIndex(49);
    g_originalNtQueryPerformanceCounter(&g_initialStartTime, NULL);
    DbgPrint("%llx", g_initialStartTime.QuadPart);
    g_oldRellocationOffset = hookSSDTProcedure(49, (ULONG64)myNtQueryPerformanceCounter);
    return STATUS_SUCCESS;  
}
