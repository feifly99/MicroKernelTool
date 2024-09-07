#include "DebugeeHeader.h"

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    HANDLE hProcess = NULL;
    CLIENT_ID clientId;
    clientId.UniqueProcess = (HANDLE)0x228;
    clientId.UniqueThread = NULL;
    OBJECT_ATTRIBUTES objAttrs;
    InitializeObjectAttributes(&objAttrs, NULL, 0, NULL, NULL);
    MEMORY_INFORMATION_CLASS MIC = MemoryBasicInformation;
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    PVAL headVAL = NULL;
    if (!NT_SUCCESS(ZwOpenProcess(&hProcess, GENERIC_ALL, &objAttrs, &clientId)))
    {
        return STATUS_UNSUCCESSFUL;
    }
    buildValidAddressSingleList(&hProcess, &MIC, &mbi, &headVAL, 0x00007FFF00000000);
    getRegionGapAndPages(headVAL);
    printListVAL(headVAL);
    ZwClose(hProcess);
    PEPROCESS pe = NULL;
    PRSL headRSL = NULL;
    UCHAR pattern[13] = { 0x32,0x30, 0x31, 0x39, 0x33, 0x30, 0x39, 0x30, 0x31, 0x30, 0x31, 0x32, 0x30 };
    SIZE_T patternLen = 13;
    PsLookupProcessByProcessId((HANDLE)clientId.UniqueProcess, &pe);
    buildDoubleLinkedAddressListForPatternStringByKMPAlgorithm(headVAL, &pe, pattern, patternLen, &headRSL);
    printListRSL(headRSL);
    ExFreeResultSavedLink(&headRSL);
    return STATUS_SUCCESS;
}
