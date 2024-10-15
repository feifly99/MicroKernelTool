#include "MemoryScannerHeader.h"

CONST INT _fltused = 0;

VOID driverUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING reg_path)
{
	UNREFERENCED_PARAMETER(reg_path);
	driverObject->DriverUnload = driverUnload;
	PVAL headVAL = NULL;
	ULONG64 pid = 0x23B8;
	CLIENT_ID cid = { 0 };
	cid.UniqueProcess = (HANDLE)pid;
	cid.UniqueThread = NULL;
	OBJECT_ATTRIBUTES kernelProcessObjAttributes = { 0 };
	InitializeObjectAttributes(&kernelProcessObjAttributes, NULL, 0, NULL, NULL);
	HANDLE hProcess = NULL;
	ZwOpenProcess(&hProcess, GENERIC_ALL, &kernelProcessObjAttributes, &cid);
	MEMORY_INFORMATION_CLASS MIC = MemoryBasicInformation;
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	buildValidAddressSingleList(
		&hProcess,
		&MIC,
		&mbi,
		&headVAL,
		0x00007FFFFFFFFFFF
	);
	getRegionGapAndPages(headVAL);
	//printListVAL(headVAL);
	int x = 1225;
	PSMI smi2 = (PSMI)ExAllocatePool(PagedPool, sizeof(SMI));
	if (smi2)
	{
		smi2->preciseMode.dataLen = 4;
		smi2->preciseMode.value_hexBytePointer = (PUCHAR)ExAllocatePool(PagedPool, 4);
	}
	if (smi2 && smi2->preciseMode.value_hexBytePointer)
	{
		for (SIZE_T j = 0; j < 4; j++)
		{
		    smi2->preciseMode.value_hexBytePointer[j] = ((UCHAR*)&x)[j];
		}
	}
	PRSL headRSL = NULL;
	buildDoubleLinkedAddressListForScaningResult(
		0,
		pid,
		headVAL,
		smi2,
		&headRSL
	);
	printListRSL(headRSL);
	if(smi2)
	{
		ExFreePool(smi2);
	}
	ExFreeResultSavedLink(&headRSL);
	ExFreeValidAddressLink(&headVAL);
	return STATUS_SUCCESS;
}
