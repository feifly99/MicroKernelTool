#include "CpuOpeationHeader.h"

VOID runRoutineForAllCpus(
	VOID (__fastcall* eachCpuRoutine)(PVOID),
	PVOID args
)
{
	ULONG initialCpuIndex = KeGetCurrentProcessorIndex();
	ULONG totalCpuCount = KeQueryActiveProcessorCount(NULL);
	for (ULONG loop = 0; loop < totalCpuCount; loop++)
	{
		KeSetSystemAffinityThread((KAFFINITY)(1 << loop));
		eachCpuRoutine(args);
	}
	KeSetSystemAffinityThread((KAFFINITY)(1 << initialCpuIndex));
	return;
}

VOID __fastcall runRoutineAtPreciseCpu(
	VOID (__fastcall* routine)(PVOID),
	PVOID args,
	ULONG targetCpuIndex
)
{
	ULONG initialCpuIndex = KeGetCurrentProcessorIndex();
	if (targetCpuIndex > KeQueryActiveProcessorCount(NULL) - 1)
	{
		log(目标CPU编号超过逻辑CPU个数);
		return;
	}
	KeSetSystemAffinityThread((KAFFINITY)(1 << targetCpuIndex));
	routine(args);
	KeSetSystemAffinityThread((KAFFINITY)(1 << initialCpuIndex));
	return;
}

VOID __fastcall checkCurrCpuIndex(
	PVOID args
)
{
	UNREFERENCED_PARAMETER(args);
	DbgPrint("current cpu index: %lu", KeGetCurrentProcessorIndex());
}

VOID __fastcall clearDebugContextForAllCpus(
	PVOID args
)
{
	UNREFERENCED_PARAMETER(args);
	ULONG_PTR dr0 = 0;
	__asm__writeDR0(dr0);
	myDR7 dr7 = { 0 };
	dr7.value64 = 0x400;
	__asm__writeDR7(dr7.value64);
	DbgPrint("After Clear: dr0: %llX, dr7: %llX at CPU: %lu", __asm__getDR0(), __asm__getDR7(), KeGetCurrentProcessorIndex());
	return;
}

VOID __fastcall setDebugContextForAllCpus(
	PVOID args
)
{
	UNREFERENCED_PARAMETER(args);
	ULONG_PTR dr0 = 0x00007FF6E7853664;
	__asm__writeDR0(dr0);
	myDR7 dr7 = { 0 };
	dr7.value64 = __asm__getDR7();
	dr7.typeBit.L0 = 1;
	dr7.typeBit.LEN0 = 3;
	dr7.typeBit.R_W0 = 3;
	__asm__writeDR7(dr7.value64);
	DbgPrint("Debug Information Set: dr0: %llX, dr7: %llX at CPU: %lu", __asm__getDR0(), __asm__getDR7(), KeGetCurrentProcessorIndex());
	return;
}