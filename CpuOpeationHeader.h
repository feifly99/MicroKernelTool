#ifndef __CPU_OPERATION__
#define __CPU_OPERATION__

#include "DriverBaseHeader.h"

typedef union _$_dr7
{
	ULONG64 value64;
	struct
	{
		ULONG front32;
		ULONG behind32;
	}type32;
	struct
	{
		ULONG L0 : 1;
		ULONG G0 : 1;
		ULONG L1 : 1;
		ULONG G1 : 1;
		ULONG L2 : 1;
		ULONG G2 : 1;
		ULONG L3 : 1;
		ULONG G3 : 1;
		ULONG LE : 1;
		ULONG GE : 1;
		ULONG ReservedSetBit10 : 1;
		ULONG ReservedClearBits11_12 : 2;
		ULONG GD : 1;
		ULONG ReservedClearBits14_15 : 2;
		ULONG R_W0 : 2;
		ULONG LEN0 : 2;
		ULONG R_W1 : 2;
		ULONG LEN1 : 2;
		ULONG R_W2 : 2;
		ULONG LEN2 : 2;
		ULONG R_W3 : 2;
		ULONG LEN3 : 2;
		ULONG ReservedBits32_63;
	}typeBit;
} myDR7;

typedef union _$_cr4
{
	ULONG64 value64;
	struct
	{
		ULONG front32;
		ULONG behind32;
	}type32;
	struct
	{
		ULONG VME : 1;
		ULONG PVI : 1;
		ULONG TSD : 1;
		ULONG DE : 1;
		ULONG PSE : 1;
		ULONG PAE : 1;
		ULONG MCE : 1;
		ULONG PGE : 1;
		ULONG PCE : 1;
		ULONG OSFXSR : 1;
		ULONG OSXMM_EXCPT : 1;
		ULONG ReservedBits11_12 : 2;
		ULONG VMXE : 1;
		ULONG ReservedBits14_31 : 18;
		ULONG ReservedBits32_63;
	}typeBit;
}myCR4;

VOID __fastcall runRoutineForAllCpus(
	VOID (__fastcall* eachCpuRoutine)(PVOID),
	PVOID args
);

VOID __fastcall runRoutineAtPreciseCpu(
	VOID (__fastcall* routine)(PVOID),
	PVOID args,
	ULONG targetCpuIndex
);

VOID(__fastcall checkCurrCpuIndex)(
	PVOID args
);

#endif