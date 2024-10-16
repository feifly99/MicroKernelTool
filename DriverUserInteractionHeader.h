#ifndef __DRIVER_USER_INTERACTION__
#define __DRIVER_USER_INTERACTION__

#include "MemoryScannerHeader.h"
#include "NonTypedFunctionsHeader.h"
#include "ProcessHideAndPretentHeader.h"
#include "SsdtHijackHeader.h"

//Driver_User shared macro/struct and pointer 

#define ____$_INITIZE_PROCESS_HANDLE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_INITIALIZE_PROCESS_MEMORY_SPACE_$____         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_SEARCH_PROCEDURE_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8003, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_STOP_SEARCH_PATTERN_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_MODULE_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8005, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_THREAD_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_WRITE_PROCESS_MEMORY_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8007, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_PROCESS_HIDEN_PROCEDURE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_PROCESS_PRETENT_PROCEDURE_$____				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8009, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_UNLOAD_DRIVER_PREPARE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8010, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define USER_IN		
#define DRIVER_OUT	

#define __INIT_GLOBAL__DEFINES__
#define __PROCESS_MEMORY_SPACE_DEFINES__
#define __SEARCH_OUTCOME_DEFINES__
#define __PROCESS_HIDEN_DEFINES__
#define __PROCESS_PRETENT_DEFINES__

#define __DRIVER_USER_IO_ENTRY_PUBLIC_SETTINGS__
#define ______FURTHER_SEARCH_OPTIONS______
#define ______BASIC_MAJOR_FUNCTION______
#define ______LONG_FUNCTION_EXTRACT______

#define __SEARCH_BYTE__ 0
#define __SEARCH_WORD__ 1
#define __SEARCH_DWORD__ 2
#define __SEARCH_QWORD__ 3
#define __SEARCH_FLOAT__ 4
#define __SEARCH_DOUBLE__ 5
#define __SEARCH_PATTERN__ 6

#define IOCTL_COMPLETE_MARK(status, len) \
do\
{\
	pIrp->IoStatus.Status = status;\
	pIrp->IoStatus.Information = len;\
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);\
}while (0); \

/*

	#define __FIRST_PRECISE_SCAN__ 0x80
	#define __FIRST_FUZZY_SCAN__ 0x90

	#define __TYPE_BYTE__ 0xA1
	#define __TYPE_WORD__ 0xA2
	#define __TYPE_DWORD__ 0xA3
	#define __TYPE_QWORD__ 0xA4
	#define __TYPE_PATTERN__ 0xA5
	#define __TYPE_FLOAT__ 0xA6
	#define __TYPE_DOUBLE__ 0xA7
	#define __TYPE_NOT_FLOATING__ 0xA8

	#define __Continue_PRECISE__ 0xC1
	#define __Continue_LARGER__ 0xC2
	#define __Continue_LOWER__ 0xC3
	#define __Continue_UNCHANGED__ 0xC4
	#define __Continue_REGION__ 0xC5

*/

typedef struct _Driver_User_SearchModeInput
{
	BOOLEAN isFirstScan;
	UCHAR dataType; //begin with __TYPE_
	UCHAR scanMode; //begin with __FIRST_ or __Continue_
	PSMI smi;
}D_U_SMI, *PD_U_SMI;

typedef struct _WriteProcessMemoryInput
{
	PVOID writeBeginAddress;
	SIZE_T writeMemoryLength;
	PUCHAR writeBuffer;
}WPMI, *PWPMI;

typedef struct _ProcessPretentInput
{
	HANDLE ditryPID;
	HANDLE parasitePID;
}PPI, *PPPI;

NTSTATUS myCreate(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
);

NTSTATUS myClose(
	IN PDEVICE_OBJECT pDeviceObject,
	IN PIRP pIrp
);

NTSTATUS Driver_User_IO_Interaction_Entry(
	IN PDEVICE_OBJECT devObj,
	IN PIRP pIrp
);

ULONG checkProtectAttributesForTargetAddress(
	PVAL headVAL,
	PVOID targetAddress
);
#endif
