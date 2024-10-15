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

typedef struct _SearchInput
{
	BOOLEAN isFirstScan;
	//inputType: [0] 1byte / [1] 2bytes / [2] 4bytes / [3] 8bytes / [4] (IEEE754)float_4bytes / [5] (IEEE754)double_8bytes / [6] pattern match 
	UCHAR inputType;
	//scanMode: [0] 精确 / [1] 变大 / [2] 变小 / [3] 未变动 / [4] 位于两数之间
	UCHAR scanMode; 

	union _globalSearchType
	{
		union _findNumber
		{
			struct _integerType
			{
				union _integerNumberReal
				{
					UCHAR byte_1;
					USHORT byte_2;
					UINT byte_4;
					ULONG64 byte_8;
				}integerNumberReal;
				UCHAR integerTolerance;
			}integerType;
			struct _floatingType
			{
				union _floatingNumberReal
				{
					float byte_float;
					double byte_double;
					ULONG float_hex;
					ULONG64 double_hex;
				}floatingNumberReal;
				UCHAR floatingTolerance;
			}floatingType;
		}findNumber;

		struct _findPattern
		{
			PUCHAR patternInput;
			UCHAR patternLenInput;
		}findPattern;

	}globalSearchType;
}SI, *PSI;

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
