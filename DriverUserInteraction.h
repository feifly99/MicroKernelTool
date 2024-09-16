#ifndef __DRIVER_USER_INTERACTION__
#define __DRIVER_USER_INTERACTION__

#include "DebugeeHeader.h"

//Driver_User shared macro/struct and pointer 

#define ____$_INITIZE_PROCESS_HANDLE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_INITIALIZE_PROCESS_MEMORY_SPACE_$____         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_GET_PATTERN_NUM_$____							CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8003, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_SEARCH_PATTERN_$____							CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_MODULE_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8005, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_THREAD_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_WRITE_PROCESS_MEMORY_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8007, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_UNLOAD_DRIVER_PREPARE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_FURTHER_SEARCH_PATTERN_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8009, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define USER_IN		
#define DRIVER_OUT	
#define __INIT_GLOBAL__DEFINES__
#define __PROCESS_MEMORY_SPACE_DEFINES__
#define __SEARCH_OUTCOME_DEFINES__
#define __DRIVER_USER_IO_ENTRY_PUBLIC_SETTINGS__

#define IOCTL_COMPLETE_MARK(status, len) \
do\
{\
pIrp->IoStatus.Status = status;\
pIrp->IoStatus.Information = len;\
IoCompleteRequest(pIrp, IO_NO_INCREMENT);\
}while (0); \

typedef struct _PatternSearchInput
{
	BOOLEAN isFirstScan;
	ULONG scanMode; 
	PUCHAR pattern;
	SIZE_T patternLen;
}PSI, *PPSI;

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
