#ifndef __DRIVER_USER_INTERACTION__
#define __DRIVER_USER_INTERACTION__

#include "DebugeeHeader.h"

//Driver_User shared macro/struct and pointer 

#define ____$_LIST_MEMORY_$____              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_GET_PATTERN_NUM_$____			 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_SEARCH_PATTERN_$____           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8003, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_MODULE_$____      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_THREAD_$____      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8005, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_WRITE_PROCESS_MEMORY_$____     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_UNLOAD_DRIVER_PREPARE_$____	 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8007, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define USER_IN		
#define DRIVER_OUT	

#define __PLACE_HOLDER__

#define IOCTL_COMPLETE_MARK(status, len) \
do\
{\
pIrp->IoStatus.Status = status;\
pIrp->IoStatus.Information = len;\
IoCompleteRequest(pIrp, IO_NO_INCREMENT);\
}while (0); \

typedef struct _ValidAddressList_UserIN
{
	USER_IN HANDLE pid;
}VAL_UI, *PVAL_UI;

typedef struct _ResultSavedList_UserIN
{
	USER_IN HANDLE pid;
	USER_IN PUCHAR pattern;
	USER_IN SIZE_T patternLen;
}RSL_UI, *PRSL_UI;

typedef struct _ResultSavedList_DriverOUT
{
	DRIVER_OUT ULONG times;
	DRIVER_OUT ULONG64 address;
	DRIVER_OUT ULONG protect;
}RSL_DO, * PRSL_DO, ** PPRSL_DO;

typedef struct _ListProcessModule_UserIN
{
	USER_IN HANDLE pid;
}LPM_UI, *PLPM_UI;

typedef struct _ListProcessThread_UserIN
{
	USER_IN HANDLE pid;
}LPT_UI, * PLPT_UI;

typedef struct _WriteProcessMemory_UserIN
{
	USER_IN HANDLE pid;
	USER_IN PVOID targetAddress;
	USER_IN PVOID content;
	USER_IN SIZE_T writeLen;
}WPM_UI, * PWPM_UI;

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
