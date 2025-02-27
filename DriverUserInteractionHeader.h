#ifndef __DRIVER_USER_INTERACTION__
#define __DRIVER_USER_INTERACTION__

#include "MemoryScannerHeader.h"
#include "NonTypedFunctionsHeader.h"
#include "ProcessHideAndPretentHeader.h"
#include "SsdtHijackHeader.h"
#include "CpuOpeationHeader.h"
#include "DbgSysRebuildHeader.h"

//Driver_User shared macro/struct and pointer 

#define ____$_PREPARE_SEARCH_PROCEDURE_$____				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8001, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_ENTER_SEARCH_PROCEDURE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8002, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_STOP_SEARCH_PROCEDURE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8003, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_MODULE_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8004, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_LIST_PROCESS_THREAD_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8005, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_WRITE_PROCESS_MEMORY_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8006, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_PROCESS_HIDEN_PROCEDURE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8007, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_PROCESS_PRETENT_PROCEDURE_$____				CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8008, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_UNLOAD_DRIVER_PREPARE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8009, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_GET_PROCESS_HANDLE_$____						CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_CLOSE_PROCESS_HANDLE_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_DLL_KERNELMODE_INJECTION_$____                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_READ_PROCESS_MEMORY_$____                     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_PROCESS_RESTORE_PROCEDURE_$____               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_REBUILD_DEBUG_SYSTEM_$____                    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define ____$_RESTORE_DEBUG_SYSTEM_$____					CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8010, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define __SEARCH_PROCEDURE_DEFINES__
#define __PROCESS_MEMORY_SPACE_DEFINES__
#define __SEARCH_OUTCOME_DEFINES__
#define __PROCESS_HIDEN_DEFINES__
#define __PROCESS_PRETENT_DEFINES__

#define __DRIVER_USER_IO_ENTRY_PUBLIC_SETTINGS__
#define ______FURTHER_SEARCH_OPTIONS______
#define ______BASIC_MAJOR_FUNCTION______
#define ______LONG_FUNCTION_EXTRACT______

#define IOCTL_COMPLETE_MARK(retSt, status, len) \
do\
{\
	pIrp->IoStatus.Status = status;\
	pIrp->IoStatus.Information = len;\
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);\
	retSt = status;\
}while (0) \

typedef enum _accessMode
{
	VIRTUAL_MODE = 1,
	PHYSICAL_MODE = 2
}ACCESS_MODE;

typedef struct _ReadProcessMemoryInput
{
	HANDLE pid;
	PVOID baseAddress;
	SIZE_T readLength;
	ACCESS_MODE accessMode;
}RPMI, * PRPMI;

typedef struct _WriteProcessMemoryInput
{
	HANDLE pid;
	PVOID baseAddress;
	SIZE_T writeLength;
	PUCHAR writeBuffer;
	ACCESS_MODE accessMode;
}WPMI, * PWPMI;

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

#endif
//使用枚举和宏表达状态参数、结构内嵌联合实现伪多态（CUDA也是）
//熟悉宏操作（保护宏、##、#、@等）
