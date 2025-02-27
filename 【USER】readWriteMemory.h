#ifndef __READ_WRITE_PROCESS_MEMORY__
#define __READ_WRITE_PROCESS_MEMORY__

#include "BaseHeader.h"

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

VOID readWriteMemoryBeginStub(
	IN HANDLE* hDevice
);

VOID readWriteMemoryReleaseStub(
	VOID
);

VOID readProcessMemory(
	IN HANDLE pid,
	IN PVOID baseAddress,
	IN SIZE_T readLength,
	IN ACCESS_MODE accessMode,
	OUT DIRECT_WRITE_TO PVOID* receiveBuffer
);

VOID writeProcessMemory(
	IN HANDLE pid,
	IN PVOID baseAddress,
	IN SIZE_T writeLength,
	IN PVOID writeBuffer,
	IN ACCESS_MODE accessMode
);

#endif