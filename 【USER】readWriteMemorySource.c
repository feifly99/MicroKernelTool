#include "readWriteMemory.h"

#pragma warning(disable: 6387)

static HANDLE g_hDevice = NULL;

VOID readWriteMemoryBeginStub(
	IN HANDLE* hDevice
)
{
	g_hDevice = *hDevice;
	return;
}

VOID readWriteMemoryReleaseStub(
	VOID
)
{
	g_hDevice = NULL;
	return;
}

VOID readProcessMemory(
	IN HANDLE pid,
	IN PVOID baseAddress,
	IN SIZE_T readLength,
	IN ACCESS_MODE accessMode,
	OUT DIRECT_WRITE_TO PVOID* receiveBuffer
)
{
	PVOID krnlOut = malloc((readLength + 0xFFFull) & ~0xFFFull);
	RtlZeroMemory(krnlOut, (readLength + 0xFFFull) & ~0xFFFull);

	RPMI krnlTrans = { 0 };
	krnlTrans.pid = pid;
	krnlTrans.baseAddress = baseAddress;
	krnlTrans.readLength = readLength;
	krnlTrans.accessMode = accessMode;

	DeviceIoControl(g_hDevice, ____$_READ_PROCESS_MEMORY_$____, &krnlTrans, sizeof(RPMI), krnlOut, (readLength + 0xFFFull) & ~0xFFFull, NULL, NULL);

	RtlCopyMemory(*receiveBuffer, krnlOut, readLength);

	free(krnlOut);
	krnlOut = NULL;

	return;
}

VOID writeProcessMemory(
	IN HANDLE pid,
	IN PVOID baseAddress,
	IN SIZE_T writeLength,
	IN PVOID writeBuffer,
	IN ACCESS_MODE accessMode
)
{
	PVOID writeBufferStable = malloc(writeLength);

	RtlZeroMemory(writeBufferStable, writeLength);
	RtlCopyMemory(writeBufferStable, writeBuffer, writeLength);

	WPMI krnlTrans = { 0 };

	krnlTrans.pid = pid;
	krnlTrans.baseAddress = baseAddress;
	krnlTrans.writeLength = writeLength;
	krnlTrans.writeBuffer = writeBufferStable;
	krnlTrans.accessMode = accessMode;

	DeviceIoControl(g_hDevice, ____$_WRITE_PROCESS_MEMORY_$____, &krnlTrans, sizeof(WPMI), NULL, 0, NULL, NULL);
	
	free(writeBufferStable);
	writeBufferStable = NULL;

	return;
}