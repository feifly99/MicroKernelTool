#include "SsdtHijackHeader.h"

ULONG64 getPointerToSSDT(
)
{
    ULONG64 KiSystemCall64ShadowAddress = __asm__readMSR(0xC0000082);
    ULONG64 KiSystemServiceStart = KiSystemCall64ShadowAddress - 0x6073C0 + 0x370;
    ULONG64 KiSystemServiceRepeat = KiSystemServiceStart + 0x14;
    ULONG64 currentRIPAddress = KiSystemServiceRepeat + 14;
    ULONG keyOffset = *(ULONG*)(KiSystemServiceRepeat + 10);
    ULONG64 pointerToSSDT = currentRIPAddress + keyOffset;
    return pointerToSSDT;
}
ULONG64 getAvaliableExecuteMemoryInSSDT(
)
{
    ULONG64 pointerToSSDT = getPointerToSSDT();
    ULONG64 SSDT_ServiceTableBase = *(ULONG64*)pointerToSSDT;
    ULONG NtOpenProcessFunctionIndex = 38;
    ULONG64 NtOpenProcessAddress = (ULONG64)(SSDT_ServiceTableBase + ((*(ULONG*)(SSDT_ServiceTableBase + NtOpenProcessFunctionIndex * 4)) >> 4));
    ULONG64 upper13BytesAddress = NtOpenProcessAddress - 13;
    return upper13BytesAddress;
}
ULONG64 getSSDTFunctionAddressByIndex(
    IN ULONG64 index
)
{
    ULONG64 pointerToSSDT = getPointerToSSDT();
    ULONG64 SSDT_BASE = *(ULONG64*)pointerToSSDT;
    return SSDT_BASE + (ULONG64)((*(ULONG*)(SSDT_BASE + index * 4)) >> 4);
}
ULONG hookSSDTProcedure(
    IN ULONG64 functionIndexInSSDT,
    IN ULONG64 newHookFunctionAddress
)
{
    ULONG64 pointerToSSDT = getPointerToSSDT();
    ULONG64 executeMemoryAvaliable = getAvaliableExecuteMemoryInSSDT();
    ULONG64 SSDT_ServiceTableBase = *(ULONG64*)pointerToSSDT;
    // 以下步骤是在SSDT表中的空余的13个CC字节处写入shellCode.
    // 写入
    // mov rax, [_longlongPtr](newHookFunctionAddress);
    // jmp rax
    // 对应的汇编指令.
    ULONG64 newHookFunctionAddressTemp = newHookFunctionAddress;
    UCHAR* pointerToNewHookFunctionAddressTemp = (UCHAR*)&newHookFunctionAddressTemp;
    UCHAR newHookFunctionAddressBytes[8] = { 0 };
    for (SIZE_T j = 0; j < 8; j++)
    {
        newHookFunctionAddressBytes[j] = pointerToNewHookFunctionAddressTemp[j];
    }
    UCHAR shellCode[12] = {
        0x48, 0xB8,
        newHookFunctionAddressBytes[0],
        newHookFunctionAddressBytes[1],
        newHookFunctionAddressBytes[2],
        newHookFunctionAddressBytes[3],
        newHookFunctionAddressBytes[4],
        newHookFunctionAddressBytes[5],
        newHookFunctionAddressBytes[6],
        newHookFunctionAddressBytes[7],
        0xFF,0xE0
    };
    SIZE_T sizeofShellCode = 12;
    CR0breakOperation(memcpy((PVOID)executeMemoryAvaliable, (PVOID)shellCode, sizeofShellCode););
    // 以下步骤是修改SSDT表中Nt*函数的四字节偏移，
    // 让操作系统寻址时重定位到上面自定义的shellCode起始地址.
    //SSDT_BASE + SSDT_BASE[INDEX] >> 4 == &function[INDEX].
    ULONG64 oldFunctionRellocationOffsetAddress = SSDT_ServiceTableBase + functionIndexInSSDT * 4;
    ULONG oldFunctionRellocationOffset = *(ULONG*)oldFunctionRellocationOffsetAddress;
    ULONG64 differ = executeMemoryAvaliable - SSDT_ServiceTableBase;
    differ <<= 4;
    UCHAR* pointerToDiffer = (UCHAR*)&differ;
    SIZE_T sizeofDifferBytes = 4;
    CR0breakOperation(memcpy((PVOID)oldFunctionRellocationOffsetAddress, (PVOID)pointerToDiffer, sizeofDifferBytes););
    return oldFunctionRellocationOffset;
}

VOID hookSSDTRestore(
    IN ULONG64 functionIndexInSSDT,
    IN ULONG oldRellocationOffset
)
{
    ULONG64 pointerToSSDT = getPointerToSSDT();
    ULONG64 SSDT_ServiceTableBase = *(ULONG64*)pointerToSSDT;

    ULONG64 shellCodeBeginAddress = (ULONG64)(SSDT_ServiceTableBase + ((*(ULONG*)(SSDT_ServiceTableBase + functionIndexInSSDT * 4)) >> 4));

    UCHAR restoreCode[12] = { 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC };
    SIZE_T sizeofRestoreCode = 12;
    CR0breakOperation(memcpy((PVOID)shellCodeBeginAddress, (PVOID)restoreCode, sizeofRestoreCode););

    ULONG64 oldFunctionRellocationOffsetAddress = SSDT_ServiceTableBase + functionIndexInSSDT * 4;
    ULONG oldRellocationOffsetTemp = oldRellocationOffset;
    UCHAR* pointerToOldRellocationOffsetTemp = (UCHAR*)&oldRellocationOffsetTemp;
    SIZE_T sizeofOldRellocationOffsetTemp = 4;
    CR0breakOperation(memcpy((PVOID)oldFunctionRellocationOffsetAddress, (PVOID)pointerToOldRellocationOffsetTemp, sizeofOldRellocationOffsetTemp););
    return;
}
