#include "SsdtHijackHeader.h"

ULONG_PTR getPointerToSSDT(
)
{
    ULONG_PTR KiSystemCall64ShadowAddress = __asm__readMSR(0xC0000082) + 0x6081C0;
    ULONG_PTR KiSystemServiceStart = KiSystemCall64ShadowAddress - 0x607E50;
    ULONG_PTR KiSystemServiceRepeat = KiSystemServiceStart + 0x14;
    ULONG_PTR currentRIPAddress = KiSystemServiceRepeat + 14;
    ULONG keyOffset = *(ULONG*)(KiSystemServiceRepeat + 10);
    ULONG_PTR pointerToSSDT = currentRIPAddress + keyOffset;
    return pointerToSSDT;
}
ULONG_PTR getAvaliableExecuteMemoryInSSDT(
)
{
    ULONG_PTR pointerToSSDT = getPointerToSSDT();
    ULONG_PTR SSDT_ServiceTableBase = *(ULONG_PTR*)pointerToSSDT;
    ULONG NtOpenProcessFunctionIndex = 38;
    ULONG_PTR NtOpenProcessAddress = (ULONG_PTR)(SSDT_ServiceTableBase + ((*(ULONG*)(SSDT_ServiceTableBase + NtOpenProcessFunctionIndex * 4)) >> 4));
    ULONG_PTR upper13BytesAddress = NtOpenProcessAddress - 13;
    return upper13BytesAddress;
}
ULONG_PTR getSSDTFunctionAddressByIndex(
    IN SIZE_T index
)
{
    ULONG_PTR pointerToSSDT = getPointerToSSDT();
    ULONG_PTR SSDT_BASE = *(ULONG_PTR*)pointerToSSDT;
    return SSDT_BASE + (ULONG_PTR)((*(ULONG*)(SSDT_BASE + index * 4)) >> 4);
}

ULONG hookSSDTProcedure(
    IN SIZE_T functionIndexInSSDT,
    IN ULONG_PTR newHookFunctionAddress
)
{
    ULONG_PTR pointerToSSDT = getPointerToSSDT();
    ULONG_PTR executeMemoryAvaliable = getAvaliableExecuteMemoryInSSDT();
    ULONG_PTR SSDT_ServiceTableBase = *(ULONG_PTR*)pointerToSSDT;
    // 以下步骤是在SSDT表中的空余的13个CC字节处写入shellCode.
    // 写入
    // mov rax, [_longlongPtr](newHookFunctionAddress);
    // jmp rax
    // 对应的汇编指令.
    ULONG_PTR newHookFunctionAddressTemp = newHookFunctionAddress;
    UCHAR* pointerToNewHookFunctionAddressTemp = (UCHAR*)&newHookFunctionAddressTemp;
    UCHAR newHookFunctionAddressBytes[8] = { 0 };
    for (SIZE_T j = 0; j < sizeof(ULONG_PTR); j++)
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
    ULONG_PTR oldFunctionRellocationOffsetAddress = SSDT_ServiceTableBase + functionIndexInSSDT * 4;
    ULONG oldFunctionRellocationOffset = *(ULONG*)oldFunctionRellocationOffsetAddress;
    SIZE_T differ = executeMemoryAvaliable - SSDT_ServiceTableBase;
    differ <<= 4;
    UCHAR* pointerToDiffer = (UCHAR*)&differ;
    SIZE_T sizeofDifferBytes = 4;
    CR0breakOperation(memcpy((PVOID)oldFunctionRellocationOffsetAddress, (PVOID)pointerToDiffer, sizeofDifferBytes););
    return oldFunctionRellocationOffset;
}

VOID hookSSDTRestore(
    IN SIZE_T functionIndexInSSDT,
    IN ULONG oldRellocationOffset
)
{
    ULONG_PTR pointerToSSDT = getPointerToSSDT();
    ULONG_PTR SSDT_ServiceTableBase = *(ULONG_PTR*)pointerToSSDT;

    ULONG_PTR shellCodeBeginAddress = (ULONG_PTR)(SSDT_ServiceTableBase + ((*(ULONG*)(SSDT_ServiceTableBase + functionIndexInSSDT * 4)) >> 4));

    UCHAR restoreCode[12] = { 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC };
    SIZE_T sizeofRestoreCode = 12;
    CR0breakOperation(memcpy((PVOID)shellCodeBeginAddress, (PVOID)restoreCode, sizeofRestoreCode););

    ULONG_PTR oldFunctionRellocationOffsetAddress = SSDT_ServiceTableBase + functionIndexInSSDT * 4;
    ULONG oldRellocationOffsetTemp = oldRellocationOffset;
    UCHAR* pointerToOldRellocationOffsetTemp = (UCHAR*)&oldRellocationOffsetTemp;
    SIZE_T sizeofOldRellocationOffsetTemp = 4;
    CR0breakOperation(memcpy((PVOID)oldFunctionRellocationOffsetAddress, (PVOID)pointerToOldRellocationOffsetTemp, sizeofOldRellocationOffsetTemp););
    return;
}
