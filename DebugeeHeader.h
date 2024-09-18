#ifndef __DEBUGEE_DRIVER_HEADER__
#define __DEBUGEE_DRIVER_HEADER__

#include "DriverBaseHeader.h"

#define DELAY_ONE_MICROSECOND     (-10)
#define DELAY_ONE_MILLISECOND    (DELAY_ONE_MICROSECOND*1000)

#define __PLACE_HOLDER__

extern ULONG64 __asm__readDR0();
extern ULONG64 __asm__readCR0();
extern ULONG64 __asm__WRbreak(IN ULONG64* oldCR0Address);
extern ULONG64 __asm__WRrestore(IN ULONG64 oldCR0Value);
extern ULONG64 __asm__getEFLregistor();
extern ULONG64 __asm__restoreEFLregistor();
extern ULONG64 __asm__PDTchange(IN ULONG64 otherProcessCR3Value, OUT ULONG64* oldCR3ValueAddress);
extern ULONG64 __asm__PDTrestore(IN ULONG64 oldCR3Value);
extern ULONG64 __asm__getImagePathNameAddress(IN ULONG64 pe);
extern ULONG64 __asm__getNextDriverNameAddress(IN ULONG64 pDriverObject);

#define CR0breakOperation(sentence) \
do\
{\
    __PLACE_HOLDER__;\
    ULONG64 oldCR0 = 0x0;\
    __asm__WRbreak(&oldCR0);\
    sentence\
    __asm__WRrestore(oldCR0);\
    __PLACE_HOLDER__;\
}while(0);

typedef ULONG64 UL64;
typedef MEMORY_INFORMATION_CLASS* PMEMORY_INFORMATION_CLASS;
typedef PEPROCESS* PPEPROCESS;

typedef struct _ValidAddressList
{
    ULONG64 beginAddress;
    ULONG64 endAddress;
    ULONG memoryState;
    ULONG memoryProtectAttributes;
    BOOLEAN executeFlag;
    ULONG64 regionGap;
    ULONG64 pageNums;
    SINGLE_LIST_ENTRY ValidAddressEntry;
}VAL, * PVAL;

typedef struct _ResultSavedList
{
    ULONG times;
    ULONG64 address;
    ULONG64 rslAddressBufferLen;
    ULONG64 thisNodeAddressPageMaxValidAddress;
    PUCHAR buffer;
    LIST_ENTRY ResultAddressEntry;
}RSL, * PRSL, ** PPRSL;

VOID KernelDriverThreadSleep(
    IN LONG msec
);
PVAL createValidAddressNode(
    IN ULONG64 begin, 
    IN ULONG64 end,
    IN ULONG memState,
    IN ULONG memProtectAttributes,
    IN BOOLEAN executeFlag
);
PRSL createSavedResultNode(
    IN ULONG times,
    IN ULONG64 address,
    IN ULONG64 addressBufferLen,
    IN PVAL headVAL
);
VOID getRegionGapAndPages(
    //此函数补全VAL结构的regionGap和pageNums成员
    IN_OUT PVAL headVAL
);
ULONG64 getMaxRegionPages(
    IN PVAL head
); 
//KMP Algorithm
VOID computeLPSArray(
    IN CONST UCHAR* pattern,
    IN UL64 M,
    OUT UL64* lps
);
VOID KMP_searchPattern(
    IN CONST UCHAR* des,
    IN CONST UCHAR* pattern,
    IN SIZE_T desLen,
    IN SIZE_T patLen,
    IN ULONG64 pageBeginAddress,
    IN PVAL headVAL,
    OUT UL64* lpsAddress,
    OUT PRSL* headRSL
);
//Debug judge and output
BOOLEAN isSame(
    IN PUCHAR A, 
    IN PUCHAR B,
    IN SIZE_T size
);
BOOLEAN checkAllRSLAddressLenValid(
    PRSL headRSL
);
VOID printListVAL(
    IN PVAL headVAL
);
VOID printListRSL(
    IN PRSL headRSL
);
VOID ReadBuffer(
    IN PVOID bufferHead,
    IN SIZE_T size
);
UCHAR farBytesDiffer(
    PUCHAR oldPattern,
    PUCHAR newPattern,
    SIZE_T minSize
);
//Single&Double linked list built
VOID buildValidAddressSingleList(
    //此函数补全VAL结构的SINGLE_LIST_ENTRY成员
    IN PHANDLE phProcess,
    IN PMEMORY_INFORMATION_CLASS pMIC,
    IN PMEMORY_BASIC_INFORMATION pmbi,
    OUT PVAL* headVAL, 
    IN ULONG64 addressMaxLimit
); 
VOID buildDoubleLinkedAddressListForPatternStringByKMPAlgorithm(
    IN ULONG64 pid,
    IN PVAL headVAL,
    IN PUCHAR pattern,
    IN SIZE_T patternLen,
    OUT PRSL* headRSL
);
SIZE_T getNodeNumsForDoubleLinkedList(
    IN PRSL headRSL
);
VOID processHiddenProcedure(
    IN ULONG64 pid
);
VOID displayAllModuleInfomationByProcessId(
    IN ULONG64 pid
);
VOID displayAllThreadInfomationByProcessId(
    IN ULONG64 pid
);
VOID writeProcessMemory(
    IN ULONG64 pid,
    IN PVOID targetAddress,
    IN PVOID content,
    IN SIZE_T size
);
VOID processPretent(
    IN HANDLE pid_dirty,
    IN HANDLE pid_clean,
    OUT PEPROCESS* dirtyPEmark
);
VOID processPretentRestore(
    IN PEPROCESS dirtyPE,
    IN HANDLE pid_dirty
);
VOID readImagePathNameAndCommandLine(
    HANDLE pid
);
//FreeLinkLists
VOID ExFreeResultSavedLink(
    OUT PRSL* headRSL
);
VOID ExFreeValidAddressLink(
    OUT PVAL* headVAL
);
#endif
