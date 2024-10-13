#ifndef __DEBUGEE_DRIVER_HEADER__
#define __DEBUGEE_DRIVER_HEADER__

#include "DriverBaseHeader.h"

#define DELAY_ONE_MICROSECOND     (-10)
#define DELAY_ONE_MILLISECOND    (DELAY_ONE_MICROSECOND*1000)

#define __PLACE_HOLDER__

extern ULONG64 __asm__testProc();
extern ULONG64 __asm__readRCX();
extern ULONG64 __asm__readDR0();
extern ULONG64 __asm__readCR0();
extern ULONG64 __asm__WRbreak(IN ULONG64* oldCR0Address);
extern ULONG64 __asm__WRrestore(IN ULONG64 oldCR0Value);
extern ULONG64 __asm__getEFLregistor();
extern ULONG64 __asm__restoreEFLregistor();
extern ULONG64 __asm__PDTchange(IN ULONG64 otherProcessCR3Value, OUT ULONG64* oldCR3ValueAddress);
extern ULONG64 __asm__PDTrestore(IN ULONG64 oldCR3Value);
extern ULONG64 __asm__getImagePathNameAddress(IN ULONG64 pe);
extern ULONG64 __asm__readMSR(IN ULONG64 msrAddress);
extern ULONG64 __asm__getNextDriverNameAddress(IN ULONG64 pDriverObject);
extern SIZE_T __asm__getFuncNumsExportedTotal_Via_DllBase(IN PVOID dllBase);
extern SIZE_T __asm__getFuncNumsExportedByName_Via_DllBase(IN PVOID dllBase);
extern PUCHAR __asm__getFuncNameByIndex_Via_DllBase(IN PVOID dllBase, IN SIZE_T index);
extern PVOID __asm__getFuncAddressByIndex_Via_DllBase(IN PVOID dllBase, IN SIZE_T differWhetherNameExported, IN SIZE_T index);

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

#define ckU64(sentence) DbgPrint("%s: %llX, %llu", #sentence, (sentence), (sentence))

typedef ULONG64 UL64;
typedef MEMORY_INFORMATION_CLASS* PMEMORY_INFORMATION_CLASS;
typedef PEPROCESS* PPEPROCESS;
typedef unsigned int UINT;

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

typedef struct _AlreadyHiddenProcessList
{
    ULONG64 pidAlreadyHidden;
    PEPROCESS eprocessHeaderAddressOfHiddenProcess;
    PLIST_ENTRY prevProcessEntry;
    PLIST_ENTRY nextProcessEntry;
    LIST_ENTRY HiddenProcessEntry;
}HPL, *PHPL;

typedef struct _AlreadyPretentProcessList
{
    ULONG64 dirtyPID;
    ULONG64 parasitePID;
    LIST_ENTRY PretentProcessEntry;
}PPL, *PPPL;

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
VOID getRegionGapAndPages(
    //此函数补全VAL结构的regionGap和pageNums成员
    IN_OUT PVAL headVAL
);
PRSL createSavedResultNode(
    IN ULONG times,
    IN ULONG64 address,
    IN ULONG64 addressBufferLen,
    IN PVAL headVAL
);
PHPL createHiddenProcessNode(
    IN ULONG64 pidOfHiddenProcess,
    IN PEPROCESS eprocessHeaderOfHiddenProcess,
    IN PLIST_ENTRY prevEntryAddress,
    IN PLIST_ENTRY nextEntryAddress
);
PPPL createPretentProcessNode(
    IN ULONG64 dirtyPID,
    IN ULONG64 parasitePID
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
    IN PRSL headRSL
);
VOID printListVAL(
    IN PVAL headVAL
);
VOID printListRSL(
    IN PRSL headRSL
);
VOID printListHPL(
    IN PHPL headHPL
);
VOID printListPPL(
    IN PPPL headPPL
);
ULONG64 getMaxRegionPages(
    IN PVAL head
);
SIZE_T getNodeNumsForDoubleLinkedList(
    IN PRSL headRSL
);
UCHAR farBytesDiffer(
    IN PUCHAR oldPattern,
    IN PUCHAR newPattern,
    IN SIZE_T minSize
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
VOID DbgPrintF(
    float* floatNumPointer
);
VOID displayAllModuleInfomationByProcessId(
    IN ULONG64 pid
);
VOID displayKernelModules(
    PDRIVER_OBJECT driverObject
);
VOID displayAllThreadInfomationByProcessId(
    IN ULONG64 pid
);
ULONG64 getPointerToSSDT(

);
ULONG64 getAvaliableExecuteMemoryInSSDT(

);
ULONG64 getSSDTFunctionAddressByIndex(
    IN ULONG64 index
);
ULONG64 getPIDByProcessName(
    IN PUCHAR name
);
ULONG64 getDllInLoadAddress(
    IN HANDLE pid,
    IN PUNICODE_STRING dllName
);
VOID displayDllExportFunctionTable(
    IN HANDLE pid,
    IN PVOID dllBaseInLoad
);
ULONG64 getDllExportFunctionAddressByName(
    IN HANDLE pid,
    IN PVOID dllBaseInLoad,
    IN PUCHAR funcName
);
UCHAR readByte(
    IN HANDLE pid,
    IN PVOID address
);
VOID writeProcessMemory(
    IN ULONG64 pid,
    IN PVOID targetAddress,
    IN PVOID pointerToContent,
    IN SIZE_T size
);
VOID processHiddenProcedure(
    IN ULONG64 pid,
    IN PHPL* headHPL
);
VOID restoreHiddenProcess(
    IN PHPL headHPL
);
VOID processPretentProcedure(
    IN HANDLE dirtyPID,
    IN HANDLE parasitePID,
    OUT PPPL* headPPL
);
VOID restorePretentProcess(
    IN PPPL headPPL
);
VOID hideThisDriver(
    IN PDRIVER_OBJECT driverObject
);
VOID restoreThisDriver(
    IN PDRIVER_OBJECT driverObject
);
ULONG hookSSDTProcedure(
    IN ULONG64 functionIndexInSSDT,
    IN ULONG64 newHookFunctionAddress
);
VOID hookSSDTRestore(
    IN ULONG64 functionIndexInSSDT,
    IN ULONG oldRellocationOffset
);
VOID readImagePathNameAndCommandLine(
    IN HANDLE pid
);
//FreeLinkLists
VOID ExFreeResultSavedLink(
    OUT PRSL* headRSL
);
VOID ExFreeValidAddressLink(
    OUT PVAL* headVAL
);
VOID ExFreeHiddenProcessLink(
    OUT PHPL* headHPL
);
VOID ExFreePretentProcessLink(
    OUT PPPL* headPPL
);
#endif
