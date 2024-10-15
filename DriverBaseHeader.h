#ifndef __DRIVER_BASE_HEADER__
#define __DRIVER_BASE_HEADER__

#pragma warning(disable:4996)

#pragma once

#include <ntifs.h> 
#include <ntddk.h>
#include <wdm.h>

#define IN_OUT
#define IN_OPT
#define OUT_OPT
#define GLOBAL
#define LOCAL
#define __PLACE_HOLDER__

typedef ULONG64 UL64;
typedef MEMORY_INFORMATION_CLASS* PMEMORY_INFORMATION_CLASS;
typedef PEPROCESS* PPEPROCESS;
typedef unsigned int UINT;
typedef INT* PINT;

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

#define ckU64(sentence) DbgPrint("%s: %llX, %llu", #sentence, (sentence), (sentence))

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

#endif
