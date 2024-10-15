#ifndef __PROCESS_HIDE_PRETENT_HEADER__
#define __PROCESS_HIDE_PRETENT_HEADER__

#include "DriverBaseHeader.h"

typedef struct _AlreadyHiddenProcessList
{
    ULONG64 pidAlreadyHidden;
    PEPROCESS eprocessHeaderAddressOfHiddenProcess;
    PLIST_ENTRY prevProcessEntry;
    PLIST_ENTRY nextProcessEntry;
    LIST_ENTRY HiddenProcessEntry;
}HPL, * PHPL;

typedef struct _AlreadyPretentProcessList
{
    ULONG64 dirtyPID;
    ULONG64 parasitePID;
    LIST_ENTRY PretentProcessEntry;
}PPL, * PPPL;


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

VOID printListHPL(
    IN PHPL headHPL
);
VOID printListPPL(
    IN PPPL headPPL
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
//FreeLinkLists
VOID ExFreeHiddenProcessLink(
    OUT PHPL* headHPL
);
VOID ExFreePretentProcessLink(
    OUT PPPL* headPPL
);
#endif
