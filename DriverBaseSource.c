#include "DriverBaseHeader.h"

VOID clearMemory(
    IN_OUT PVOID des,
    IN SIZE_T length
)
{
    for (SIZE_T j = 0; j < length; j++)
    {
        *(UCHAR*)((ULONG_PTR)des + j) = 0;
    }
    return;
}

VOID copyMemory(
    IN_OUT PVOID des,
    IN PVOID src,
    IN SIZE_T length
)
{
    for (SIZE_T j = 0; j < length; j++)
    {
        *(UCHAR*)((ULONG_PTR)des + j) = *(UCHAR*)((ULONG_PTR)src + j);
    }
    return;
}
