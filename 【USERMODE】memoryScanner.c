#include "memoryScanner.h"
#pragma warning(disable: 6011)
PSI initializeSI(
	IN ULONG isFistScan,
	IN VALUE_TYPE valueType,
	IN SCAN_TYPE scanType,
	IN UNION_MEMBER_TYPE memberType,
	IN PVOID ptr2MainInput,
	IN PVOID ptr2SubInput,
	IN SIZE_T patternTypeLengthInput
)
{
	PSI retSI = (PSI)malloc(sizeof(SI));
	SIZE_T len = 0;
	if (retSI)
	{
		RtlZeroMemory(retSI, sizeof(SI));
	}
	retSI->isFirstScan = isFistScan;
	retSI->valueType = valueType;
	retSI->scanType = scanType;
	retSI->memberType = memberType;
	switch (retSI->valueType)
	{
		case TYPE_BYTE:
			len = 1;
			break;
		case TYPE_WORD:
			len = 2;
			break;
		case TYPE_DWORD:
			len = 4;
			break;
		case TYPE_QWORD:
			len = 8;
			break;
		case TYPE_PATTERN:
			len = patternTypeLengthInput;
			break;
		case TYPE_FLOAT:
			len = 4;
			break;
		case TYPE_DOUBLE:
			len = 8;
			break;
		default:
			break;
	}
	switch (retSI->scanType)
	{
		case FIRST_PRECISE_SCAN:
		case CONTINUE_PRECISE:
		{
			retSI->u.precise.ptr2Value = ptr2MainInput;
			retSI->u.precise.valueLen = len;
			break;
		}
		case FIRST_REGION_SCAN:
		case CONTINUE_REGION:
		{
			retSI->u.region.ptr2LowerBound = ptr2MainInput;
			retSI->u.region.ptr2HigherBound = ptr2SubInput;
			retSI->u.region.valueLen = len;
			break;
		}
		case FIRST_PATTERN_SCAN:
		case CONTINUE_PATTERN:
		{
			retSI->u.pattern.ptr2Pattern = ptr2MainInput;
			retSI->u.pattern.patternLen = len;
			break;
		}
		default:
		{
			break;
		}
	}
	return retSI;
}

VOID checkSI(
	IN PSI si
)
{
	printf("isFirstScan: %lX\n", si->isFirstScan);
	printf("valueType: %X\n", si->valueType);
	printf("scanType: %X\n", si->scanType);
	printf("memberType: %X\n", si->memberType);
	switch (si->memberType)
	{
	case UNION_MEMBER_PRECISE:
	{
		switch (si->valueType)
		{
		case TYPE_BYTE:
			printf("数值: %hhu, %hhd\n", *(UCHAR*)si->u.precise.ptr2Value, *(CHAR*)si->u.precise.ptr2Value);
			break;
		case TYPE_WORD:
			printf("数值: %hu, %hd\n", *(USHORT*)si->u.precise.ptr2Value, *(SHORT*)si->u.precise.ptr2Value);
			break;
		case TYPE_DWORD:
			printf("数值: %u, %d\n", *(UINT*)si->u.precise.ptr2Value, *(INT*)si->u.precise.ptr2Value);
			break;
		case TYPE_QWORD:
			printf("数值: %llu, %lld\n", *(ULONG64*)si->u.precise.ptr2Value, *(LONG64*)si->u.precise.ptr2Value);
			break;
		default:
			break;
		}
		break;
	}
	case UNION_MEMBER_REGION:
	{
		switch (si->valueType)
		{
		case TYPE_BYTE:
			printf("小数值: %hhu, %hhd\n", *(UCHAR*)si->u.region.ptr2LowerBound, *(CHAR*)si->u.region.ptr2LowerBound);
			printf("大数值: %hhu, %hhd\n", *(UCHAR*)si->u.region.ptr2HigherBound, *(CHAR*)si->u.region.ptr2HigherBound);
			break;
		case TYPE_WORD:
			printf("小数值: %hu, %hd\n", *(USHORT*)si->u.region.ptr2LowerBound, *(SHORT*)si->u.region.ptr2LowerBound);
			printf("大数值: %hu, %hd\n", *(USHORT*)si->u.region.ptr2HigherBound, *(SHORT*)si->u.region.ptr2HigherBound);
			break;
		case TYPE_DWORD:
			printf("小数值: %u, %d\n", *(UINT*)si->u.region.ptr2LowerBound, *(INT*)si->u.region.ptr2LowerBound);
			printf("大数值: %u, %d\n", *(UINT*)si->u.region.ptr2HigherBound, *(INT*)si->u.region.ptr2HigherBound);
			break;
		case TYPE_QWORD:
			printf("小数值: %llu, %lld\n", *(ULONG64*)si->u.region.ptr2LowerBound, *(LONG64*)si->u.region.ptr2LowerBound);
			printf("大数值: %llu, %lld\n", *(ULONG64*)si->u.region.ptr2HigherBound, *(LONG64*)si->u.region.ptr2HigherBound);
			break;
		case TYPE_FLOAT:
			printf("小数值: %f\n", *(float*)si->u.region.ptr2LowerBound);
			printf("大数值: %f\n", *(float*)si->u.region.ptr2HigherBound);
			break;
		case TYPE_DOUBLE:
			printf("小数值: %lf\n", *(double*)si->u.region.ptr2LowerBound);
			printf("大数值: %lf\n", *(double*)si->u.region.ptr2HigherBound);
			break;
		default:
			break;
		}
		break;
	}
	case UNION_MEMBER_PATTERN:
	{
		switch (si->valueType)
		{
		case TYPE_PATTERN:
		{
			printf("字符串:\n");
			for (size_t j = 0; j < si->u.pattern.patternLen; j++)
			{
				printf("%c", ((UCHAR*)si->u.pattern.ptr2Pattern)[j]);
			}
			printf("\n");
			break;
		}
		default:
			break;
		}
		break;
	}
	default:
	{
		break;
	}
	}
}

VOID freeSI(
	IN PSI* si
)
{
	switch ((*si)->memberType)
	{
		case UNION_MEMBER_PRECISE:
		{
			free((*si)->u.precise.ptr2Value);
			(*si)->u.precise.ptr2Value = NULL;
			break;
		}
		case UNION_MEMBER_REGION:
		{
			free((*si)->u.region.ptr2LowerBound);
			(*si)->u.region.ptr2LowerBound = NULL;
			free((*si)->u.region.ptr2HigherBound);
			(*si)->u.region.ptr2HigherBound = NULL;
			break;
		}
		case UNION_MEMBER_PATTERN:
		{
			free((*si)->u.pattern.ptr2Pattern);
			(*si)->u.pattern.ptr2Pattern = NULL;
			break;
		}
		default:
		{
			break;
		}
	}
	free((*si));
	*si = NULL;
	return;
}
