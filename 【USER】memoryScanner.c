#include "memoryScanner.h"

static HANDLE g_hDevice = NULL;

VOID memoryScannerBeginStub(
	IN HANDLE* hDevice
)
{
	g_hDevice = *hDevice;
	return;
}

VOID memoryScannerReleaseStub(
	VOID
)
{
	g_hDevice = NULL;
	return;
}

static VOID initializeSearchProcedure(
	IN ULONG64 pidInput
)
{
	HANDLE pid = (HANDLE)pidInput;
	DeviceIoControl(g_hDevice, ____$_PREPARE_SEARCH_PROCEDURE_$____, &pid, sizeof(HANDLE), NULL, 0, NULL, NULL);
}

static PSI initializeSI(
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

static VOID checkSI(
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
					printf("��ֵ: %hhu, %hhd\n", *(UCHAR*)si->u.precise.ptr2Value, *(CHAR*)si->u.precise.ptr2Value);
					break;
				case TYPE_WORD:
					printf("��ֵ: %hu, %hd\n", *(USHORT*)si->u.precise.ptr2Value, *(SHORT*)si->u.precise.ptr2Value);
					break;
				case TYPE_DWORD:
					printf("��ֵ: %u, %d\n", *(UINT*)si->u.precise.ptr2Value, *(INT*)si->u.precise.ptr2Value);
					break;
				case TYPE_QWORD:
					printf("��ֵ: %llu, %lld\n", *(ULONG64*)si->u.precise.ptr2Value, *(LONG64*)si->u.precise.ptr2Value);
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
					printf("С��ֵ: %hhu, %hhd\n", *(UCHAR*)si->u.region.ptr2LowerBound, *(CHAR*)si->u.region.ptr2LowerBound);
					printf("����ֵ: %hhu, %hhd\n", *(UCHAR*)si->u.region.ptr2HigherBound, *(CHAR*)si->u.region.ptr2HigherBound);
					break;
				case TYPE_WORD:
					printf("С��ֵ: %hu, %hd\n", *(USHORT*)si->u.region.ptr2LowerBound, *(SHORT*)si->u.region.ptr2LowerBound);
					printf("����ֵ: %hu, %hd\n", *(USHORT*)si->u.region.ptr2HigherBound, *(SHORT*)si->u.region.ptr2HigherBound);
					break;
				case TYPE_DWORD:
					printf("С��ֵ: %u, %d\n", *(UINT*)si->u.region.ptr2LowerBound, *(INT*)si->u.region.ptr2LowerBound);
					printf("����ֵ: %u, %d\n", *(UINT*)si->u.region.ptr2HigherBound, *(INT*)si->u.region.ptr2HigherBound);
					break;
				case TYPE_QWORD:
					printf("С��ֵ: %llu, %lld\n", *(ULONG64*)si->u.region.ptr2LowerBound, *(LONG64*)si->u.region.ptr2LowerBound);
					printf("����ֵ: %llu, %lld\n", *(ULONG64*)si->u.region.ptr2HigherBound, *(LONG64*)si->u.region.ptr2HigherBound);
					break;
				case TYPE_FLOAT:
					printf("С��ֵ: %f\n", *(float*)si->u.region.ptr2LowerBound);
					printf("����ֵ: %f\n", *(float*)si->u.region.ptr2HigherBound);
					break;
				case TYPE_DOUBLE:
					printf("С��ֵ: %lf\n", *(double*)si->u.region.ptr2LowerBound);
					printf("����ֵ: %lf\n", *(double*)si->u.region.ptr2HigherBound);
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
					printf("�ַ���:\n");
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

static VOID freeSI(
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

VOID enterScanLoop(
	HANDLE pid
)
{
	HANDLE krnlPidTrans = pid;
	initializeSearchProcedure((ULONG64)krnlPidTrans);

	PSI si = NULL;
	log(��������ģʽ��1.��ȷ��ֵ��2.ģ��������3.ģʽƥ��.);
	ULONG mainMark = 0;
	scanf_s("%lu", &mainMark);

	switch (mainMark)
	{
		case 1:
		{
			log(����ȷ��ֵ�������������ͣ�1.���ֽڣ�2.˫�ֽڣ�3.���ֽڣ�4.���ֽ�.);
			ULONG subMark = 0;
			scanf_s("%lu", &subMark);
			switch (subMark)
			{
				case 1:
				{
					log(���뵥�ֽ����ݣ�);
					UCHAR* buf = (UCHAR*)malloc(sizeof(UCHAR));
					scanf_s("%hhu", buf);
					si = initializeSI(
						TRUE,
						TYPE_BYTE,
						FIRST_PRECISE_SCAN,
						UNION_MEMBER_PRECISE,
						buf,
						NULL,
						0
					);
					break;
				}
				case 2:
				{
					log(����˫�ֽ����ݣ�);
					USHORT* buf = (USHORT*)malloc(sizeof(USHORT));
					scanf_s("%hu", buf);
					si = initializeSI(
						TRUE,
						TYPE_WORD,
						FIRST_PRECISE_SCAN,
						UNION_MEMBER_PRECISE,
						buf,
						NULL,
						0
					);
					break;
				}
				case 3:
				{
					log(�������ֽ����ݣ�);
					UINT* buf = (UINT*)malloc(sizeof(UINT));
					scanf_s("%u", buf);
					si = initializeSI(
						TRUE,
						TYPE_DWORD,
						FIRST_PRECISE_SCAN,
						UNION_MEMBER_PRECISE,
						buf,
						NULL,
						0
					);
					break;
				}
				case 4:
				{
					log(������ֽ����ݣ�);
					ULONG64* buf = (ULONG64*)malloc(sizeof(ULONG64));
					scanf_s("%llu", buf);
					si = initializeSI(
						TRUE,
						TYPE_QWORD,
						FIRST_PRECISE_SCAN,
						UNION_MEMBER_PRECISE,
						buf,
						NULL,
						0
					);
					break;
				}
				default:
				{
					break;
				}
			}
			break;
		}
		case 2:
		{
			log(��ģ�������������������ͣ�1.���ֽڣ�2.˫�ֽڣ�3.���ֽڣ�4.���ֽڣ�5.�����㣻6.˫����.);
			ULONG subMark = 0;
			scanf_s("%lu", &subMark);
			switch (subMark)
			{
				case 1:
				{
					log(���뵥�ֽ�ģ�������½磺);
					UCHAR* l = (UCHAR*)malloc(sizeof(UCHAR));
					scanf_s("%hhu", l);
					log(���뵥�ֽ�ģ�������Ͻ磺);
					UCHAR* h = (UCHAR*)malloc(sizeof(UCHAR));
					scanf_s("%hhu", h);
					si = initializeSI(
						TRUE,
						TYPE_BYTE,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					break;
				}
				case 2:
				{
					log(����˫�ֽ�ģ�������½磺);
					USHORT* l = (USHORT*)malloc(sizeof(USHORT));
					scanf_s("%hu", l);
					log(����˫�ֽ�ģ�������Ͻ磺);
					USHORT* h = (USHORT*)malloc(sizeof(USHORT));
					scanf_s("%hu", h);
					si = initializeSI(
						TRUE,
						TYPE_WORD,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					break;
				}
				case 3:
				{
					log(�������ֽ�ģ�������½磺);
					UINT* l = (UINT*)malloc(sizeof(UINT));
					scanf_s("%u", l);
					log(�������ֽ�ģ�������Ͻ磺);
					UINT* h = (UINT*)malloc(sizeof(UINT));
					scanf_s("%u", h);
					si = initializeSI(
						TRUE,
						TYPE_DWORD,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					break;
				}
				case 4:
				{
					log(������ֽ�ģ�������½磺);
					ULONG64* l = (ULONG64*)malloc(sizeof(ULONG64));
					scanf_s("%llu", l);
					log(������ֽ�ģ�������Ͻ磺);
					ULONG64* h = (ULONG64*)malloc(sizeof(ULONG64));
					scanf_s("%llu", h);
					si = initializeSI(
						TRUE,
						TYPE_QWORD,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					break;
				}
				case 5:
				{
					log(���뵥����ģ�������½磺);
					float* l = (float*)malloc(sizeof(float));
					scanf_s("%f", l);
					log(���뵥����ģ�������Ͻ磺);
					float* h = (float*)malloc(sizeof(float));
					scanf_s("%f", h);
					si = initializeSI(
						TRUE,
						TYPE_FLOAT,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					checkSI(si);
					break;
				}
				case 6:
				{
					log(����˫����ģ�������½磺);
					double* l = (double*)malloc(sizeof(double));
					scanf_s("%lf", l);
					log(����˫����ģ�������Ͻ磺);
					double* h = (double*)malloc(sizeof(double));
					scanf_s("%lf", h);
					si = initializeSI(
						TRUE,
						TYPE_FLOAT,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					break;
				}
				default:
				{
					break;
				}
			}
			break;
		}
		case 3:
		{
			CONST PUCHAR p = (CONST PUCHAR)malloc(500 * sizeof(UCHAR));
			RtlZeroMemory(p, 500);
			log(���ַ����������ַ�����ѧ���ȣ�);
			ULONG len = 0;
			scanf_s("%lu", &len);
			log(���ַ����������ַ�����);
			//����������ѧ������9���ַ�����"woaiwojia"����ô��p���д洢����"woaiwojia\0".
			//���Ǵ���SI��ʱ��ֻ����p��ǰ���\0�Ĳ��֣������scanf_s�г�����len + 1����SIֻ��ȡlen���ַ�.
			//���scanf_s�в���len + 1����ôprintf�޷�������%s��ӡ���ַ���.
			//��Σ�ա����������������򲻿���%s������ַ���������������
			//��Σ�ա�������strncmp/ѭ�� + %c + ���ȵȷ�ʽ���ؿ������������
			scanf_s("%s", p, len + 1);
			si = initializeSI(
				TRUE,
				TYPE_PATTERN,
				FIRST_PATTERN_SCAN,
				UNION_MEMBER_PATTERN,
				p,
				NULL,
				len
			);
			break;
		}
		default:
		{
			break;
		}
	}

	DeviceIoControl(g_hDevice, ____$_ENTER_SEARCH_PROCEDURE_$____, si, sizeof(SI), NULL, 0, NULL, NULL);
	
	while (1)
	{
		log(����������1��0��.);
		ULONG continueMark = 0;
		scanf_s("%lu", &continueMark);
		if (continueMark == 0)
		{
			DeviceIoControl(g_hDevice, ____$_STOP_SEARCH_PROCEDURE_$____, NULL, 0, NULL, 0, NULL, NULL);
			break;
		}
		else
		{
			si->isFirstScan = FALSE;
			switch (si->memberType)
			{
				case UNION_MEMBER_PRECISE:
				{
					log(�ϴ��Ǿ�ȷ�����������������ģʽ��1.��ȷ������2.������ֵ��3.��С����ֵ��4.δ�䶯����ֵ��5.������ĳ��ָ��ֵ��6.��С��ĳ��ָ��ֵ.);
					ULONG continueType = 0;
					scanf_s("%lu", &continueType);
					switch (continueType)
					{
					case 1:
					{
						si->scanType = CONTINUE_PRECISE;
						switch (si->valueType)
						{
						case TYPE_BYTE:
						{
							log(�����µĵ��ֽ����ݣ�);
							scanf_s("%hhu", (UCHAR*)si->u.precise.ptr2Value);
							break;
						}
						case TYPE_WORD:
						{
							log(�����µ�˫�ֽ����ݣ�);
							scanf_s("%hu", (USHORT*)si->u.precise.ptr2Value);
							break;
						}
						case TYPE_DWORD:
						{
							log(�����µ����ֽ����ݣ�);
							scanf_s("%u", (UINT*)si->u.precise.ptr2Value);
							break;
						}
						case TYPE_QWORD:
						{
							log(�����µİ��ֽ����ݣ�);
							scanf_s("%llu", (ULONG64*)si->u.precise.ptr2Value);
							break;
						}
						default:
						{
							break;
						}
						}
						break;
					}
					case 2:
					{
						UNREFERENCED_PARAMETER(si->u);
						si->scanType = CONTINUE_LARGER;
						break;
					}
					case 3:
					{
						UNREFERENCED_PARAMETER(si->u);
						si->scanType = CONTINUE_LOWER;
						break;
					}
					case 4:
					{
						UNREFERENCED_PARAMETER(si->u);
						si->scanType = CONTINUE_UNCHANGED;
						break;
					}
					case 5:
					{
						UNREFERENCED_PARAMETER(si->u);
						si->scanType = CONTINUE_INCREASED_BY;
						break;
					}
					case 6:
					{
						UNREFERENCED_PARAMETER(si->u);
						si->scanType = CONTINUE_DECREASED_BY;
						break;
					}
					default:
					{
						break;
					}
					}
					break;
				}
				case UNION_MEMBER_REGION:
				{
					log(�ϴ���ģ�������������������ģʽ��1.������ֵ��2.������ֵ��3.��С����ֵ��4.δ�䶯����ֵ��5.������ĳ��ָ��ֵ��6.��С��ĳ��ָ��ֵ.);
					ULONG continueType = 0;
					scanf_s("%lu", &continueType);
					switch (continueType)
					{
					case 1:
					{
						si->scanType = CONTINUE_REGION;
						switch (si->valueType)
						{
						case TYPE_BYTE:
						{
							log(�����µĵ��ֽ��½磺);
							scanf_s("%hhu", (UCHAR*)si->u.region.ptr2LowerBound);
							log(�����µĵ��ֽ��Ͻ磺);
							scanf_s("%hhu", (UCHAR*)si->u.region.ptr2HigherBound);
							break;
						}
						case TYPE_WORD:
						{
							log(�����µ�˫�ֽ��½磺);
							scanf_s("%hu", (USHORT*)si->u.region.ptr2LowerBound);
							log(�����µ�˫�ֽ��Ͻ磺);
							scanf_s("%hu", (USHORT*)si->u.region.ptr2HigherBound);
							break;
						}
						case TYPE_DWORD:
						{
							log(�����µ����ֽ��½磺);
							scanf_s("%u", (UINT*)si->u.region.ptr2LowerBound);
							log(�����µ����ֽ��Ͻ磺);
							scanf_s("%u", (UINT*)si->u.region.ptr2HigherBound);
							break;
						}
						case TYPE_QWORD:
						{
							log(�����µİ��ֽ��½磺);
							scanf_s("%llu", (ULONG64*)si->u.region.ptr2LowerBound);
							log(�����µİ��ֽ��Ͻ磺);
							scanf_s("%llu", (ULONG64*)si->u.region.ptr2HigherBound);
							break;
						}
						case TYPE_FLOAT:
						{
							log(�����µĵ������½磺);
							scanf_s("%f", (float*)si->u.region.ptr2LowerBound);
							log(�����µĵ������Ͻ磺);
							scanf_s("%f", (float*)si->u.region.ptr2HigherBound);
							break;
						}
						case TYPE_DOUBLE:
						{
							log(�����µ�˫�����½磺);
							scanf_s("%lf", (double*)si->u.region.ptr2LowerBound);
							log(�����µ�˫�����Ͻ磺);
							scanf_s("%lf", (double*)si->u.region.ptr2HigherBound);
							break;
						}
						default:
						{
							break;
						}
						}
						break;//���break!
					}
					case 2:
					{
						UNREFERENCED_PARAMETER(si->u);
						si->scanType = CONTINUE_LARGER;
						break;
					}
					case 3:
					{
						UNREFERENCED_PARAMETER(si->u);
						si->scanType = CONTINUE_LOWER;
						break;
					}
					case 4:
					{
						UNREFERENCED_PARAMETER(si->u);
						si->scanType = CONTINUE_UNCHANGED;
						break;
					}
					case 5:
					{
						UNREFERENCED_PARAMETER(si->u);
						si->scanType = CONTINUE_INCREASED_BY;
						break;
					}
					case 6:
					{
						UNREFERENCED_PARAMETER(si->u);
						si->scanType = CONTINUE_DECREASED_BY;
						break;
					}
					default:
					{
						break;
					}
					}
					break;
				}
				case UNION_MEMBER_PATTERN:
				{
					RtlZeroMemory(si->u.pattern.ptr2Pattern, si->u.pattern.patternLen);
					log(�ϴ����ַ���ƥ�䡣ֻ�ܼ���ѡ���ַ�����ȷƥ��.);
					si->scanType = CONTINUE_PATTERN;
					log(�������ַ������ȣ�);
					//����������ѧ������9���ַ�����"woaiwojia"����ô��p���д洢����"woaiwojia\0".
					//���Ǵ���SI��ʱ��ֻ����p��ǰ���\0�Ĳ��֣������scanf_s�г�����len + 1����SIֻ��ȡlen���ַ�.
					//���scanf_s�в���len + 1����ôprintf�޷�������%s��ӡ���ַ���.
					//��Σ�ա����������������򲻿���%s������ַ���������������
					//��Σ�ա�������strncmp/ѭ�� + %c + ���ȵȷ�ʽ���ؿ������������
					ULONG len = 0;
					scanf_s("%lu", &len);
					si->u.pattern.patternLen = len;
					log(�������ַ�����);
					scanf_s("%s", si->u.pattern.ptr2Pattern, len + 1);
					break;
				}
				default:
				{
					break;
				}
			}
			DeviceIoControl(g_hDevice, ____$_ENTER_SEARCH_PROCEDURE_$____, si, sizeof(SI), NULL, 0, NULL, NULL);
		}
	}
	freeSI(&si);
	return;
}

/*

	printf("____$_INITIALIZE_DRIVER_SETTINGS_$____\n");
	if (DeviceIoControl(hDevice, ____$_INITIZE_PROCESS_ID_$____, &pid, sizeof(HANDLE), NULL, 0, NULL, NULL))
	{
		log([sYsHacker] ��ȡ���̾���ɹ�\n);
	}
	else
	{
		log([sYsHacker] ��ȡ���̾��ʧ�ܣ��رճ���\n);
		CloseHandle(hDevice);
		return 0xCC;
	}
	if (DeviceIoControl(hDevice, ____$_INITIALIZE_PROCESS_MEMORY_SPACE_$____, NULL, 0, NULL, 0, NULL, NULL))
	{
		log([sYsHacker] �����ڴ��ʼ���ɹ�\n);
	}
	else
	{
		log(�����ڴ��ʼ��ʧ�ܣ��رճ���\n);
		CloseHandle(hDevice);
		return 0xDD;
	}

	PSI si = NULL;
	log(��������ģʽ��1.��ȷ��ֵ��2.ģ��������3.ģʽƥ��.);
	ULONG mainMark = 0;
	scanf_s("%lu", &mainMark);
	switch (mainMark)
	{
		case 1:
		{
			log(����ȷ��ֵ�������������ͣ�1.���ֽڣ�2.˫�ֽڣ�3.���ֽڣ�4.���ֽ�.);
			ULONG subMark = 0;
			scanf_s("%lu", &subMark);
			switch (subMark)
			{
				case 1:
				{
					log(���뵥�ֽ����ݣ�);
					UCHAR* buf = (UCHAR*)malloc(sizeof(UCHAR));
					scanf_s("%hhu", buf);
					si = initializeSI(
						TRUE,
						TYPE_BYTE,
						FIRST_PRECISE_SCAN,
						UNION_MEMBER_PRECISE,
						buf,
						NULL,
						0
					);
					break;
				}
				case 2:
				{
					log(����˫�ֽ����ݣ�);
					USHORT* buf = (USHORT*)malloc(sizeof(USHORT));
					scanf_s("%hu", buf);
					si = initializeSI(
						TRUE,
						TYPE_WORD,
						FIRST_PRECISE_SCAN,
						UNION_MEMBER_PRECISE,
						buf,
						NULL,
						0
					);
					break;
				}
				case 3:
				{
					log(�������ֽ����ݣ�);
					UINT* buf = (UINT*)malloc(sizeof(UINT));
					scanf_s("%u", buf);
					si = initializeSI(
						TRUE,
						TYPE_DWORD,
						FIRST_PRECISE_SCAN,
						UNION_MEMBER_PRECISE,
						buf,
						NULL,
						0
					);
					break;
				}
				case 4:
				{
					log(������ֽ����ݣ�);
					ULONG64* buf = (ULONG64*)malloc(sizeof(ULONG64));
					scanf_s("%llu", buf);
					si = initializeSI(
						TRUE,
						TYPE_QWORD,
						FIRST_PRECISE_SCAN,
						UNION_MEMBER_PRECISE,
						buf,
						NULL,
						0
					);
					break;
				}
				default:
				{
					break;
				}
			}
			break;
		}
		case 2:
		{
			log(��ģ�������������������ͣ�1.���ֽڣ�2.˫�ֽڣ�3.���ֽڣ�4.���ֽڣ�5.�����㣻6.˫����.);
			ULONG subMark = 0;
			scanf_s("%lu", &subMark);
			switch (subMark)
			{
				case 1:
				{
					log(���뵥�ֽ�ģ�������½磺);
					UCHAR* l = (UCHAR*)malloc(sizeof(UCHAR));
					scanf_s("%hhu", l);
					log(���뵥�ֽ�ģ�������Ͻ磺);
					UCHAR* h = (UCHAR*)malloc(sizeof(UCHAR));
					scanf_s("%hhu", h);
					si = initializeSI(
						TRUE,
						TYPE_BYTE,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					break;
				}
				case 2:
				{
					log(����˫�ֽ�ģ�������½磺);
					USHORT* l = (USHORT*)malloc(sizeof(USHORT));
					scanf_s("%hu", l);
					log(����˫�ֽ�ģ�������Ͻ磺);
					USHORT* h = (USHORT*)malloc(sizeof(USHORT));
					scanf_s("%hu", h);
					si = initializeSI(
						TRUE,
						TYPE_WORD,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					break;
				}
				case 3:
				{
					log(�������ֽ�ģ�������½磺);
					UINT* l = (UINT*)malloc(sizeof(UINT));
					scanf_s("%u", l);
					log(�������ֽ�ģ�������Ͻ磺);
					UINT* h = (UINT*)malloc(sizeof(UINT));
					scanf_s("%u", h);
					si = initializeSI(
						TRUE,
						TYPE_DWORD,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					break;
				}
				case 4:
				{
					log(������ֽ�ģ�������½磺);
					ULONG64* l = (ULONG64*)malloc(sizeof(ULONG64));
					scanf_s("%llu", l);
					log(������ֽ�ģ�������Ͻ磺);
					ULONG64* h = (ULONG64*)malloc(sizeof(ULONG64));
					scanf_s("%llu", h);
					si = initializeSI(
						TRUE,
						TYPE_QWORD,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					break;
				}
				case 5:
				{
					log(���뵥����ģ�������½磺);
					float* l = (float*)malloc(sizeof(float));
					scanf_s("%f", l);
					log(���뵥����ģ�������Ͻ磺);
					float* h = (float*)malloc(sizeof(float));
					scanf_s("%f", h);
					si = initializeSI(
						TRUE,
						TYPE_FLOAT,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					checkSI(si);
					break;
				}
				case 6:
				{
					log(����˫����ģ�������½磺);
					double* l = (double*)malloc(sizeof(double));
					scanf_s("%lf", l);
					log(����˫����ģ�������Ͻ磺);
					double* h = (double*)malloc(sizeof(double));
					scanf_s("%lf", h);
					si = initializeSI(
						TRUE,
						TYPE_FLOAT,
						FIRST_REGION_SCAN,
						UNION_MEMBER_REGION,
						l,
						h,
						0
					);
					break;
				}
				default:
				{
					break;
				}
			}
			break;
		}
		case 3:
		{
			CONST PUCHAR p = (CONST PUCHAR)malloc(500 * sizeof(UCHAR));
			RtlZeroMemory(p, 500);
			log(���ַ����������ַ�����ѧ���ȣ�);
			ULONG len = 0;
			scanf_s("%lu", &len);
			log(���ַ����������ַ�����);
			//����������ѧ������9���ַ�����"woaiwojia"����ô��p���д洢����"woaiwojia\0".
			//���Ǵ���SI��ʱ��ֻ����p��ǰ���\0�Ĳ��֣������scanf_s�г�����len + 1����SIֻ��ȡlen���ַ�.
			//���scanf_s�в���len + 1����ôprintf�޷�������%s��ӡ���ַ���.
			//��Σ�ա����������������򲻿���%s������ַ���������������
			//��Σ�ա�������strncmp/ѭ�� + %c + ���ȵȷ�ʽ���ؿ������������
			scanf_s("%s", p, len + 1);
			si = initializeSI(
				TRUE,
				TYPE_PATTERN,
				FIRST_PATTERN_SCAN,
				UNION_MEMBER_PATTERN,
				p,
				NULL,
				len
			);
			break;
		}
		default:
		{
			break;
		}
	}
	DeviceIoControl(hDevice, ____$_SEARCH_PROCEDURE_$____, si, sizeof(SI), NULL, 0, NULL, NULL);
	ULONG continueMark = 0;
	while (1)
	{
		log(����������1��0��.);
		scanf_s("%lu", &continueMark);
		if (continueMark == 0)
		{
			DeviceIoControl(hDevice, ____$_STOP_SEARCH_PROCEDURE_$____, NULL, 0, NULL, 0, NULL, NULL);
			break;
		}
		else
		{
			si->isFirstScan = FALSE;
			switch (si->memberType)
			{
				case UNION_MEMBER_PRECISE:
				{
					log(�ϴ��Ǿ�ȷ�����������������ģʽ��1.��ȷ������2.������ֵ��3.��С����ֵ��4.δ�䶯����ֵ��5.������ĳ��ָ��ֵ��6.��С��ĳ��ָ��ֵ.);
					ULONG continueType = 0;
					scanf_s("%lu", &continueType);
					switch (continueType)
					{
						case 1:
						{
							si->scanType = CONTINUE_PRECISE;
							switch (si->valueType)
							{
								case TYPE_BYTE:
								{
									log(�����µĵ��ֽ����ݣ�);
									scanf_s("%hhu", (UCHAR*)si->u.precise.ptr2Value);
									break;
								}
								case TYPE_WORD:
								{
									log(�����µ�˫�ֽ����ݣ�);
									scanf_s("%hu", (USHORT*)si->u.precise.ptr2Value);
									break;
								}
								case TYPE_DWORD:
								{
									log(�����µ����ֽ����ݣ�);
									scanf_s("%u", (UINT*)si->u.precise.ptr2Value);
									break;
								}
								case TYPE_QWORD:
								{
									log(�����µİ��ֽ����ݣ�);
									scanf_s("%llu", (ULONG64*)si->u.precise.ptr2Value);
									break;
								}
								default:
								{
									break;
								}
							}
							break;
						}
						case 2:
						{
							UNREFERENCED_PARAMETER(si->u);
							si->scanType = CONTINUE_LARGER;
							break;
						}
						case 3:
						{
							UNREFERENCED_PARAMETER(si->u);
							si->scanType = CONTINUE_LOWER;
							break;
						}
						case 4:
						{
							UNREFERENCED_PARAMETER(si->u);
							si->scanType = CONTINUE_UNCHANGED;
							break;
						}
						case 5:
						{
							UNREFERENCED_PARAMETER(si->u);
							si->scanType = CONTINUE_INCREASED_BY;
							break;
						}
						case 6:
						{
							UNREFERENCED_PARAMETER(si->u);
							si->scanType = CONTINUE_DECREASED_BY;
							break;
						}
						default:
						{
							break;
						}
					}
					break;
				}
				case UNION_MEMBER_REGION:
				{
					log(�ϴ���ģ�������������������ģʽ��1.������ֵ��2.������ֵ��3.��С����ֵ��4.δ�䶯����ֵ��5.������ĳ��ָ��ֵ��6.��С��ĳ��ָ��ֵ.);
					ULONG continueType = 0;
					scanf_s("%lu", &continueType);
					switch (continueType)
					{
						case 1:
						{
							si->scanType = CONTINUE_REGION;
							switch (si->valueType)
							{
								case TYPE_BYTE:
								{
									log(�����µĵ��ֽ��½磺);
									scanf_s("%hhu", (UCHAR*)si->u.region.ptr2LowerBound);
									log(�����µĵ��ֽ��Ͻ磺);
									scanf_s("%hhu", (UCHAR*)si->u.region.ptr2HigherBound);
									break;
								}
								case TYPE_WORD:
								{
									log(�����µ�˫�ֽ��½磺);
									scanf_s("%hu", (USHORT*)si->u.region.ptr2LowerBound);
									log(�����µ�˫�ֽ��Ͻ磺);
									scanf_s("%hu", (USHORT*)si->u.region.ptr2HigherBound);
									break;
								}
								case TYPE_DWORD:
								{
									log(�����µ����ֽ��½磺);
									scanf_s("%u", (UINT*)si->u.region.ptr2LowerBound);
									log(�����µ����ֽ��Ͻ磺);
									scanf_s("%u", (UINT*)si->u.region.ptr2HigherBound);
									break;
								}
								case TYPE_QWORD:
								{
									log(�����µİ��ֽ��½磺);
									scanf_s("%llu", (ULONG64*)si->u.region.ptr2LowerBound);
									log(�����µİ��ֽ��Ͻ磺);
									scanf_s("%llu", (ULONG64*)si->u.region.ptr2HigherBound);
									break;
								}
								case TYPE_FLOAT:
								{
									log(�����µĵ������½磺);
									scanf_s("%f", (float*)si->u.region.ptr2LowerBound);
									log(�����µĵ������Ͻ磺);
									scanf_s("%f", (float*)si->u.region.ptr2HigherBound);
									break;
								}
								case TYPE_DOUBLE:
								{
									log(�����µ�˫�����½磺);
									scanf_s("%lf", (double*)si->u.region.ptr2LowerBound);
									log(�����µ�˫�����Ͻ磺);
									scanf_s("%lf", (double*)si->u.region.ptr2HigherBound);
									break;
								}
								default:
								{
									break;
								}
							}
							break;//���break!
						}
						case 2:
						{
							UNREFERENCED_PARAMETER(si->u);
							si->scanType = CONTINUE_LARGER;
							break;
						}
						case 3:
						{
							UNREFERENCED_PARAMETER(si->u);
							si->scanType = CONTINUE_LOWER;
							break;
						}
						case 4:
						{
							UNREFERENCED_PARAMETER(si->u);
							si->scanType = CONTINUE_UNCHANGED;
							break;
						}
						case 5:
						{
							UNREFERENCED_PARAMETER(si->u);
							si->scanType = CONTINUE_INCREASED_BY;
							break;
						}
						case 6:
						{
							UNREFERENCED_PARAMETER(si->u);
							si->scanType = CONTINUE_DECREASED_BY;
							break;
						}
						default:
						{
							break;
						}
					}
					break;
				}
				case UNION_MEMBER_PATTERN:
				{
					RtlZeroMemory(si->u.pattern.ptr2Pattern, si->u.pattern.patternLen);
					log(�ϴ����ַ���ƥ�䡣ֻ�ܼ���ѡ���ַ�����ȷƥ��.);
					si->scanType = CONTINUE_PATTERN;
					log(�������ַ������ȣ�);
					//����������ѧ������9���ַ�����"woaiwojia"����ô��p���д洢����"woaiwojia\0".
					//���Ǵ���SI��ʱ��ֻ����p��ǰ���\0�Ĳ��֣������scanf_s�г�����len + 1����SIֻ��ȡlen���ַ�.
					//���scanf_s�в���len + 1����ôprintf�޷�������%s��ӡ���ַ���.
					//��Σ�ա����������������򲻿���%s������ַ���������������
					//��Σ�ա�������strncmp/ѭ�� + %c + ���ȵȷ�ʽ���ؿ������������
					ULONG len = 0;
					scanf_s("%lu", &len);
					si->u.pattern.patternLen = len;
					log(�������ַ�����);
					scanf_s("%s", si->u.pattern.ptr2Pattern, len + 1);
					break;
				}
				default:
				{
					break;
				}
			}
			DeviceIoControl(hDevice, ____$_SEARCH_PROCEDURE_$____, si, sizeof(SI), NULL, 0, NULL, NULL);
		}
	}
	DeviceIoControl(hDevice, ____$_UNLOAD_DRIVER_PREPARE_$____, NULL, 0, NULL, 0, NULL, NULL);
	CloseHandle(hDevice);
	freeSI(&si);
	system("pause");
*/