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
	log(输入搜索模式：1.精确数值；2.模糊搜索；3.模式匹配.);
	ULONG mainMark = 0;
	scanf_s("%lu", &mainMark);

	switch (mainMark)
	{
		case 1:
		{
			log(【精确数值】输入数据类型：1.单字节；2.双字节；3.四字节；4.八字节.);
			ULONG subMark = 0;
			scanf_s("%lu", &subMark);
			switch (subMark)
			{
				case 1:
				{
					log(输入单字节数据：);
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
					log(输入双字节数据：);
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
					log(输入四字节数据：);
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
					log(输入八字节数据：);
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
			log(【模糊搜索】输入数据类型：1.单字节；2.双字节；3.四字节；4.八字节；5.单浮点；6.双浮点.);
			ULONG subMark = 0;
			scanf_s("%lu", &subMark);
			switch (subMark)
			{
				case 1:
				{
					log(输入单字节模糊搜索下界：);
					UCHAR* l = (UCHAR*)malloc(sizeof(UCHAR));
					scanf_s("%hhu", l);
					log(输入单字节模糊搜索上界：);
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
					log(输入双字节模糊搜索下界：);
					USHORT* l = (USHORT*)malloc(sizeof(USHORT));
					scanf_s("%hu", l);
					log(输入双字节模糊搜索上界：);
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
					log(输入四字节模糊搜索下界：);
					UINT* l = (UINT*)malloc(sizeof(UINT));
					scanf_s("%u", l);
					log(输入四字节模糊搜索上界：);
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
					log(输入八字节模糊搜索下界：);
					ULONG64* l = (ULONG64*)malloc(sizeof(ULONG64));
					scanf_s("%llu", l);
					log(输入八字节模糊搜索上界：);
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
					log(输入单浮点模糊搜索下界：);
					float* l = (float*)malloc(sizeof(float));
					scanf_s("%f", l);
					log(输入单浮点模糊搜索上界：);
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
					log(输入双浮点模糊搜索下界：);
					double* l = (double*)malloc(sizeof(double));
					scanf_s("%lf", l);
					log(输入双浮点模糊搜索上界：);
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
			log(【字符串】输入字符串数学长度：);
			ULONG len = 0;
			scanf_s("%lu", &len);
			log(【字符串】输入字符串：);
			//比如输入数学长度是9，字符串是"woaiwojia"，那么在p池中存储的是"woaiwojia\0".
			//但是传入SI的时候只传入p池前面非\0的部分，因此在scanf_s中长度是len + 1但是SI只截取len个字符.
			//如果scanf_s中不是len + 1，那么printf无法正常用%s打印此字符串.
			//【危险】在驱动程序中万万不可用%s输出此字符串！！！！！！
			//【危险】必须用strncmp/循环 + %c + 长度等方式保守控制输出！！！
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
		log(继续搜索？1是0否.);
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
					log(上次是精确搜索。输入继续搜索模式：1.精确搜索；2.变大的数值；3.变小的数值；4.未变动的数值；5.增大了某个指定值；6.减小了某个指定值.);
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
							log(输入新的单字节数据：);
							scanf_s("%hhu", (UCHAR*)si->u.precise.ptr2Value);
							break;
						}
						case TYPE_WORD:
						{
							log(输入新的双字节数据：);
							scanf_s("%hu", (USHORT*)si->u.precise.ptr2Value);
							break;
						}
						case TYPE_DWORD:
						{
							log(输入新的四字节数据：);
							scanf_s("%u", (UINT*)si->u.precise.ptr2Value);
							break;
						}
						case TYPE_QWORD:
						{
							log(输入新的八字节数据：);
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
					log(上次是模糊搜索。输入继续搜索模式：1.区间数值；2.变大的数值；3.变小的数值；4.未变动的数值；5.增大了某个指定值；6.减小了某个指定值.);
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
							log(输入新的单字节下界：);
							scanf_s("%hhu", (UCHAR*)si->u.region.ptr2LowerBound);
							log(输入新的单字节上界：);
							scanf_s("%hhu", (UCHAR*)si->u.region.ptr2HigherBound);
							break;
						}
						case TYPE_WORD:
						{
							log(输入新的双字节下界：);
							scanf_s("%hu", (USHORT*)si->u.region.ptr2LowerBound);
							log(输入新的双字节上界：);
							scanf_s("%hu", (USHORT*)si->u.region.ptr2HigherBound);
							break;
						}
						case TYPE_DWORD:
						{
							log(输入新的四字节下界：);
							scanf_s("%u", (UINT*)si->u.region.ptr2LowerBound);
							log(输入新的四字节上界：);
							scanf_s("%u", (UINT*)si->u.region.ptr2HigherBound);
							break;
						}
						case TYPE_QWORD:
						{
							log(输入新的八字节下界：);
							scanf_s("%llu", (ULONG64*)si->u.region.ptr2LowerBound);
							log(输入新的八字节上界：);
							scanf_s("%llu", (ULONG64*)si->u.region.ptr2HigherBound);
							break;
						}
						case TYPE_FLOAT:
						{
							log(输入新的单浮点下界：);
							scanf_s("%f", (float*)si->u.region.ptr2LowerBound);
							log(输入新的单浮点上界：);
							scanf_s("%f", (float*)si->u.region.ptr2HigherBound);
							break;
						}
						case TYPE_DOUBLE:
						{
							log(输入新的双浮点下界：);
							scanf_s("%lf", (double*)si->u.region.ptr2LowerBound);
							log(输入新的双浮点上界：);
							scanf_s("%lf", (double*)si->u.region.ptr2HigherBound);
							break;
						}
						default:
						{
							break;
						}
						}
						break;//这个break!
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
					log(上次是字符串匹配。只能继续选择字符串精确匹配.);
					si->scanType = CONTINUE_PATTERN;
					log(输入新字符串长度：);
					//比如输入数学长度是9，字符串是"woaiwojia"，那么在p池中存储的是"woaiwojia\0".
					//但是传入SI的时候只传入p池前面非\0的部分，因此在scanf_s中长度是len + 1但是SI只截取len个字符.
					//如果scanf_s中不是len + 1，那么printf无法正常用%s打印此字符串.
					//【危险】在驱动程序中万万不可用%s输出此字符串！！！！！！
					//【危险】必须用strncmp/循环 + %c + 长度等方式保守控制输出！！！
					ULONG len = 0;
					scanf_s("%lu", &len);
					si->u.pattern.patternLen = len;
					log(输入新字符串：);
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
		log([sYsHacker] 获取进程句柄成功\n);
	}
	else
	{
		log([sYsHacker] 获取进程句柄失败，关闭程序\n);
		CloseHandle(hDevice);
		return 0xCC;
	}
	if (DeviceIoControl(hDevice, ____$_INITIALIZE_PROCESS_MEMORY_SPACE_$____, NULL, 0, NULL, 0, NULL, NULL))
	{
		log([sYsHacker] 进程内存初始化成功\n);
	}
	else
	{
		log(进程内存初始化失败，关闭程序\n);
		CloseHandle(hDevice);
		return 0xDD;
	}

	PSI si = NULL;
	log(输入搜索模式：1.精确数值；2.模糊搜索；3.模式匹配.);
	ULONG mainMark = 0;
	scanf_s("%lu", &mainMark);
	switch (mainMark)
	{
		case 1:
		{
			log(【精确数值】输入数据类型：1.单字节；2.双字节；3.四字节；4.八字节.);
			ULONG subMark = 0;
			scanf_s("%lu", &subMark);
			switch (subMark)
			{
				case 1:
				{
					log(输入单字节数据：);
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
					log(输入双字节数据：);
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
					log(输入四字节数据：);
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
					log(输入八字节数据：);
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
			log(【模糊搜索】输入数据类型：1.单字节；2.双字节；3.四字节；4.八字节；5.单浮点；6.双浮点.);
			ULONG subMark = 0;
			scanf_s("%lu", &subMark);
			switch (subMark)
			{
				case 1:
				{
					log(输入单字节模糊搜索下界：);
					UCHAR* l = (UCHAR*)malloc(sizeof(UCHAR));
					scanf_s("%hhu", l);
					log(输入单字节模糊搜索上界：);
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
					log(输入双字节模糊搜索下界：);
					USHORT* l = (USHORT*)malloc(sizeof(USHORT));
					scanf_s("%hu", l);
					log(输入双字节模糊搜索上界：);
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
					log(输入四字节模糊搜索下界：);
					UINT* l = (UINT*)malloc(sizeof(UINT));
					scanf_s("%u", l);
					log(输入四字节模糊搜索上界：);
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
					log(输入八字节模糊搜索下界：);
					ULONG64* l = (ULONG64*)malloc(sizeof(ULONG64));
					scanf_s("%llu", l);
					log(输入八字节模糊搜索上界：);
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
					log(输入单浮点模糊搜索下界：);
					float* l = (float*)malloc(sizeof(float));
					scanf_s("%f", l);
					log(输入单浮点模糊搜索上界：);
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
					log(输入双浮点模糊搜索下界：);
					double* l = (double*)malloc(sizeof(double));
					scanf_s("%lf", l);
					log(输入双浮点模糊搜索上界：);
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
			log(【字符串】输入字符串数学长度：);
			ULONG len = 0;
			scanf_s("%lu", &len);
			log(【字符串】输入字符串：);
			//比如输入数学长度是9，字符串是"woaiwojia"，那么在p池中存储的是"woaiwojia\0".
			//但是传入SI的时候只传入p池前面非\0的部分，因此在scanf_s中长度是len + 1但是SI只截取len个字符.
			//如果scanf_s中不是len + 1，那么printf无法正常用%s打印此字符串.
			//【危险】在驱动程序中万万不可用%s输出此字符串！！！！！！
			//【危险】必须用strncmp/循环 + %c + 长度等方式保守控制输出！！！
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
		log(继续搜索？1是0否.);
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
					log(上次是精确搜索。输入继续搜索模式：1.精确搜索；2.变大的数值；3.变小的数值；4.未变动的数值；5.增大了某个指定值；6.减小了某个指定值.);
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
									log(输入新的单字节数据：);
									scanf_s("%hhu", (UCHAR*)si->u.precise.ptr2Value);
									break;
								}
								case TYPE_WORD:
								{
									log(输入新的双字节数据：);
									scanf_s("%hu", (USHORT*)si->u.precise.ptr2Value);
									break;
								}
								case TYPE_DWORD:
								{
									log(输入新的四字节数据：);
									scanf_s("%u", (UINT*)si->u.precise.ptr2Value);
									break;
								}
								case TYPE_QWORD:
								{
									log(输入新的八字节数据：);
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
					log(上次是模糊搜索。输入继续搜索模式：1.区间数值；2.变大的数值；3.变小的数值；4.未变动的数值；5.增大了某个指定值；6.减小了某个指定值.);
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
									log(输入新的单字节下界：);
									scanf_s("%hhu", (UCHAR*)si->u.region.ptr2LowerBound);
									log(输入新的单字节上界：);
									scanf_s("%hhu", (UCHAR*)si->u.region.ptr2HigherBound);
									break;
								}
								case TYPE_WORD:
								{
									log(输入新的双字节下界：);
									scanf_s("%hu", (USHORT*)si->u.region.ptr2LowerBound);
									log(输入新的双字节上界：);
									scanf_s("%hu", (USHORT*)si->u.region.ptr2HigherBound);
									break;
								}
								case TYPE_DWORD:
								{
									log(输入新的四字节下界：);
									scanf_s("%u", (UINT*)si->u.region.ptr2LowerBound);
									log(输入新的四字节上界：);
									scanf_s("%u", (UINT*)si->u.region.ptr2HigherBound);
									break;
								}
								case TYPE_QWORD:
								{
									log(输入新的八字节下界：);
									scanf_s("%llu", (ULONG64*)si->u.region.ptr2LowerBound);
									log(输入新的八字节上界：);
									scanf_s("%llu", (ULONG64*)si->u.region.ptr2HigherBound);
									break;
								}
								case TYPE_FLOAT:
								{
									log(输入新的单浮点下界：);
									scanf_s("%f", (float*)si->u.region.ptr2LowerBound);
									log(输入新的单浮点上界：);
									scanf_s("%f", (float*)si->u.region.ptr2HigherBound);
									break;
								}
								case TYPE_DOUBLE:
								{
									log(输入新的双浮点下界：);
									scanf_s("%lf", (double*)si->u.region.ptr2LowerBound);
									log(输入新的双浮点上界：);
									scanf_s("%lf", (double*)si->u.region.ptr2HigherBound);
									break;
								}
								default:
								{
									break;
								}
							}
							break;//这个break!
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
					log(上次是字符串匹配。只能继续选择字符串精确匹配.);
					si->scanType = CONTINUE_PATTERN;
					log(输入新字符串长度：);
					//比如输入数学长度是9，字符串是"woaiwojia"，那么在p池中存储的是"woaiwojia\0".
					//但是传入SI的时候只传入p池前面非\0的部分，因此在scanf_s中长度是len + 1但是SI只截取len个字符.
					//如果scanf_s中不是len + 1，那么printf无法正常用%s打印此字符串.
					//【危险】在驱动程序中万万不可用%s输出此字符串！！！！！！
					//【危险】必须用strncmp/循环 + %c + 长度等方式保守控制输出！！！
					ULONG len = 0;
					scanf_s("%lu", &len);
					si->u.pattern.patternLen = len;
					log(输入新字符串：);
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