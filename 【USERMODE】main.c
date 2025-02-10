#include "memoryScanner.h"

#pragma warning(disable: 6011)

#define __PLACE_HOLDER__

#define log(sen) printf("%s\n", (CONST CHAR*)#sen);

ULONG64 pid = 0;
HANDLE hDevice = NULL;
	
int main(void)
{
	pid = 0;
	printf("进程PID（以十进制输入）：");
	scanf_s("%llu", &pid);
	hDevice = CreateFile(L"\\\\.\\ANYIFEI_SYMBOLINK_NAME", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
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
	return 0;
}
