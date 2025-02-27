#include "publicInterface.h"

#pragma warning(disable: 6387)

PGET_PROCESS_HANDLE getProcessHandleResource = NULL;

int main()
{
	initializeGlobalKernelFileHandle();
	ULONG functionCode = 0;
	printf("\t\t\t\t\t[sYsHacker By AYF @HEU]\n选择操作：\n\t\t\t\t\t1.调试器；\n\t\t\t\t\t2.DLL注入；\n\t\t\t\t\t3.隐藏进程；\n\t\t\t\t\t4.列举进程模块/线程；\n\t\t\t\t\t5.内存浏览；\n\t\t\t\t\t6.获得进程句柄；\n\t\t\t\t\t7.读写进程内存；\n\t\t\t\t\t8.重构调试逻辑.\n您的选择：");
	scanf_s("%lu", &functionCode);

	getProcessHandleResource = (PGET_PROCESS_HANDLE)malloc(sizeof(GET_PROCESS_HANDLE)); 
	RtlZeroMemory(getProcessHandleResource, sizeof(GET_PROCESS_HANDLE));

	switch (functionCode)
	{
		case DEBUGGER_STUB:
		{
			beginStub(DEBUGGER_STUB);

			releaseStub(DEBUGGER_STUB);
			break;
		}
		case INJECTION_STUB:
		{
			beginStub(INJECTION_STUB);

			releaseStub(INJECTION_STUB);
			break;
		}
		case PROCESS_HIDEN_STUB:
		{
			beginStub(PROCESS_HIDEN_STUB);

			releaseStub(PROCESS_HIDEN_STUB);
			break;
		}
		case LIST_PROCESS_MODULE_THREAD_STUB:
		{
			beginStub(LIST_PROCESS_MODULE_THREAD_STUB);

			releaseStub(LIST_PROCESS_MODULE_THREAD_STUB);
			break;
		}
		case MEMORY_SCANNER_STUB:
		{
			beginStub(MEMORY_SCANNER_STUB);

			releaseStub(MEMORY_SCANNER_STUB);
			break;
		}
		case GET_HANDLE_STUB:
		{
			beginStub(GET_HANDLE_STUB);

			releaseStub(GET_HANDLE_STUB);
			break;
		}
		case READ_WRITE_STUB:
		{
			beginStub(READ_WRITE_STUB);

			releaseStub(READ_WRITE_STUB);
			break;
		}
		case REBUILD_DEBUG_SYSTEM_STUB:
		{
			beginStub(REBUILD_DEBUG_SYSTEM_STUB);

			releaseStub(REBUILD_DEBUG_SYSTEM_STUB);
			break;
		}
		default:
		{
			printf("输入有误，已经终止此进程.\n");
			closeGlobalKernelFileHandle();
			return 0xFFFF;
		}
	}
	closeGlobalKernelFileHandle();
	return 0;
}