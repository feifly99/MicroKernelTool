#include "publicInterface.h"

#pragma warning(disable: 6387)

PGET_PROCESS_HANDLE getProcessHandleResource = NULL;

int main()
{
	initializeGlobalKernelFileHandle();
	ULONG functionCode = 0;
	printf("\t\t\t\t\t[sYsHacker By AYF @HEU]\nѡ�������\n\t\t\t\t\t1.��������\n\t\t\t\t\t2.DLLע�룻\n\t\t\t\t\t3.���ؽ��̣�\n\t\t\t\t\t4.�оٽ���ģ��/�̣߳�\n\t\t\t\t\t5.�ڴ������\n\t\t\t\t\t6.��ý��̾����\n\t\t\t\t\t7.��д�����ڴ棻\n\t\t\t\t\t8.�ع������߼�.\n����ѡ��");
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
			printf("���������Ѿ���ֹ�˽���.\n");
			closeGlobalKernelFileHandle();
			return 0xFFFF;
		}
	}
	closeGlobalKernelFileHandle();
	return 0;
}