.data

	t1 QWORD 7FFD513C0542h
	t2 QWORD 7FFD51531530h
	t3 QWORD 7FFD5152A728h
	t4 QWORD 7FFD5141E4D0h
	t5 QWORD 7FFD51379EB0h

.code
	
	__asm__testProc PROC
		mov qword ptr [rsp + 8], rbx
		mov qword ptr [rsp + 10h], rsi
		push rdi
		sub rsp, 20h
		mov rdi, rcx
		test rcx, rcx
		je labelss
		lea rdx, qword ptr [t2]
		call qword ptr [t3]
		nop dword ptr [rax + rax]
	labelss:
		xor r8d, r8d
		xor rcx, rdi
		call t5
		mov rbx, qword ptr [rsp + 30h]
		mov rsi, qword ptr [rsp + 38h]
		add rsp, 20h
		pop rdi
		ret
	__asm__testProc ENDP

	__asm__readRCX PROC
		mov rax, rcx
		ret
	__asm__readRCX ENDP

	__asm__readDR0 PROC
		mov rax, dr0
		ret
	__asm__readDR0 ENDP

	__asm__readCR0 PROC
		mov rax, cr0
		ret
	__asm__readCR0 ENDP

	__asm__WRbreak PROC ; ULONG64 __asm__WRbreak(IN ULONG64* oldCR0Address)
		mov rax, cr0
		mov qword ptr [rcx], rax
		and rax, 0FFFEFFFFh	 ;对rax作32位寄存器操作，高位自动清零
		mov cr0, rax
		ret
	__asm__WRbreak ENDP ;返回值：作完and CR0后的CR0值

	__asm__WRrestore PROC
		mov cr0, rcx
		ret
	__asm__WRrestore ENDP

	__asm__PDTchange PROC ; ULONG64 __asm__PDTbreak(IN ULONG64 newCR3AddressValue, OUT ULONG64* oldCR3Address)
		mov rax, cr3
		mov cr3, rcx
		mov qword ptr [rdx], rax
		ret
	__asm__PDTchange ENDP ;返回值：原来CR3的值

	__asm__PDTrestore PROC
		mov cr3, rcx
		ret
	__asm__PDTrestore ENDP

	__asm__getEFLregistor PROC
		pushfq
		pop rax
		ret
	__asm__getEFLregistor ENDP

	__asm__restoreEFLregistor PROC
		push rax
		popfq
		ret
	__asm__restoreEFLregistor ENDP

	__asm__getImagePathNameAddress PROC
		mov rax, rcx
		add rax, 550h
		mov rax, qword ptr [rax]
		add rax, 20h
		mov rax, qword ptr [rax]
		add rax, 60h
		ret
	__asm__getImagePathNameAddress ENDP
	
	__asm__readMSR PROC ;ULONG64 __asm__readMSR(IN ULONG64* regArrayAddress, OUT ULONG64 msrAddress)
		rdmsr
		shl rdx, 20h
		add rax, rdx
		ret
	__asm__readMSR ENDP

	__asm__getFuncNumsExportedTotal_Via_DllBase PROC ;__asm__getFuncNumsExportedTotal_Via_DllBase(IN PVOID dllBase);
		push r15
		mov r15, rcx
		add rcx, 3Ch
		mov ecx, dword ptr [rcx]
		add rcx, r15 
		add rcx, 18h
		add rcx, 70h
		mov ecx, dword ptr [rcx]
		add rcx, r15
		add rcx, 14h
		mov ecx, dword ptr [rcx]
		mov rax, rcx
		pop r15
		ret
	__asm__getFuncNumsExportedTotal_Via_DllBase ENDP

	__asm__getFuncNumsExportedByName_Via_DllBase PROC ;__asm__getFuncNumsExportedByName_Via_DllBase(IN PVOID dllBase);
		push r15
		mov r15, rcx
		add rcx, 3Ch
		mov ecx, dword ptr [rcx]
		add rcx, r15 
		add rcx, 18h
		add rcx, 70h
		mov ecx, dword ptr [rcx]
		add rcx, r15
		add rcx, 18h
		mov ecx, dword ptr [rcx]
		mov rax, rcx
		pop r15
		ret
	__asm__getFuncNumsExportedByName_Via_DllBase ENDP

	__asm__getFuncNameByIndex_Via_DllBase PROC ;__asm__getFuncNameByIndex_Via_DllBase(IN PVOID dllBase, IN SIZE_T index);
		push r15
		mov r15, rcx
		add rcx, 3Ch
		mov ecx, dword ptr [rcx]
		add rcx, r15 
		add rcx, 18h
		add rcx, 70h
		mov ecx, dword ptr [rcx]
		add rcx, r15
		add rcx, 20h
		mov ecx, dword ptr [rcx]
		add rcx, r15
		mov ecx, dword ptr [rcx + rdx * 4]
		add rcx, r15
		mov rax, rcx
		pop r15
		ret
	__asm__getFuncNameByIndex_Via_DllBase ENDP

	__asm__getFuncAddressByIndex_Via_DllBase PROC ;__asm__getFuncAddressByIndex_Via_DllBase(IN PVOID dllBase, IN SIZE_T differWhetherNameExported, IN SIZE_T index);
		push r15
		add rdx, r8
		mov r15, rcx
		add rcx, 3Ch
		mov ecx, dword ptr [rcx]
		add rcx, r15 
		add rcx, 18h
		add rcx, 70h
		mov ecx, dword ptr [rcx]
		add rcx, r15
		add rcx, 1Ch
		mov ecx, dword ptr [rcx]
		add rcx, r15
		mov ecx, dword ptr [rcx + rdx * 4]
		add rcx, r15
		mov rax, rcx
		pop r15
		ret
	__asm__getFuncAddressByIndex_Via_DllBase ENDP

END
