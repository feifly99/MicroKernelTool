.code

	__asm__readDR0 PROC
		mov rax, dr0
		ret
	__asm__readDR0 ENDP

	__asm__readCR0 PROC
		mov rax, cr0
		ret
	__asm__readCR0 ENDP

	;___X64___Only___↓___
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
	
	;___X64___Only___↑___

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
	
	__asm__readMSR PROC ;ULONG64 __asm__readMSR(ULONG64* regArrayAddress, ULONG64 msrAddress)
		rdmsr
		shl rdx, 20h
		add rax, rdx
		ret
	__asm__readMSR ENDP

	__asm__getFuncNumsExportedTotal_Via_DllBase PROC ;__asm__getFuncNumsExportedTotal_Via_DllBase(IN PVOID dllBase, OUT SIZE_T* count);
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
		mov qword ptr [rdx], rcx
		pop r15
		ret
	__asm__getFuncNumsExportedTotal_Via_DllBase ENDP

	__asm__getFuncNumsExportedByName_Via_DllBase PROC ;__asm__getFuncNumsExportedByName_Via_DllBase(IN PVOID dllBase, OUT SIZE_T* count);
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
		mov qword ptr [rdx], rcx
		pop r15
		ret
	__asm__getFuncNumsExportedByName_Via_DllBase ENDP

	__asm__getFuncNameByIndex_Via_DllBase PROC ;__asm__getFuncNameByIndex_Via_DllBase(IN PVOID dllBase, IN SIZE_T index, OUT ULONG64* nameAddress);
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
		mov qword ptr [r8], rcx
		pop r15
		ret
	__asm__getFuncNameByIndex_Via_DllBase ENDP

	__asm__getFuncAddressByIndex_Via_DllBase PROC ;__asm__getFuncAddressByIndex_Via_DllBase(IN PVOID dllBase, IN SIZE_T differWhetherNameExported, IN SIZE_T index, OUT ULONG64* funcAddress);
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
		mov qword ptr [r9], rcx
		pop r15
		ret
	__asm__getFuncAddressByIndex_Via_DllBase ENDP

END
