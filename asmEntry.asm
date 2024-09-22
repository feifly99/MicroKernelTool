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

	__asm__getExportFuncsNameByTargetIndex PROC ;_asm_getExportFuncNameByTargetIndex(ULONG64 DllBase, ULONG64 index)
		push r11
		push r10
		push rbx
		mov r11, rdx
		mov r10, rcx
		add rcx, 3Ch
		mov ecx, dword ptr [rcx]
		mov rax, r10
		add rax, rcx 
		add rax, 18h 
		mov eax, dword ptr [rax + 70h]
		mov rbx, r10
		add rbx, rax 
		mov ebx, dword ptr [rbx + 20h]
		mov rcx, r10
		add rcx, rbx
		mov ecx, dword ptr [rcx + r11 * 4]
		add r10, rcx
		mov rax, r10
		pop rbx
		pop r10
		pop r11
		ret
	__asm__getExportFuncsNameByTargetIndex ENDP

	__asm__getExportFuncsAddressByTargetIndex PROC ;_asm_getExportFuncsAddressByTargetIndex(ULONG64 DllBase, ULONG64 index)
		push r11
		push r10
		push rbx
		mov r11, rdx
		mov r10, rcx
		add rcx, 3Ch
		mov ecx, dword ptr [rcx]
		mov rax, r10
		add rax, rcx 
		add rax, 18h 
		mov eax, dword ptr [rax + 70h]
		mov rbx, r10
		add rbx, rax 
		mov ebx, dword ptr [rbx + 1Ch]
		mov rcx, r10
		add rcx, rbx
		mov ecx, dword ptr [rcx + r11 * 4]
		add r10, rcx
		mov rax, r10
		pop rbx
		pop r10
		pop r11
		ret
	__asm__getExportFuncsAddressByTargetIndex ENDP

	__asm__getNumberOfFunctionsExportedByName PROC ;_asm_getExportFuncsNumber(ULONG64 DllBase)
		push r10
		push rbx
		mov r10, rcx
		add rcx, 3Ch
		mov ecx, dword ptr [rcx]
		mov rax, r10
		add rax, rcx 
		add rax, 18h 
		mov eax, dword ptr [rax + 70h]
		mov rbx, r10
		add rbx, rax 
		mov ebx, dword ptr [rbx + 18h]
		mov rax, rbx
		pop rbx
		pop r10
		ret
	__asm__getNumberOfFunctionsExportedByName ENDP

END
