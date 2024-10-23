.code

	__asm__getIDT PROC
		sidt qword ptr [rcx]
		ret
	__asm__getIDT ENDP

	__asm__jump PROC
		jmp rcx
	__asm__jump ENDP

	__asm__readAllRegistors PROC ;ULONG64 __asm__checkAllRegistors(ULONG64* registorSavedPointer); //20
		push r15
		mov r15, rcx
		mov qword ptr [r15 + 0], rax
		mov qword ptr [r15 + 8h], rbx
		mov qword ptr [r15 + 10h], rcx
		mov qword ptr [r15 + 18h], rdx
		mov qword ptr [r15 + 20h], rdi
		mov qword ptr [r15 + 28h], rsi
		mov qword ptr [r15 + 30h], rbp
		mov qword ptr [r15 + 38h], rsp
		mov qword ptr [r15 + 40h], r8
		mov qword ptr [r15 + 48h], r9
		mov rax, cr0
		mov qword ptr [r15 + 50h], rax
		mov rax, cr2
		mov qword ptr [r15 + 58h], rax
		mov rax, cr3
		mov qword ptr [r15 + 60h], rax
		mov rax, cr4
		mov qword ptr [r15 + 68h], rax
		mov rax, dr0
		mov qword ptr [r15 + 70h], rax
		mov rax, dr1
		mov qword ptr [r15 + 78h], rax
		mov rax, dr2
		mov qword ptr [r15 + 80h], rax
		mov rax, dr3
		mov qword ptr [r15 + 88h], rax
		mov rax, dr6
		mov qword ptr [r15 + 90h], rax
		mov rax, dr7
		mov qword ptr [r15 + 98h], rax
		pop r15
		ret
	__asm__readAllRegistors ENDP

	__asm__getRAX PROC
		mov rax, rax
		ret
	__asm__getRAX ENDP

	__asm__getRBX PROC
		mov rax, rbx
		ret
	__asm__getRBX ENDP

	__asm__getRCX PROC
		mov rax, rcx
		ret
	__asm__getRCX ENDP

	__asm__getRDX PROC
		mov rax, rdx
		ret
	__asm__getRDX ENDP

	__asm__getRSI PROC
		mov rax, rsi
		ret
	__asm__getRSI ENDP

	__asm__getRDI PROC
		mov rax, rdi
		ret
	__asm__getRDI ENDP

	__asm__getRBP PROC
		mov rax, rbp
		ret
	__asm__getRBP ENDP

	__asm__getRSP PROC
		mov rax, rsp
		ret
	__asm__getRSP ENDP

	__asm__getR8 PROC
		mov rax, R8
		ret
	__asm__getR8 ENDP

	__asm__getR9 PROC
		mov rax, R9
		ret
	__asm__getR9 ENDP

	__asm__getCR0 PROC
		mov rax, cr0
		ret
	__asm__getCR0 ENDP

	__asm__getCR2 PROC
		mov rax, cr2
		ret
	__asm__getCR2 ENDP

	__asm__getCR3 PROC
		mov rax, cr3
		ret
	__asm__getCR3 ENDP

	__asm__getCR4 PROC
		mov rax, cr4
		ret
	__asm__getCR4 ENDP

	__asm__getDR0 PROC
		mov rax, dr0
		ret
	__asm__getDR0 ENDP

	__asm__getDR1 PROC
		mov rax, dr1
		ret
	__asm__getDR1 ENDP

	__asm__getDR2 PROC
		mov rax, dr2
		ret
	__asm__getDR2 ENDP

	__asm__getDR3 PROC
		mov rax, dr3
		ret
	__asm__getDR3 ENDP

	__asm__getDR6 PROC
		mov rax, dr6
		ret
	__asm__getDR6 ENDP

	__asm__getDR7 PROC
		mov rax, dr7
		ret
	__asm__getDR7 ENDP

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
