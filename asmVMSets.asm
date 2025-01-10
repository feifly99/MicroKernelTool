.code

	;VMX VALID OPERATIONS FORM↓
	;
	;VMXON QWORD PTR [RAX]
	;VMXOFF
	;VMCLEAR QWORD PTR [RAX]
	;VMPTRLD QWORD PTR [RAX]
	;VMREAD RAX, RCX
	;VMWRITE RAX, RCX
	;VMLAUNCH
	;VMRESUME
	;VMCALL
	;
	;VMX VALID OPERATIONS FORM↑

	__vasm__CPUID PROC
		xor rcx, rcx
		mov rax, 1
		cpuid
		mov rax, 1
		shl rax, 5
		and rcx, rax
		mov rax, rcx
		ret
	__vasm__CPUID ENDP

	__vasm__enableVMXEonCR4 PROC
		push rbx
		mov rbx, cr4
		xor rax, rax
		inc rax
		sal rax, 13
		or rbx, rax
		mov cr4, rbx
		mov rax, cr4
		pop rbx
		ret
	__vasm__enableVMXEonCR4 ENDP

	__vasm__checkPAwidth PROC
		mov rax, 80000008h
		cpuid
		ret
	__vasm__checkPAwidth ENDP

	__vasm__IA32_FETURE_MSR_CHECK PROC
		rdmsr
		ret
	__vasm__IA32_FETURE_MSR_CHECK ENDP

	__vasm__VMXON PROC
		push rcx
		VMXON qword ptr [rsp]
		pushfq
		pop rax
		pop rcx
		ret
	__vasm__VMXON ENDP

	__vasm__VMXOFF PROC
		VMXOFF
		ret
	__vasm__VMXOFF ENDP

	__vasm__VMCLEAR PROC
		push rcx
		VMCLEAR qword ptr [rcx]
		pop rax
		ret
	__vasm__VMCLEAR ENDP

END
