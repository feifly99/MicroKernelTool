.code

	__asm__readDR0 PROC
		mov rax, dr0
		ret
	__asm__readDR0 ENDP

	__asm__readCR0 PROC
		mov rax, cr0
		ret
	__asm__readCR0 ENDP

	__asm__ChangeCR0Register PROC
		mov eax, 80040033h
		mov cr0, rax
		ret
	__asm__ChangeCR0Register ENDP

	__asm__RestoreCR0Register PROC
		mov rax, 80050033h
		mov cr0, rax
		ret
	__asm__RestoreCR0Register ENDP

	__asm__getcode PROC
		mov rax, rcx
		mov byte ptr [rax], 82h
		ret
	__asm__getcode ENDP

END