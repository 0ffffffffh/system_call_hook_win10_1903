include ksamd64.inc
includelib ntoskrnl.lib

EXTERNDEF KhpHooked_NtClose : QWORD

.data

.code

KhpGetCr0 PROC
mov rax, cr0
ret
KhpGetCr0 ENDP

KhpSetCr0 PROC
mov cr0, rcx
ret
KhpSetCr0 ENDP

;6 args passed in it
KhpHookHandler PROC
	;rcx holds original syscall func

	push rsi
	push r12


	lea r12, KhpHooked_NtClose ; hook func
	
	lea rax, [rsp + 48] ; skip arg shadow area
	mov rsi, 20 ;max iter count
again:
	add rax, 8
	dec rsi
	test rsi,rsi
	jz fail
	cmp qword ptr[rax], rcx
	jne again

	;replace the original sys service routine with
	;our hook function from the determined stack 
	;location which is saved
	;by system service dispatcher and let the execution as is.
	;system service dispatcher will be restoring 
	;hook function pointer
	;from the stack and executes it.
	mov [rax], r12

fail:

	pop r12
	pop rsi

	xor rax,rax
	ret

KhpHookHandler ENDP

END
