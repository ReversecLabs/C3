IFDEF RAX
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; 64 bit code ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

.code

NtCreateThreadExWin10_1507 proc
	mov     r10, rcx
	mov     eax, 0B3h
	syscall 
	ret			
NtCreateThreadExWin10_1507 endp

NtCreateThreadExWin10_1511 proc
	mov     r10, rcx
	mov     eax, 0B4h
	syscall 
	ret			
NtCreateThreadExWin10_1511 endp

NtCreateThreadExWin10_1607 proc
	mov     r10, rcx
	mov     eax, 0B6h
	syscall 
	ret			
NtCreateThreadExWin10_1607 endp

NtCreateThreadExWin10_1703 proc
	mov     r10, rcx
	mov     eax, 0B9h
	syscall 
	ret			
NtCreateThreadExWin10_1703 endp

NtCreateThreadExWin10_1709 proc
	mov     r10, rcx
	mov     eax, 0BAh
	syscall 
	ret			
NtCreateThreadExWin10_1709 endp

NtCreateThreadExWin10_1803 proc
	mov     r10, rcx
	mov     eax, 0BBh
	syscall 
	ret			
NtCreateThreadExWin10_1803 endp

NtCreateThreadExWin10_1809 proc
	mov     r10, rcx
	mov     eax, 0BCh
	syscall 
	ret			
NtCreateThreadExWin10_1809 endp

NtCreateThreadExWin10_1903_1909 proc
	mov     r10, rcx
	mov     eax, 0BDh
	syscall 
	ret			
NtCreateThreadExWin10_1903_1909 endp

NtCreateThreadExWin10_2004 proc
	mov     r10, rcx
	mov     eax, 0C1h
	syscall 
	ret			
NtCreateThreadExWin10_2004 endp

NtCreateThreadExWin7 proc
	mov     r10, rcx
	mov     eax, 0A5h
	syscall 
	ret			
NtCreateThreadExWin7 endp

NtCreateThreadExWin80 proc
	mov     r10, rcx
	mov     eax, 0AFh
	syscall 
	ret			
NtCreateThreadExWin80 endp

NtCreateThreadExWin81 proc
	mov     r10, rcx
	mov     eax, 0B0h
	syscall 
	ret			
NtCreateThreadExWin81 endp

NtAllocateVirtualMemoryWin10 proc
	mov     r10, rcx
	mov     eax, 18h
	syscall 
	ret
NtAllocateVirtualMemoryWin10 endp

NtAllocateVirtualMemoryWin7 proc
	mov     r10, rcx
	mov     eax, 15h
	syscall 
	ret
NtAllocateVirtualMemoryWin7 endp

NtAllocateVirtualMemoryWin80 proc
	mov     r10, rcx
	mov     eax, 16h
	syscall 
	ret
NtAllocateVirtualMemoryWin80 endp

NtAllocateVirtualMemoryWin81 proc
	mov     r10, rcx
	mov     eax, 17h
	syscall 
	ret
NtAllocateVirtualMemoryWin81 endp

NtProtectVirtualMemoryWin10 proc
	mov     r10, rcx
	mov     eax, 50h
	syscall 
	ret
NtProtectVirtualMemoryWin10 endp

NtProtectVirtualMemoryWin7 proc
	mov     r10, rcx
	mov     eax, 4Dh
	syscall 
	ret
NtProtectVirtualMemoryWin7 endp

NtProtectVirtualMemoryWin80 proc
	mov     r10, rcx
	mov     eax, 4Eh
	syscall 
	ret
NtProtectVirtualMemoryWin80 endp

NtProtectVirtualMemoryWin81 proc
	mov     r10, rcx
	mov     eax, 4Fh
	syscall 
	ret
NtProtectVirtualMemoryWin81 endp

ELSE
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; 32 bit code ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

.model flat,c 
.stack 4096
ASSUME FS:NOTHING

.code

NtCreateThreadExWin10_1507 proc
	mov     eax, 0B3h
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin10_1507 endp

NtCreateThreadExWin10_1511 proc
	mov     eax, 0B4h
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin10_1511 endp

NtCreateThreadExWin10_1607 proc
	mov     eax, 0B6h
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin10_1607 endp

NtCreateThreadExWin10_1703 proc
	mov     eax, 0B9h
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin10_1703 endp

NtCreateThreadExWin10_1709 proc
	mov     eax, 0BAh
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin10_1709 endp

NtCreateThreadExWin10_1803 proc
	mov     eax, 0BBh
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin10_1803 endp

NtCreateThreadExWin10_1809 proc
	mov     eax, 0BCh
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin10_1809 endp

NtCreateThreadExWin10_1903_1909 proc
	mov     eax, 0BDh
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin10_1903_1909 endp

NtCreateThreadExWin10_2004 proc
	mov     eax, 0C1h
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin10_2004 endp

NtCreateThreadExWin7 proc
	mov     eax, 0A5h
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin7 endp

NtCreateThreadExWin80 proc
	mov     eax, 0AFh
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin80 endp

NtCreateThreadExWin81 proc
	mov     eax, 0B0h
	mov edx, fs:[0C0h]
	call edx 
	ret			
NtCreateThreadExWin81 endp

NtAllocateVirtualMemoryWin10 proc
	mov     eax, 18h
	mov edx, fs:[0C0h]
	call edx 
	ret
NtAllocateVirtualMemoryWin10 endp

NtAllocateVirtualMemoryWin7 proc
	mov     eax, 15h
	mov edx, fs:[0C0h]
	call edx 
	ret
NtAllocateVirtualMemoryWin7 endp

NtAllocateVirtualMemoryWin80 proc
	mov     eax, 16h
	mov edx, fs:[0C0h]
	call edx 
	ret
NtAllocateVirtualMemoryWin80 endp

NtAllocateVirtualMemoryWin81 proc
	mov     eax, 17h
	mov edx, fs:[0C0h]
	call edx 
	ret
NtAllocateVirtualMemoryWin81 endp

NtProtectVirtualMemoryWin10 proc
	mov     eax, 50h
	mov edx, fs:[0C0h]
	call edx 
	ret
NtProtectVirtualMemoryWin10 endp

NtProtectVirtualMemoryWin7 proc
	mov     eax, 4Dh
	mov edx, fs:[0C0h]
	call edx 
	ret
NtProtectVirtualMemoryWin7 endp

NtProtectVirtualMemoryWin80 proc
	mov     eax, 4Eh
	mov edx, fs:[0C0h]
	call edx 
	ret
NtProtectVirtualMemoryWin80 endp

NtProtectVirtualMemoryWin81 proc
	mov     eax, 4Fh
	mov edx, fs:[0C0h]
	call edx 
	ret
NtProtectVirtualMemoryWin81 endp

ENDIF

end

