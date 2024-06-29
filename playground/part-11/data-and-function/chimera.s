	.file	"chimera.c"
	.text
	.globl	ftl_exit
	.type	ftl_exit, @function
ftl_exit:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -4(%rbp)
	movl	-4(%rbp), %eax
#APP
# 8 "chimera.c" 1
	             mov %eax, %edi 
            mov $60, %rax 
            syscall
# 0 "" 2
#NO_APP
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	ftl_exit, .-ftl_exit
	.globl	_start
	.type	_start, @function
_start:
.LFB1:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$0, %eax
	call	change_number@PLT
	movl	$0, %eax
	call	change_number@PLT
	movq	number@GOTPCREL(%rip), %rax
	movl	(%rax), %eax
	movl	%eax, %edi
	call	ftl_exit@PLT
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	_start, .-_start
	.ident	"GCC: (Debian 13.2.0-13) 13.2.0"
	.section	.note.GNU-stack,"",@progbits
