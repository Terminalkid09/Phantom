.section .text
.globl peb_get_ntdll
.globl peb_get_kernel32

# ── peb_get_ntdll ─────────────────────────────────────────────────────────────
# Returns the base address of ntdll.dll by walking the PEB
# InMemoryOrderModuleList (index 1 = ntdll).
#
# Returns: RAX = ntdll.dll base address, or NULL on failure
# ──────────────────────────────────────────────────────────────────────────────
peb_get_ntdll:
    pushq   %rbx
    pushq   %rsi

    movq    %gs:0x60, %rax      # rax = PEB
    testq   %rax, %rax
    jz      .Lerr_ntdll
    movq    0x18(%rax), %rax    # rax = PEB->Ldr
    testq   %rax, %rax
    jz      .Lerr_ntdll
    movq    0x10(%rax), %rsi    # rsi = Ldr->InMemoryOrderModuleList.Flink
    testq   %rsi, %rsi
    jz      .Lerr_ntdll

    # Skip first entry (the executable itself)
    movq    (%rsi), %rsi        # rsi = 2nd entry (ntdll)
    testq   %rsi, %rsi
    jz      .Lerr_ntdll

    # LDR_DATA_TABLE_ENTRY is 0x10 bytes before InMemoryOrderLinks field
    leaq    -0x10(%rsi), %rbx
    movq    0x30(%rbx), %rax    # rax = DllBase

    popq    %rsi
    popq    %rbx
    ret

.Lerr_ntdll:
    xorl    %eax, %eax
    popq    %rsi
    popq    %rbx
    ret


# ── peb_get_kernel32 ──────────────────────────────────────────────────────────
# Returns the base address of kernel32.dll by walking the PEB
# InMemoryOrderModuleList (index 2 = kernel32.dll on modern Windows).
#
# Returns: RAX = kernel32.dll base address, or NULL on failure
# ──────────────────────────────────────────────────────────────────────────────
peb_get_kernel32:
    pushq   %rbx
    pushq   %rsi

    movq    %gs:0x60, %rax      # rax = PEB
    testq   %rax, %rax
    jz      .Lerr_k32
    movq    0x18(%rax), %rax    # rax = PEB->Ldr
    testq   %rax, %rax
    jz      .Lerr_k32
    movq    0x10(%rax), %rsi    # rsi = Ldr->InMemoryOrderModuleList.Flink
    testq   %rsi, %rsi
    jz      .Lerr_k32

    # Skip exe (1st entry)
    movq    (%rsi), %rsi        # rsi = 2nd entry (ntdll)
    testq   %rsi, %rsi
    jz      .Lerr_k32
    # Skip ntdll (2nd entry) → now at 3rd = kernel32
    movq    (%rsi), %rsi        # rsi = 3rd entry (kernel32 or kernelbase)
    testq   %rsi, %rsi
    jz      .Lerr_k32

    # LDR_DATA_TABLE_ENTRY is 0x10 bytes before InMemoryOrderLinks
    leaq    -0x10(%rsi), %rbx
    movq    0x30(%rbx), %rax    # rax = DllBase

    popq    %rsi
    popq    %rbx
    ret

.Lerr_k32:
    xorl    %eax, %eax
    popq    %rsi
    popq    %rbx
    ret
