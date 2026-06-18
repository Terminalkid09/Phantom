.section .text
.globl api_resolve_by_hash

# ── ROR13 Hash Function ──────────────────────────────────────────────────────
# Computes the ROR13 hash of a null-terminated ASCII string.
# The hash is used to identify API functions without storing their names.
#
# Input:
#   RCX = pointer to null-terminated ASCII string
# Returns:
#   EAX = ROR13 hash value
# ──────────────────────────────────────────────────────────────────────────────
ror13_hash:
    pushq   %rbx
    xorl    %eax, %eax          # eax = hash accumulator
    movq    %rcx, %rbx          # rbx = string pointer

.Lhash_loop:
    movzbl  (%rbx), %ecx        # ecx = next char (zero-extended)
    testb   %cl, %cl
    jz      .Lhash_done

    # Convert to uppercase (a-z → A-Z)
    cmpb    $97, %cl            # 'a'
    jb      .Lhash_byte_ok
    cmpb    $122, %cl           # 'z'
    ja      .Lhash_byte_ok
    subb    $32, %cl            # uppercase

.Lhash_byte_ok:
    rorl    $13, %eax
    addl    %ecx, %eax

    incq    %rbx
    jmp     .Lhash_loop

.Lhash_done:
    popq    %rbx
    ret


# ── api_resolve_ror13 ─────────────────────────────────────────────────────────
# Walks the Export Address Table (EAT) of the specified DLL module to find
# a function matching the given ROR13 hash.
#
# Input:
#   RCX = DLL base address (HMODULE)
#   EDX = ROR13 hash of target function name
#
# Returns:
#   RAX = function address (absolute), or NULL if not found
# ──────────────────────────────────────────────────────────────────────────────
api_resolve_ror13:
    pushq   %rbp
    pushq   %rbx
    pushq   %r12
    pushq   %r13
    pushq   %r14
    pushq   %r15
    subq    $8, %rsp            # align stack

    movq    %rcx, %r15          # r15 = DLL base
    movl    %edx, %r14d         # r14d = target hash

    # --- Parse DOS header ---
    movzwq  0x3C(%r15), %rax    # rax = e_lfanew
    addq    %r15, %rax          # rax = PE header address
    movq    %rax, %r13          # r13 = PE header

    # --- Parse NT headers ---
    # OptionalHeader is at PE + 0x18 (x64)  or PE + 0x14 (x86)
    # DataDirectory[0] (Export Directory) is at OptionalHeader + 0x70 (x64) or 0x60 (x86)
    # For x64: OptionalHeader starts at PE + 0x18
    # DataDirectory array starts at OptionalHeader + 0x70 (for PE32+)
    leaq    0x88(%r13), %rax    # rax = PE + 0x18 + 0x70 = export data directory
    movl    (%rax), %r12d       # r12d = Export Directory RVA
    movl    4(%rax), %r8d       #   skip Size field
    testl   %r12d, %r12d
    jz      .Lnot_found

    # --- Locate Export Directory ---
    addq    %r15, %r12          # r12 = absolute address of export dir
    movq    %r12, %rbx          # rbx = IMAGE_EXPORT_DIRECTORY

    # --- Extract key fields ---
    movl    0x18(%rbx), %r13d   # r13d = NumberOfNames
    movl    0x1C(%rbx), %r12d   # r12d = AddressOfFunctions RVA
    movl    0x20(%rbx), %r8d    # r8d  = AddressOfNames RVA
    movl    0x24(%rbx), %r9d    # r9d  = AddressOfNameOrdinals RVA

    # Convert RVAs to absolute addresses
    addq    %r15, %r12          # r12 = AddressOfFunctions
    addq    %r15, %r8           # r8  = AddressOfNames
    addq    %r15, %r9           # r9  = AddressOfNameOrdinals

    # --- Walk the Name Pointer Table ---
    xorl    %r10d, %r10d        # r10 = index (0..NumberOfNames-1)

.Lenum_names:
    cmpl    %r13d, %r10d        # done?
    jae     .Lnot_found

    # Get name pointer
    movl    (%r8, %r10, 4), %ecx  # ecx = RVA of name string
    addq    %r15, %rcx            # rcx = absolute address of name string

    # Hash this name
    pushq   %rcx
    pushq   %r8
    pushq   %r9
    pushq   %r10
    pushq   %r12
    pushq   %r13

    call    ror13_hash            # eax = hash of this function name

    popq    %r13
    popq    %r12
    popq    %r10
    popq    %r9
    popq    %r8
    addq    $8, %rsp              # pop saved rcx

    # Compare with target hash
    cmpl    %r14d, %eax
    je      .Lfound_name

    # Next name
    incq    %r10
    jmp     .Lenum_names

.Lfound_name:
    # Get ordinal index
    movzwl  (%r9, %r10, 2), %eax # eax = ordinal (WORD)
    movl    (%r12, %rax, 4), %ecx # ecx = function RVA
    addq    %r15, %rcx           # rcx = absolute function address
    movq    %rcx, %rax           # rax = result

    addq    $8, %rsp            # undo subq $8
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret

.Lnot_found:
    xorl    %eax, %eax

    addq    $8, %rsp            # undo subq $8
    popq    %r15
    popq    %r14
    popq    %r13
    popq    %r12
    popq    %rbx
    popq    %rbp
    ret
