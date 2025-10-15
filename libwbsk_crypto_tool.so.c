typedef unsigned char   undefined;

typedef unsigned char    byte;
typedef unsigned char    dwfenc;
typedef unsigned int    dword;
typedef unsigned long    qword;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned int    undefined4;
typedef unsigned long    undefined8;
typedef unsigned short    word;
typedef struct eh_frame_hdr eh_frame_hdr, *Peh_frame_hdr;

struct eh_frame_hdr {
    byte eh_frame_hdr_version; // Exception Handler Frame Header Version
    dwfenc eh_frame_pointer_encoding; // Exception Handler Frame Pointer Encoding
    dwfenc eh_frame_desc_entry_count_encoding; // Encoding of # of Exception Handler FDEs
    dwfenc eh_frame_table_encoding; // Exception Handler Table Encoding
};

typedef struct fde_table_entry fde_table_entry, *Pfde_table_entry;

struct fde_table_entry {
    dword initial_loc; // Initial Location
    dword data_loc; // Data location
};

typedef struct timeval timeval, *Ptimeval;

typedef long __time_t;

typedef long __suseconds_t;

struct timeval {
    __time_t tv_sec;
    __suseconds_t tv_usec;
};

typedef struct timezone timezone, *Ptimezone;

typedef struct timezone *__timezone_ptr_t;

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

typedef ulong size_t;

typedef int __pid_t;

typedef struct Elf64_Rela Elf64_Rela, *PElf64_Rela;

struct Elf64_Rela {
    qword r_offset; // location to apply the relocation action
    qword r_info; // the symbol table index and the type of relocation
    qword r_addend; // a constant addend used to compute the relocatable field value
};

typedef struct Elf64_Dyn_AARCH64 Elf64_Dyn_AARCH64, *PElf64_Dyn_AARCH64;

typedef enum Elf64_DynTag_AARCH64 {
    DT_NULL=0,
    DT_NEEDED=1,
    DT_PLTRELSZ=2,
    DT_PLTGOT=3,
    DT_HASH=4,
    DT_STRTAB=5,
    DT_SYMTAB=6,
    DT_RELA=7,
    DT_RELASZ=8,
    DT_RELAENT=9,
    DT_STRSZ=10,
    DT_SYMENT=11,
    DT_INIT=12,
    DT_FINI=13,
    DT_SONAME=14,
    DT_RPATH=15,
    DT_SYMBOLIC=16,
    DT_REL=17,
    DT_RELSZ=18,
    DT_RELENT=19,
    DT_PLTREL=20,
    DT_DEBUG=21,
    DT_TEXTREL=22,
    DT_JMPREL=23,
    DT_BIND_NOW=24,
    DT_INIT_ARRAY=25,
    DT_FINI_ARRAY=26,
    DT_INIT_ARRAYSZ=27,
    DT_FINI_ARRAYSZ=28,
    DT_RUNPATH=29,
    DT_FLAGS=30,
    DT_PREINIT_ARRAY=32,
    DT_PREINIT_ARRAYSZ=33,
    DT_RELRSZ=35,
    DT_RELR=36,
    DT_RELRENT=37,
    DT_ANDROID_REL=1610612751,
    DT_ANDROID_RELSZ=1610612752,
    DT_ANDROID_RELA=1610612753,
    DT_ANDROID_RELASZ=1610612754,
    DT_ANDROID_RELR=1879040000,
    DT_ANDROID_RELRSZ=1879040001,
    DT_ANDROID_RELRENT=1879040003,
    DT_GNU_PRELINKED=1879047669,
    DT_GNU_CONFLICTSZ=1879047670,
    DT_GNU_LIBLISTSZ=1879047671,
    DT_CHECKSUM=1879047672,
    DT_PLTPADSZ=1879047673,
    DT_MOVEENT=1879047674,
    DT_MOVESZ=1879047675,
    DT_FEATURE_1=1879047676,
    DT_POSFLAG_1=1879047677,
    DT_SYMINSZ=1879047678,
    DT_SYMINENT=1879047679,
    DT_GNU_XHASH=1879047924,
    DT_GNU_HASH=1879047925,
    DT_TLSDESC_PLT=1879047926,
    DT_TLSDESC_GOT=1879047927,
    DT_GNU_CONFLICT=1879047928,
    DT_GNU_LIBLIST=1879047929,
    DT_CONFIG=1879047930,
    DT_DEPAUDIT=1879047931,
    DT_AUDIT=1879047932,
    DT_PLTPAD=1879047933,
    DT_MOVETAB=1879047934,
    DT_SYMINFO=1879047935,
    DT_VERSYM=1879048176,
    DT_RELACOUNT=1879048185,
    DT_RELCOUNT=1879048186,
    DT_FLAGS_1=1879048187,
    DT_VERDEF=1879048188,
    DT_VERDEFNUM=1879048189,
    DT_VERNEED=1879048190,
    DT_VERNEEDNUM=1879048191,
    DT_AUXILIARY=2147483645,
    DT_FILTER=2147483647
} Elf64_DynTag_AARCH64;

struct Elf64_Dyn_AARCH64 {
    enum Elf64_DynTag_AARCH64 d_tag;
    qword d_val;
};

typedef struct Elf64_Shdr Elf64_Shdr, *PElf64_Shdr;

typedef enum Elf_SectionHeaderType_AARCH64 {
    SHT_NULL=0,
    SHT_PROGBITS=1,
    SHT_SYMTAB=2,
    SHT_STRTAB=3,
    SHT_RELA=4,
    SHT_HASH=5,
    SHT_DYNAMIC=6,
    SHT_NOTE=7,
    SHT_NOBITS=8,
    SHT_REL=9,
    SHT_SHLIB=10,
    SHT_DYNSYM=11,
    SHT_INIT_ARRAY=14,
    SHT_FINI_ARRAY=15,
    SHT_PREINIT_ARRAY=16,
    SHT_GROUP=17,
    SHT_SYMTAB_SHNDX=18,
    SHT_ANDROID_REL=1610612737,
    SHT_ANDROID_RELA=1610612738,
    SHT_GNU_ATTRIBUTES=1879048181,
    SHT_GNU_HASH=1879048182,
    SHT_GNU_LIBLIST=1879048183,
    SHT_CHECKSUM=1879048184,
    SHT_SUNW_move=1879048186,
    SHT_SUNW_COMDAT=1879048187,
    SHT_SUNW_syminfo=1879048188,
    SHT_GNU_verdef=1879048189,
    SHT_GNU_verneed=1879048190,
    SHT_GNU_versym=1879048191,
    SHT_AARCH64_ATTRIBUTES=1879048195
} Elf_SectionHeaderType_AARCH64;

struct Elf64_Shdr {
    dword sh_name;
    enum Elf_SectionHeaderType_AARCH64 sh_type;
    qword sh_flags;
    qword sh_addr;
    qword sh_offset;
    qword sh_size;
    dword sh_link;
    dword sh_info;
    qword sh_addralign;
    qword sh_entsize;
};

typedef struct Elf64_Sym Elf64_Sym, *PElf64_Sym;

struct Elf64_Sym {
    dword st_name;
    byte st_info;
    byte st_other;
    word st_shndx;
    qword st_value;
    qword st_size;
};

typedef struct Elf64_Ehdr Elf64_Ehdr, *PElf64_Ehdr;

struct Elf64_Ehdr {
    byte e_ident_magic_num;
    char e_ident_magic_str[3];
    byte e_ident_class;
    byte e_ident_data;
    byte e_ident_version;
    byte e_ident_osabi;
    byte e_ident_abiversion;
    byte e_ident_pad[7];
    word e_type;
    word e_machine;
    dword e_version;
    qword e_entry;
    qword e_phoff;
    qword e_shoff;
    dword e_flags;
    word e_ehsize;
    word e_phentsize;
    word e_phnum;
    word e_shentsize;
    word e_shnum;
    word e_shstrndx;
};

typedef struct Elf64_Phdr Elf64_Phdr, *PElf64_Phdr;

typedef enum Elf_ProgramHeaderType_AARCH64 {
    PT_NULL=0,
    PT_LOAD=1,
    PT_DYNAMIC=2,
    PT_INTERP=3,
    PT_NOTE=4,
    PT_SHLIB=5,
    PT_PHDR=6,
    PT_TLS=7,
    PT_GNU_EH_FRAME=1685382480,
    PT_GNU_STACK=1685382481,
    PT_GNU_RELRO=1685382482,
    PT_AARCH64_ARCHEXT=1879048192
} Elf_ProgramHeaderType_AARCH64;

struct Elf64_Phdr {
    enum Elf_ProgramHeaderType_AARCH64 p_type;
    dword p_flags;
    qword p_offset;
    qword p_vaddr;
    qword p_paddr;
    qword p_filesz;
    qword p_memsz;
    qword p_align;
};

typedef struct evp_pkey_ctx_st evp_pkey_ctx_st, *Pevp_pkey_ctx_st;

struct evp_pkey_ctx_st {
};

typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;



undefined DAT_0011b000;
undefined __stack_chk_guard;
string s_com.byd.bydautolink_0011b008;
undefined4 DAT_0011b024;
undefined4 __bss_start__;
int DAT_0011b024;
undefined wbsk_WB_LAES_decrypt;
undefined wbsk_WB_LAES_encrypt;
undefined1[256] LAES_encrypt_xor1;
undefined1[256] LAES_encrypt_te4;
undefined1[1024] LAES_encrypt_te3;
undefined1[1024] LAES_encrypt_te2;
undefined1[1024] LAES_encrypt_te0;
undefined1[256] LAES_encrypt_xor;
undefined1[1024] LAES_encrypt_te1;
undefined1[256] LAES_encrypt_xor0;
undefined LAES_decrypt_td4;
undefined1[256] LAES_decrypt_xor1;
undefined1[1024] LAES_decrypt_td0;
undefined1[256] LAES_decrypt_xor;
undefined1[1024] LAES_decrypt_td1;
undefined1[1024] LAES_decrypt_td3;
undefined1[256] LAES_decrypt_xor0;
undefined1[1024] LAES_decrypt_td2;
undefined DAT_0010a168;
undefined DAT_0010a0f8;
int DAT_0011b028;
undefined4 DAT_0011b028;

void FUN_00101340(void)

{
  (*(code *)(undefined *)0x0)();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

long random(void)

{
  long lVar1;
  
  lVar1 = random();
  return lVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

__pid_t getpid(void)

{
  __pid_t _Var1;
  
  _Var1 = getpid();
  return _Var1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memcpy(void *__dest,void *__src,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memcpy(__dest,__src,__n);
  return pvVar1;
}



void __cxa_finalize(void)

{
  __cxa_finalize();
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * malloc(size_t __size)

{
  void *pvVar1;
  
  pvVar1 = malloc(__size);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

ulong strtoul(char *__nptr,char **__endptr,int __base)

{
  ulong uVar1;
  
  uVar1 = strtoul(__nptr,__endptr,__base);
  return uVar1;
}



void __android_log_print(void)

{
  __android_log_print();
  return;
}



void __stack_chk_fail(void)

{
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * calloc(size_t __nmemb,size_t __size)

{
  void *pvVar1;
  
  pvVar1 = calloc(__nmemb,__size);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strtok(char *__s,char *__delim)

{
  char *pcVar1;
  
  pcVar1 = strtok(__s,__delim);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int gettimeofday(timeval *__tv,__timezone_ptr_t __tz)

{
  int iVar1;
  
  iVar1 = gettimeofday(__tv,__tz);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void * memset(void *__s,int __c,size_t __n)

{
  void *pvVar1;
  
  pvVar1 = memset(__s,__c,__n);
  return pvVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

int strcmp(char *__s1,char *__s2)

{
  int iVar1;
  
  iVar1 = strcmp(__s1,__s2);
  return iVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void srandom(uint __seed)

{
  srandom(__seed);
  return;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

char * strchr(char *__s,int __c)

{
  char *pcVar1;
  
  pcVar1 = strchr(__s,__c);
  return pcVar1;
}



// WARNING: Unknown calling convention -- yet parameter storage is locked

void free(void *__ptr)

{
  free(__ptr);
  return;
}



void entry(void)

{
  __cxa_finalize(&DAT_0011b000);
  return;
}



int init(EVP_PKEY_CTX *ctx)

{
  int iVar1;
  
  check_package_name(ctx);
  iVar1 = check_md5(ctx);
  return iVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_LAES_ecb_encrypt
               (undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5,undefined4 param_6,undefined4 param_7)

{
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_28 = 1;
  local_24 = 4;
  local_10 = 0;
  local_18 = 1;
  local_14 = 0;
  local_20 = 0;
  local_c = param_7;
  wbsk_internal_crypto(param_1,param_2,param_3,param_4,0,0,param_5,param_6,&local_28);
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_LAES_ecb_decrypt
               (undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5,undefined4 param_6,undefined4 param_7)

{
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_28 = 1;
  local_24 = 4;
  local_10 = 0;
  local_18 = 1;
  local_14 = 1;
  local_20 = 0;
  local_c = param_7;
  wbsk_internal_crypto(param_1,param_2,param_3,param_4,0,0,param_5,param_6,&local_28);
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_skb_encrypt(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4,
                     undefined8 param_5,undefined4 param_6,undefined8 param_7,undefined4 param_8,
                     undefined4 param_9,undefined4 param_10)

{
  undefined4 local_28 [2];
  undefined4 local_20;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_28[0] = 0;
  local_10 = param_9;
  local_c = param_10;
  local_18 = 1;
  local_14 = 0;
  local_20 = 0;
  wbsk_internal_crypto(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_28);
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_skb_decrypt(undefined8 param_1,undefined4 param_2,undefined8 param_3,undefined8 param_4,
                     undefined8 param_5,undefined4 param_6,undefined8 param_7,undefined4 param_8,
                     undefined4 param_9,undefined4 param_10)

{
  undefined4 local_28 [2];
  undefined4 local_20;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_28[0] = 0;
  local_10 = param_9;
  local_c = param_10;
  local_18 = 1;
  local_14 = 1;
  local_20 = 0;
  wbsk_internal_crypto(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_28);
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_001017f8(void)

{
  uint uVar1;
  timeval local_18;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  uVar1 = getpid();
  gettimeofday(&local_18,(__timezone_ptr_t)0x0);
  srandom(uVar1 << 0x10 ^ uVar1 ^ (uint)local_18.tv_sec ^ (uint)local_18.tv_usec ^ 0xbb40e64e);
  random();
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



undefined8 FUN_00101888(byte *param_1,int param_2,long *param_3)

{
  void *pvVar1;
  undefined8 uVar2;
  int iStack_4;
  
  pvVar1 = malloc((long)param_2 - 4);
  *param_3 = (long)pvVar1;
  if (*param_3 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    switch(*param_1 ^ param_1[3]) {
    case 0:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 0;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0x80;
      break;
    case 1:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 0;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0x80;
      break;
    case 2:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 0;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0xc0;
      break;
    case 3:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 0;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0xc0;
      break;
    case 4:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 0;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0x100;
      break;
    case 5:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 0;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0x100;
      break;
    case 6:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 1;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0x40;
      break;
    case 7:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 1;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0x40;
      break;
    case 8:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 2;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0xc0;
      break;
    case 9:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 2;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0xc0;
      break;
    case 10:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 3;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0x80;
      break;
    case 0xb:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 3;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0x80;
      break;
    case 0xc:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 4;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0x80;
      break;
    case 0xd:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 4;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0x80;
      break;
    case 0xe:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 4;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0xc0;
      break;
    case 0xf:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 4;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0xc0;
      break;
    case 0x10:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 4;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0x100;
      break;
    case 0x11:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 4;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0x100;
      break;
    case 0x12:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 5;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0x40;
      break;
    case 0x13:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 5;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0x40;
      break;
    case 0x14:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 6;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0xc0;
      break;
    case 0x15:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 6;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0xc0;
      break;
    case 0x16:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 7;
      *(undefined4 *)(param_3 + 3) = 0;
      *(undefined4 *)(param_3 + 2) = 0x80;
      break;
    case 0x17:
      *(undefined4 *)((long)param_3 + 0x14) = 1;
      *(undefined4 *)((long)param_3 + 0xc) = 7;
      *(undefined4 *)(param_3 + 3) = 1;
      *(undefined4 *)(param_3 + 2) = 0x80;
      break;
    default:
      return 0xffffffff;
    }
    for (iStack_4 = 4; iStack_4 < param_2; iStack_4 = iStack_4 + 1) {
      *(byte *)(*param_3 + (long)iStack_4 + -4) = param_1[iStack_4] ^ param_1[iStack_4 % 3];
    }
    *(int *)(param_3 + 1) = param_2 + -4;
    uVar2 = 0;
  }
  return uVar2;
}



void FUN_00101e4c(long *param_1)

{
  if (*param_1 != 0) {
    free((void *)*param_1);
    *param_1 = 0;
  }
  return;
}



// WARNING: Switch with 1 destination removed at 0x00101f24 : 8 cases all go to same destination
// WARNING: Switch with 1 destination removed at 0x00101fe8 : 8 cases all go to same destination

undefined8 FUN_00101e84(long param_1,int param_2,int param_3,int param_4)

{
  int iVar1;
  undefined1 uVar2;
  int local_8;
  int local_4;
  
  iVar1 = 0;
  if (param_3 != 0) {
    iVar1 = param_2 / param_3;
  }
  local_8 = param_3 - (param_2 - iVar1 * param_3);
  if (local_8 == 0) {
    local_8 = param_3;
  }
  if (param_4 == 1) {
    memset((void *)(param_1 + param_2),local_8,(long)local_8);
  }
  else if (param_4 == 2) {
    for (local_4 = 0; local_4 < local_8 + -1; local_4 = local_4 + 1) {
      uVar2 = FUN_001017f8();
      *(undefined1 *)(param_1 + (param_2 + local_4)) = uVar2;
    }
    *(char *)(param_1 + (long)(param_2 + local_8) + -1) = (char)local_8;
  }
  return 0;
}



undefined4 FUN_00102000(int *param_1,long param_2)

{
  undefined4 local_4;
  
  local_4 = 0;
  if ((*param_1 == 0) || (param_1[1] == *(int *)(param_2 + 0xc))) {
    if ((param_1[4] == 0) || (param_1[5] == *(int *)(param_2 + 0x18))) {
      if ((param_1[2] != 0) && (param_1[3] != *(int *)(param_2 + 0x10))) {
        local_4 = 3;
      }
    }
    else {
      local_4 = 2;
    }
  }
  else {
    local_4 = 1;
  }
  return local_4;
}



void check_package_name(undefined8 param_1)

{
  int iVar1;
  char *__s2;
  char *local_10;
  
  if (s_com_byd_bydautolink_0011b008[0] == '\0') {
    DAT_0011b024 = 1;
  }
  else {
    __s2 = (char *)get_pkgname(param_1);
    local_10 = strtok(s_com_byd_bydautolink_0011b008,";");
    while (local_10 != (char *)0x0) {
      iVar1 = strcmp(local_10,__s2);
      if (iVar1 == 0) {
        DAT_0011b024 = 1;
        break;
      }
      local_10 = strtok((char *)0x0,";");
    }
    if (__s2 != (char *)0x0) {
      free(__s2);
    }
  }
  return;
}



void check_md5(void)

{
  __bss_start__ = 1;
  return;
}



undefined8 FUN_001021a8(long param_1,long param_2,long param_3,int param_4,int param_5,long param_6)

{
  undefined8 uVar1;
  
  if (param_1 == 0) {
    uVar1 = 100;
  }
  else if (param_2 == 0) {
    uVar1 = 0x65;
  }
  else if ((param_3 == 0) || (param_5 == param_4)) {
    if (param_6 == 0) {
      uVar1 = 0x67;
    }
    else {
      uVar1 = 0;
    }
  }
  else {
    uVar1 = 0x66;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_internal_crypto
               (void *param_1,int param_2,long param_3,int *param_4,undefined8 param_5,
               undefined4 param_6,undefined8 param_7,undefined4 param_8,long param_9)

{
  int iVar1;
  int iVar2;
  int local_4c;
  int local_48;
  uint local_44;
  void *local_38;
  undefined8 local_28;
  int local_1c;
  int local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_4c = -1;
  local_28 = 0;
  local_38 = (void *)0x0;
  local_44 = 0;
  if (__bss_start__ == 0) {
    local_4c = 6;
    iVar2 = local_4c;
  }
  else if (DAT_0011b024 == 0) {
    local_4c = 7;
    iVar2 = local_4c;
  }
  else {
    iVar2 = FUN_00101888(param_7,param_8,&local_28);
    if (iVar2 == -1) {
      local_4c = 5;
      iVar2 = local_4c;
    }
    else {
      if ((((local_1c == 0) || (local_1c == 3)) || (local_1c == 4)) || (local_1c == 7)) {
        local_44 = 0x10;
      }
      else if (((local_1c == 1) || (local_1c == 2)) || ((local_1c == 5 || (local_1c == 6)))) {
        local_44 = 8;
      }
      iVar2 = FUN_001021a8(param_1,param_3,param_5,param_6,local_44,param_7);
      if (iVar2 < 1) {
        iVar2 = FUN_00102000(param_9,&local_28);
        if (iVar2 == 0) {
          if (*(int *)(param_9 + 0x1c) == 0) {
            iVar2 = 0;
            if (local_44 != 0) {
              iVar2 = param_2 / (int)local_44;
            }
            if (param_2 != iVar2 * local_44) {
              local_4c = 0xe;
              iVar2 = local_4c;
              goto LAB_00102754;
            }
          }
          if (local_10 == 1) {
            iVar2 = 0;
            if (local_44 != 0) {
              iVar2 = param_2 / (int)local_44;
            }
            if (param_2 != iVar2 * local_44) {
              local_4c = 0xe;
              iVar2 = local_4c;
              goto LAB_00102754;
            }
          }
          local_48 = param_2;
          if ((*(int *)(param_9 + 0x1c) != 0) && (local_10 == 0)) {
            iVar2 = 0;
            if (local_44 != 0) {
              iVar2 = param_2 / (int)local_44;
            }
            local_48 = (iVar2 + 1) * local_44;
          }
          if (*param_4 < local_48) {
            local_4c = 3;
            iVar2 = local_4c;
          }
          else {
            local_38 = calloc((long)local_48,1);
            memcpy(local_38,param_1,(long)param_2);
            if ((*(int *)(param_9 + 0x1c) != 0) && (local_10 == 0)) {
              FUN_00101e84(local_38,param_2,local_44,*(undefined4 *)(param_9 + 0x1c),
                           *(undefined4 *)(param_9 + 4));
            }
            if ((local_1c == 4) && (local_10 == 0)) {
              if (*(int *)(param_9 + 0x18) == 0) {
                local_4c = wbsk_CRYPTO_ecb128_encrypt
                                     (local_38,param_3,local_48,&local_28,wbsk_WB_LAES_encrypt);
              }
              else if (*(int *)(param_9 + 0x18) == 1) {
                local_4c = wbsk_CRYPTO_cbc128_encrypt
                                     (local_38,param_3,local_48,param_5,&local_28,
                                      wbsk_WB_LAES_encrypt);
              }
            }
            else if ((local_1c == 4) && (local_10 == 1)) {
              if (*(int *)(param_9 + 0x18) == 0) {
                local_4c = wbsk_CRYPTO_ecb128_decrypt
                                     (local_38,param_3,local_48,&local_28,wbsk_WB_LAES_decrypt);
              }
              else if (*(int *)(param_9 + 0x18) == 1) {
                local_4c = wbsk_CRYPTO_cbc128_decrypt
                                     (local_38,param_3,local_48,param_5,&local_28,
                                      wbsk_WB_LAES_decrypt);
              }
            }
            iVar2 = local_4c;
            if (local_4c == 0) {
              if (*(int *)(param_9 + 0x1c) == 0) {
                *param_4 = param_2;
              }
              else if (*(int *)(param_9 + 0x14) == 1) {
                if (local_44 < *(byte *)(param_3 + (long)param_2 + -1)) {
                  if ((int)(uint)*(byte *)(param_3 + (long)param_2 + -1) < param_2) {
                    param_2 = param_2 - (uint)*(byte *)(param_3 + (long)param_2 + -1);
                  }
                }
                else {
                  param_2 = param_2 - (uint)*(byte *)(param_3 + (long)param_2 + -1);
                }
                *param_4 = param_2;
              }
              else if (*(int *)(param_9 + 0x14) == 0) {
                iVar1 = 0;
                if (local_44 != 0) {
                  iVar1 = param_2 / (int)local_44;
                }
                *param_4 = (iVar1 + 1) * local_44;
              }
            }
          }
        }
        else {
          local_4c = 2;
          iVar2 = local_4c;
        }
      }
    }
  }
LAB_00102754:
  local_4c = iVar2;
  if (local_38 != (void *)0x0) {
    free(local_38);
  }
  FUN_00101e4c(&local_28);
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(local_4c);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_CRYPTO_ecb64_encrypt
               (long param_1,long param_2,int param_3,undefined8 param_4,code *param_5)

{
  undefined4 local_10;
  int local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_10 = 0;
  for (local_c = 0; local_c < param_3; local_c = local_c + 8) {
    (*param_5)(param_1 + local_c,param_2 + local_c,param_4,&local_10);
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(local_10);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_CRYPTO_ecb64_decrypt
               (long param_1,long param_2,int param_3,undefined8 param_4,code *param_5)

{
  undefined4 local_10;
  int local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_10 = 0;
  for (local_c = 0; local_c < param_3; local_c = local_c + 8) {
    (*param_5)(param_1 + local_c,param_2 + local_c,param_4,&local_10);
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(local_10);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_CRYPTO_ecb128_encrypt
               (long param_1,long param_2,int param_3,undefined8 param_4,code *param_5)

{
  undefined4 local_10;
  int local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_10 = 0;
  for (local_c = 0; local_c < param_3; local_c = local_c + 0x10) {
    (*param_5)(param_1 + local_c,param_2 + local_c,param_4,&local_10);
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(local_10);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_CRYPTO_ecb128_decrypt
               (long param_1,long param_2,int param_3,undefined8 param_4,code *param_5)

{
  undefined4 local_10;
  int local_c;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_10 = 0;
  for (local_c = 0; local_c < param_3; local_c = local_c + 0x10) {
    (*param_5)(param_1 + local_c,param_2 + local_c,param_4,&local_10);
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(local_10);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_CRYPTO_cbc64_encrypt
               (long param_1,long param_2,int param_3,long param_4,undefined8 param_5,code *param_6)

{
  int local_34;
  long local_30;
  long local_28;
  undefined4 local_18;
  int local_14;
  long local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_18 = 0;
  local_30 = param_2;
  local_28 = param_1;
  local_10 = param_4;
  for (local_34 = param_3; 7 < local_34; local_34 = local_34 + -8) {
    for (local_14 = 0; local_14 < 8; local_14 = local_14 + 1) {
      *(byte *)(local_30 + local_14) =
           *(byte *)(local_28 + local_14) ^ *(byte *)(local_10 + local_14);
    }
    (*param_6)(local_30,local_30,param_5,&local_18);
    local_10 = local_30;
    local_28 = local_28 + 8;
    local_30 = local_30 + 8;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(local_18);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_CRYPTO_cbc64_decrypt
               (long param_1,long param_2,int param_3,long param_4,undefined8 param_5,code *param_6)

{
  int local_34;
  long local_30;
  long local_28;
  undefined4 local_18;
  int local_14;
  long local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_18 = 0;
  local_30 = param_2;
  local_28 = param_1;
  local_10 = param_4;
  for (local_34 = param_3; 7 < local_34; local_34 = local_34 + -8) {
    (*param_6)(local_28,local_30,param_5,&local_18);
    for (local_14 = 0; local_14 < 8; local_14 = local_14 + 1) {
      *(byte *)(local_30 + local_14) =
           *(byte *)(local_30 + local_14) ^ *(byte *)(local_10 + local_14);
    }
    local_10 = local_28;
    local_28 = local_28 + 8;
    local_30 = local_30 + 8;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(local_18);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_CRYPTO_cbc128_encrypt
               (long param_1,long param_2,int param_3,long param_4,undefined8 param_5,code *param_6)

{
  int local_34;
  long local_30;
  long local_28;
  undefined4 local_18;
  int local_14;
  long local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_18 = 0;
  local_30 = param_2;
  local_28 = param_1;
  local_10 = param_4;
  for (local_34 = param_3; 0xf < local_34; local_34 = local_34 + -0x10) {
    for (local_14 = 0; local_14 < 0x10; local_14 = local_14 + 1) {
      *(byte *)(local_30 + local_14) =
           *(byte *)(local_28 + local_14) ^ *(byte *)(local_10 + local_14);
    }
    (*param_6)(local_30,local_30,param_5,&local_18);
    local_10 = local_30;
    local_28 = local_28 + 0x10;
    local_30 = local_30 + 0x10;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(local_18);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_CRYPTO_cbc128_decrypt
               (long param_1,long param_2,int param_3,long param_4,undefined8 param_5,code *param_6)

{
  int local_34;
  long local_30;
  long local_28;
  undefined4 local_18;
  int local_14;
  long local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_18 = 0;
  local_30 = param_2;
  local_28 = param_1;
  local_10 = param_4;
  for (local_34 = param_3; 0xf < local_34; local_34 = local_34 + -0x10) {
    (*param_6)(local_28,local_30,param_5,&local_18);
    for (local_14 = 0; local_14 < 0x10; local_14 = local_14 + 1) {
      *(byte *)(local_30 + local_14) =
           *(byte *)(local_30 + local_14) ^ *(byte *)(local_10 + local_14);
    }
    local_10 = local_28;
    local_28 = local_28 + 0x10;
    local_30 = local_30 + 0x10;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail(local_18);
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_WB_LAES_encrypt(long param_1,long param_2,long *param_3)

{
  int iVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  int local_4c;
  int local_48;
  byte local_38 [16];
  byte local_28 [16];
  byte local_18 [16];
  long local_8;
  
  lVar3 = ___stack_chk_guard;
  local_8 = ___stack_chk_guard;
  lVar4 = *param_3;
  iVar2 = (int)param_3[2];
  iVar1 = iVar2 + 0x1f;
  if (-1 < iVar2) {
    iVar1 = iVar2;
  }
  for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
    local_38[local_48] =
         LAES_encrypt_xor0
         [(int)((uint)(*(byte *)(param_1 + local_48) >> 4) << 4 ^
               (uint)(*(byte *)(lVar4 + local_48) >> 4))] & 0xf0 ^
         (byte)LAES_encrypt_xor0
               [(int)((*(byte *)(param_1 + local_48) & 0xf) << 4 ^ *(byte *)(lVar4 + local_48) & 0xf
                     )] >> 4;
  }
  for (local_4c = 1; local_4c < (iVar1 >> 5) + 6; local_4c = local_4c + 1) {
    local_28[0] = (byte)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[0] * 4)
                        >> 0x18);
    local_28[1] = (char)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[0] * 4)
                        >> 0x10);
    local_28[2] = (char)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[0] * 4)
                        >> 8);
    local_28[3] = (char)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[0] * 4);
    local_28[4] = (char)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[4] * 4)
                        >> 0x18);
    local_28[5] = (char)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[4] * 4)
                        >> 0x10);
    local_28[6] = (char)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[4] * 4)
                        >> 8);
    local_28[7] = (char)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[4] * 4);
    local_28[8] = (char)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[8] * 4)
                        >> 0x18);
    local_28[9] = (char)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[8] * 4)
                        >> 0x10);
    local_28[10] = (char)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[8] * 4)
                         >> 8);
    local_28[0xb] = (char)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[8] * 4);
    local_28[0xc] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[0xc] * 4) >> 0x18
               );
    local_28[0xd] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[0xc] * 4) >> 0x10
               );
    local_28[0xe] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[0xc] * 4) >> 8);
    local_28[0xf] = (char)*(undefined4 *)(LAES_encrypt_te0 + (long)(int)(uint)local_38[0xc] * 4);
    local_18[0] = (byte)((uint)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[5] * 4)
                        >> 0x18);
    local_18[1] = (char)((uint)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[5] * 4)
                        >> 0x10);
    local_18[2] = (char)((uint)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[5] * 4)
                        >> 8);
    local_18[3] = (char)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[5] * 4);
    local_18[4] = (char)((uint)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[9] * 4)
                        >> 0x18);
    local_18[5] = (char)((uint)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[9] * 4)
                        >> 0x10);
    local_18[6] = (char)((uint)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[9] * 4)
                        >> 8);
    local_18[7] = (char)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[9] * 4);
    local_18[8] = (char)((uint)*(undefined4 *)
                                (LAES_encrypt_te1 + (long)(int)(uint)local_38[0xd] * 4) >> 0x18);
    local_18[9] = (char)((uint)*(undefined4 *)
                                (LAES_encrypt_te1 + (long)(int)(uint)local_38[0xd] * 4) >> 0x10);
    local_18[10] = (char)((uint)*(undefined4 *)
                                 (LAES_encrypt_te1 + (long)(int)(uint)local_38[0xd] * 4) >> 8);
    local_18[0xb] = (char)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[0xd] * 4);
    local_18[0xc] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[1] * 4) >> 0x18);
    local_18[0xd] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[1] * 4) >> 0x10);
    local_18[0xe] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[1] * 4) >> 8);
    local_18[0xf] = (char)*(undefined4 *)(LAES_encrypt_te1 + (long)(int)(uint)local_38[1] * 4);
    for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
      local_28[local_48] =
           LAES_encrypt_xor
           [(int)((uint)(local_28[local_48] >> 4) << 4 ^ (uint)(local_18[local_48] >> 4))] & 0xf0 ^
           (byte)LAES_encrypt_xor[(int)((local_28[local_48] & 0xf) << 4 ^ local_18[local_48] & 0xf)]
           >> 4;
    }
    local_18[0] = (byte)((uint)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[10] * 4)
                        >> 0x18);
    local_18[1] = (char)((uint)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[10] * 4)
                        >> 0x10);
    local_18[2] = (char)((uint)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[10] * 4)
                        >> 8);
    local_18[3] = (char)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[10] * 4);
    local_18[4] = (char)((uint)*(undefined4 *)
                                (LAES_encrypt_te2 + (long)(int)(uint)local_38[0xe] * 4) >> 0x18);
    local_18[5] = (char)((uint)*(undefined4 *)
                                (LAES_encrypt_te2 + (long)(int)(uint)local_38[0xe] * 4) >> 0x10);
    local_18[6] = (char)((uint)*(undefined4 *)
                                (LAES_encrypt_te2 + (long)(int)(uint)local_38[0xe] * 4) >> 8);
    local_18[7] = (char)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[0xe] * 4);
    local_18[8] = (char)((uint)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[2] * 4)
                        >> 0x18);
    local_18[9] = (char)((uint)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[2] * 4)
                        >> 0x10);
    local_18[10] = (char)((uint)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[2] * 4)
                         >> 8);
    local_18[0xb] = (char)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[2] * 4);
    local_18[0xc] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[6] * 4) >> 0x18);
    local_18[0xd] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[6] * 4) >> 0x10);
    local_18[0xe] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[6] * 4) >> 8);
    local_18[0xf] = (char)*(undefined4 *)(LAES_encrypt_te2 + (long)(int)(uint)local_38[6] * 4);
    for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
      local_28[local_48] =
           LAES_encrypt_xor
           [(int)((uint)(local_28[local_48] >> 4) << 4 ^ (uint)(local_18[local_48] >> 4))] & 0xf0 ^
           (byte)LAES_encrypt_xor[(int)((local_28[local_48] & 0xf) << 4 ^ local_18[local_48] & 0xf)]
           >> 4;
    }
    local_18[0] = (byte)((uint)*(undefined4 *)
                                (LAES_encrypt_te3 + (long)(int)(uint)local_38[0xf] * 4) >> 0x18);
    local_18[1] = (char)((uint)*(undefined4 *)
                                (LAES_encrypt_te3 + (long)(int)(uint)local_38[0xf] * 4) >> 0x10);
    local_18[2] = (char)((uint)*(undefined4 *)
                                (LAES_encrypt_te3 + (long)(int)(uint)local_38[0xf] * 4) >> 8);
    local_18[3] = (char)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[0xf] * 4);
    local_18[4] = (char)((uint)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[3] * 4)
                        >> 0x18);
    local_18[5] = (char)((uint)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[3] * 4)
                        >> 0x10);
    local_18[6] = (char)((uint)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[3] * 4)
                        >> 8);
    local_18[7] = (char)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[3] * 4);
    local_18[8] = (char)((uint)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[7] * 4)
                        >> 0x18);
    local_18[9] = (char)((uint)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[7] * 4)
                        >> 0x10);
    local_18[10] = (char)((uint)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[7] * 4)
                         >> 8);
    local_18[0xb] = (char)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[7] * 4);
    local_18[0xc] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[0xb] * 4) >> 0x18
               );
    local_18[0xd] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[0xb] * 4) >> 0x10
               );
    local_18[0xe] =
         (char)((uint)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[0xb] * 4) >> 8);
    local_18[0xf] = (char)*(undefined4 *)(LAES_encrypt_te3 + (long)(int)(uint)local_38[0xb] * 4);
    for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
      local_28[local_48] =
           LAES_encrypt_xor
           [(int)((uint)(local_28[local_48] >> 4) << 4 ^ (uint)(local_18[local_48] >> 4))] & 0xf0 ^
           (byte)LAES_encrypt_xor[(int)((local_28[local_48] & 0xf) << 4 ^ local_18[local_48] & 0xf)]
           >> 4;
    }
    for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
      local_38[local_48] =
           LAES_encrypt_xor
           [(int)((uint)(local_28[local_48] >> 4) << 4 ^
                 (uint)(*(byte *)(lVar4 + (local_4c * 0x10 + local_48)) >> 4))] & 0xf0 ^
           (byte)LAES_encrypt_xor
                 [(int)((local_28[local_48] & 0xf) << 4 ^
                       *(byte *)(lVar4 + (local_4c * 0x10 + local_48)) & 0xf)] >> 4;
    }
  }
  local_28[0] = LAES_encrypt_te4[(int)(uint)local_38[0]];
  local_28[1] = LAES_encrypt_te4[(int)(uint)local_38[5]];
  local_28[2] = LAES_encrypt_te4[(int)(uint)local_38[10]];
  local_28[3] = LAES_encrypt_te4[(int)(uint)local_38[0xf]];
  local_28[4] = LAES_encrypt_te4[(int)(uint)local_38[4]];
  local_28[5] = LAES_encrypt_te4[(int)(uint)local_38[9]];
  local_28[6] = LAES_encrypt_te4[(int)(uint)local_38[0xe]];
  local_28[7] = LAES_encrypt_te4[(int)(uint)local_38[3]];
  local_28[8] = LAES_encrypt_te4[(int)(uint)local_38[8]];
  local_28[9] = LAES_encrypt_te4[(int)(uint)local_38[0xd]];
  local_28[10] = LAES_encrypt_te4[(int)(uint)local_38[2]];
  local_28[0xb] = LAES_encrypt_te4[(int)(uint)local_38[7]];
  local_28[0xc] = LAES_encrypt_te4[(int)(uint)local_38[0xc]];
  local_28[0xd] = LAES_encrypt_te4[(int)(uint)local_38[1]];
  local_28[0xe] = LAES_encrypt_te4[(int)(uint)local_38[6]];
  local_28[0xf] = LAES_encrypt_te4[(int)(uint)local_38[0xb]];
  for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
    *(byte *)(param_2 + local_48) =
         LAES_encrypt_xor1
         [(int)((uint)(local_28[local_48] >> 4) << 4 ^
               (uint)(*(byte *)(lVar4 + (local_4c * 0x10 + local_48)) >> 4))] & 0xf0 ^
         (byte)LAES_encrypt_xor1
               [(int)((local_28[local_48] & 0xf) << 4 ^
                     *(byte *)(lVar4 + (local_4c * 0x10 + local_48)) & 0xf)] >> 4;
  }
  if (lVar3 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void wbsk_WB_LAES_decrypt(long param_1,long param_2,long *param_3)

{
  int iVar1;
  int iVar2;
  long lVar3;
  long lVar4;
  int local_4c;
  int local_48;
  byte local_38 [16];
  byte local_28 [16];
  byte local_18 [16];
  long local_8;
  
  lVar3 = ___stack_chk_guard;
  local_8 = ___stack_chk_guard;
  lVar4 = *param_3;
  iVar2 = (int)param_3[2];
  iVar1 = iVar2 + 0x1f;
  if (-1 < iVar2) {
    iVar1 = iVar2;
  }
  for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
    local_38[local_48] =
         LAES_decrypt_xor0
         [(int)((uint)(*(byte *)(param_1 + local_48) >> 4) << 4 ^
               (uint)(*(byte *)(lVar4 + local_48) >> 4))] & 0xf0 ^
         (byte)LAES_decrypt_xor0
               [(int)((*(byte *)(param_1 + local_48) & 0xf) << 4 ^ *(byte *)(lVar4 + local_48) & 0xf
                     )] >> 4;
  }
  for (local_4c = 1; local_4c < (iVar1 >> 5) + 6; local_4c = local_4c + 1) {
    local_28[0] = (byte)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[0] * 4)
                        >> 0x18);
    local_28[1] = (char)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[0] * 4)
                        >> 0x10);
    local_28[2] = (char)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[0] * 4)
                        >> 8);
    local_28[3] = (char)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[0] * 4);
    local_28[4] = (char)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[4] * 4)
                        >> 0x18);
    local_28[5] = (char)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[4] * 4)
                        >> 0x10);
    local_28[6] = (char)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[4] * 4)
                        >> 8);
    local_28[7] = (char)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[4] * 4);
    local_28[8] = (char)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[8] * 4)
                        >> 0x18);
    local_28[9] = (char)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[8] * 4)
                        >> 0x10);
    local_28[10] = (char)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[8] * 4)
                         >> 8);
    local_28[0xb] = (char)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[8] * 4);
    local_28[0xc] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[0xc] * 4) >> 0x18
               );
    local_28[0xd] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[0xc] * 4) >> 0x10
               );
    local_28[0xe] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[0xc] * 4) >> 8);
    local_28[0xf] = (char)*(undefined4 *)(LAES_decrypt_td0 + (long)(int)(uint)local_38[0xc] * 4);
    local_18[0] = (byte)((uint)*(undefined4 *)
                                (LAES_decrypt_td1 + (long)(int)(uint)local_38[0xd] * 4) >> 0x18);
    local_18[1] = (char)((uint)*(undefined4 *)
                                (LAES_decrypt_td1 + (long)(int)(uint)local_38[0xd] * 4) >> 0x10);
    local_18[2] = (char)((uint)*(undefined4 *)
                                (LAES_decrypt_td1 + (long)(int)(uint)local_38[0xd] * 4) >> 8);
    local_18[3] = (char)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[0xd] * 4);
    local_18[4] = (char)((uint)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[1] * 4)
                        >> 0x18);
    local_18[5] = (char)((uint)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[1] * 4)
                        >> 0x10);
    local_18[6] = (char)((uint)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[1] * 4)
                        >> 8);
    local_18[7] = (char)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[1] * 4);
    local_18[8] = (char)((uint)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[5] * 4)
                        >> 0x18);
    local_18[9] = (char)((uint)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[5] * 4)
                        >> 0x10);
    local_18[10] = (char)((uint)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[5] * 4)
                         >> 8);
    local_18[0xb] = (char)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[5] * 4);
    local_18[0xc] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[9] * 4) >> 0x18);
    local_18[0xd] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[9] * 4) >> 0x10);
    local_18[0xe] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[9] * 4) >> 8);
    local_18[0xf] = (char)*(undefined4 *)(LAES_decrypt_td1 + (long)(int)(uint)local_38[9] * 4);
    for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
      local_28[local_48] =
           LAES_decrypt_xor
           [(int)((uint)(local_28[local_48] >> 4) << 4 ^ (uint)(local_18[local_48] >> 4))] & 0xf0 ^
           (byte)LAES_decrypt_xor[(int)((local_28[local_48] & 0xf) << 4 ^ local_18[local_48] & 0xf)]
           >> 4;
    }
    local_18[0] = (byte)((uint)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[10] * 4)
                        >> 0x18);
    local_18[1] = (char)((uint)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[10] * 4)
                        >> 0x10);
    local_18[2] = (char)((uint)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[10] * 4)
                        >> 8);
    local_18[3] = (char)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[10] * 4);
    local_18[4] = (char)((uint)*(undefined4 *)
                                (LAES_decrypt_td2 + (long)(int)(uint)local_38[0xe] * 4) >> 0x18);
    local_18[5] = (char)((uint)*(undefined4 *)
                                (LAES_decrypt_td2 + (long)(int)(uint)local_38[0xe] * 4) >> 0x10);
    local_18[6] = (char)((uint)*(undefined4 *)
                                (LAES_decrypt_td2 + (long)(int)(uint)local_38[0xe] * 4) >> 8);
    local_18[7] = (char)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[0xe] * 4);
    local_18[8] = (char)((uint)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[2] * 4)
                        >> 0x18);
    local_18[9] = (char)((uint)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[2] * 4)
                        >> 0x10);
    local_18[10] = (char)((uint)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[2] * 4)
                         >> 8);
    local_18[0xb] = (char)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[2] * 4);
    local_18[0xc] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[6] * 4) >> 0x18);
    local_18[0xd] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[6] * 4) >> 0x10);
    local_18[0xe] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[6] * 4) >> 8);
    local_18[0xf] = (char)*(undefined4 *)(LAES_decrypt_td2 + (long)(int)(uint)local_38[6] * 4);
    for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
      local_28[local_48] =
           LAES_decrypt_xor
           [(int)((uint)(local_28[local_48] >> 4) << 4 ^ (uint)(local_18[local_48] >> 4))] & 0xf0 ^
           (byte)LAES_decrypt_xor[(int)((local_28[local_48] & 0xf) << 4 ^ local_18[local_48] & 0xf)]
           >> 4;
    }
    local_18[0] = (byte)((uint)*(undefined4 *)(LAES_decrypt_td3 + (long)(int)(uint)local_38[7] * 4)
                        >> 0x18);
    local_18[1] = (char)((uint)*(undefined4 *)(LAES_decrypt_td3 + (long)(int)(uint)local_38[7] * 4)
                        >> 0x10);
    local_18[2] = (char)((uint)*(undefined4 *)(LAES_decrypt_td3 + (long)(int)(uint)local_38[7] * 4)
                        >> 8);
    local_18[3] = (char)*(undefined4 *)(LAES_decrypt_td3 + (long)(int)(uint)local_38[7] * 4);
    local_18[4] = (char)((uint)*(undefined4 *)
                                (LAES_decrypt_td3 + (long)(int)(uint)local_38[0xb] * 4) >> 0x18);
    local_18[5] = (char)((uint)*(undefined4 *)
                                (LAES_decrypt_td3 + (long)(int)(uint)local_38[0xb] * 4) >> 0x10);
    local_18[6] = (char)((uint)*(undefined4 *)
                                (LAES_decrypt_td3 + (long)(int)(uint)local_38[0xb] * 4) >> 8);
    local_18[7] = (char)*(undefined4 *)(LAES_decrypt_td3 + (long)(int)(uint)local_38[0xb] * 4);
    local_18[8] = (char)((uint)*(undefined4 *)
                                (LAES_decrypt_td3 + (long)(int)(uint)local_38[0xf] * 4) >> 0x18);
    local_18[9] = (char)((uint)*(undefined4 *)
                                (LAES_decrypt_td3 + (long)(int)(uint)local_38[0xf] * 4) >> 0x10);
    local_18[10] = (char)((uint)*(undefined4 *)
                                 (LAES_decrypt_td3 + (long)(int)(uint)local_38[0xf] * 4) >> 8);
    local_18[0xb] = (char)*(undefined4 *)(LAES_decrypt_td3 + (long)(int)(uint)local_38[0xf] * 4);
    local_18[0xc] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td3 + (long)(int)(uint)local_38[3] * 4) >> 0x18);
    local_18[0xd] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td3 + (long)(int)(uint)local_38[3] * 4) >> 0x10);
    local_18[0xe] =
         (char)((uint)*(undefined4 *)(LAES_decrypt_td3 + (long)(int)(uint)local_38[3] * 4) >> 8);
    local_18[0xf] = (char)*(undefined4 *)(LAES_decrypt_td3 + (long)(int)(uint)local_38[3] * 4);
    for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
      local_28[local_48] =
           LAES_decrypt_xor
           [(int)((uint)(local_28[local_48] >> 4) << 4 ^ (uint)(local_18[local_48] >> 4))] & 0xf0 ^
           (byte)LAES_decrypt_xor[(int)((local_28[local_48] & 0xf) << 4 ^ local_18[local_48] & 0xf)]
           >> 4;
    }
    for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
      local_38[local_48] =
           LAES_decrypt_xor
           [(int)((uint)(local_28[local_48] >> 4) << 4 ^
                 (uint)(*(byte *)(lVar4 + (local_4c * 0x10 + local_48)) >> 4))] & 0xf0 ^
           (byte)LAES_decrypt_xor
                 [(int)((local_28[local_48] & 0xf) << 4 ^
                       *(byte *)(lVar4 + (local_4c * 0x10 + local_48)) & 0xf)] >> 4;
    }
  }
  local_28[0] = (&LAES_decrypt_td4)[(int)(uint)local_38[0]];
  local_28[1] = (&LAES_decrypt_td4)[(int)(uint)local_38[0xd]];
  local_28[2] = (&LAES_decrypt_td4)[(int)(uint)local_38[10]];
  local_28[3] = (&LAES_decrypt_td4)[(int)(uint)local_38[7]];
  local_28[4] = (&LAES_decrypt_td4)[(int)(uint)local_38[4]];
  local_28[5] = (&LAES_decrypt_td4)[(int)(uint)local_38[1]];
  local_28[6] = (&LAES_decrypt_td4)[(int)(uint)local_38[0xe]];
  local_28[7] = (&LAES_decrypt_td4)[(int)(uint)local_38[0xb]];
  local_28[8] = (&LAES_decrypt_td4)[(int)(uint)local_38[8]];
  local_28[9] = (&LAES_decrypt_td4)[(int)(uint)local_38[5]];
  local_28[10] = (&LAES_decrypt_td4)[(int)(uint)local_38[2]];
  local_28[0xb] = (&LAES_decrypt_td4)[(int)(uint)local_38[0xf]];
  local_28[0xc] = (&LAES_decrypt_td4)[(int)(uint)local_38[0xc]];
  local_28[0xd] = (&LAES_decrypt_td4)[(int)(uint)local_38[9]];
  local_28[0xe] = (&LAES_decrypt_td4)[(int)(uint)local_38[6]];
  local_28[0xf] = (&LAES_decrypt_td4)[(int)(uint)local_38[3]];
  for (local_48 = 0; local_48 < 0x10; local_48 = local_48 + 1) {
    *(byte *)(param_2 + local_48) =
         LAES_decrypt_xor1
         [(int)((uint)(local_28[local_48] >> 4) << 4 ^
               (uint)(*(byte *)(lVar4 + (local_4c * 0x10 + local_48)) >> 4))] & 0xf0 ^
         (byte)LAES_decrypt_xor1
               [(int)((local_28[local_48] & 0xf) << 4 ^
                     *(byte *)(lVar4 + (local_4c * 0x10 + local_48)) & 0xf)] >> 4;
  }
  if (lVar3 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



char * get_pkgname(long *param_1)

{
  undefined8 uVar1;
  undefined8 uVar2;
  char *__s;
  char *pcVar3;
  code *pcVar4;
  
  uVar1 = (**(code **)(*param_1 + 0x30))(param_1,"android/app/ActivityThread");
  uVar2 = (**(code **)(*param_1 + 0x388))(param_1,uVar1,"currentPackageName","()Ljava/lang/String;")
  ;
  pcVar4 = *(code **)(*param_1 + 0x548);
  uVar1 = (**(code **)(*param_1 + 0x390))(param_1,uVar1,uVar2);
  __s = (char *)(*pcVar4)(param_1,uVar1,0);
  pcVar3 = strchr(__s,0x3a);
  if (pcVar3 != (char *)0x0) {
    *pcVar3 = '\0';
  }
  return __s;
}



void ByteToHexStr(long param_1,long param_2,int param_3)

{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  undefined8 local_8;
  
  for (local_8 = 0; local_8 < param_3; local_8 = local_8 + 1) {
    bVar3 = *(byte *)(param_1 + local_8) >> 4;
    bVar2 = *(byte *)(param_1 + local_8) & 0xf;
    bVar1 = bVar3 + 0x30;
    if (bVar1 < 0x3a) {
      *(byte *)(param_2 + local_8 * 2) = bVar1;
    }
    else {
      *(byte *)(param_2 + local_8 * 2) = bVar3 + 0x37;
    }
    bVar1 = bVar2 + 0x30;
    if (bVar1 < 0x3a) {
      *(byte *)(param_2 + local_8 * 2 + 1) = bVar1;
    }
    else {
      *(byte *)(param_2 + local_8 * 2 + 1) = bVar2 + 0x37;
    }
  }
  return;
}



undefined8 getApkSha(long *param_1,undefined8 param_2)

{
  int iVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  void *__ptr;
  code *pcVar6;
  
  uVar2 = (**(code **)(*param_1 + 0x30))(param_1,"android/app/ActivityThread");
  uVar3 = (**(code **)(*param_1 + 0x388))
                    (param_1,uVar2,"currentActivityThread","()Landroid/app/ActivityThread;");
  uVar3 = (**(code **)(*param_1 + 0x390))(param_1,uVar2,uVar3);
  uVar2 = (**(code **)(*param_1 + 0x108))
                    (param_1,uVar2,"getSystemContext","()Landroid/app/ContextImpl;");
  uVar2 = (**(code **)(*param_1 + 0x110))(param_1,uVar3,uVar2);
  uVar3 = (**(code **)(*param_1 + 0x30))(param_1,"android/app/ContextImpl");
  uVar3 = (**(code **)(*param_1 + 0x108))
                    (param_1,uVar3,"getPackageManager","()Landroid/content/pm/PackageManager;");
  uVar2 = (**(code **)(*param_1 + 0x110))(param_1,uVar2,uVar3);
  uVar3 = (**(code **)(*param_1 + 0xf8))(param_1,uVar2);
  uVar3 = (**(code **)(*param_1 + 0x108))
                    (param_1,uVar3,"getPackageInfo",
                     "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
  uVar4 = (**(code **)(*param_1 + 0x538))(param_1,param_2);
  uVar2 = (**(code **)(*param_1 + 0x110))(param_1,uVar2,uVar3,uVar4,0x40);
  uVar3 = (**(code **)(*param_1 + 0xf8))(param_1,uVar2);
  uVar3 = (**(code **)(*param_1 + 0x2f0))
                    (param_1,uVar3,"signatures","[Landroid/content/pm/Signature;");
  uVar2 = (**(code **)(*param_1 + 0x2f8))(param_1,uVar2,uVar3);
  (**(code **)(*param_1 + 0x558))(param_1,uVar2);
  uVar2 = (**(code **)(*param_1 + 0x568))(param_1,uVar2,0);
  uVar3 = (**(code **)(*param_1 + 0xf8))(param_1,uVar2);
  uVar3 = (**(code **)(*param_1 + 0x108))(param_1,uVar3,"toByteArray",&DAT_0010a0f8);
  uVar2 = (**(code **)(*param_1 + 0x110))(param_1,uVar2,uVar3);
  uVar3 = (**(code **)(*param_1 + 0x30))(param_1,"java/security/MessageDigest");
  uVar4 = (**(code **)(*param_1 + 0x388))
                    (param_1,uVar3,"getInstance","(Ljava/lang/String;)Ljava/security/MessageDigest;"
                    );
  pcVar6 = *(code **)(*param_1 + 0x390);
  uVar5 = (**(code **)(*param_1 + 0x538))(param_1,&DAT_0010a168);
  uVar4 = (*pcVar6)(param_1,uVar3,uVar4,uVar5);
  uVar5 = (**(code **)(*param_1 + 0x108))(param_1,uVar3,"update","([B)V");
  (**(code **)(*param_1 + 0x1e8))(param_1,uVar4,uVar5,uVar2);
  uVar2 = (**(code **)(*param_1 + 0x108))(param_1,uVar3,"digest",&DAT_0010a0f8);
  uVar2 = (**(code **)(*param_1 + 0x110))(param_1,uVar4,uVar2);
  iVar1 = (**(code **)(*param_1 + 0x558))(param_1,uVar2);
  uVar3 = (**(code **)(*param_1 + 0x5c0))(param_1,uVar2,0);
  __ptr = malloc((long)(iVar1 * 2 + 1));
  if (__ptr == (void *)0x0) {
    uVar2 = 0;
  }
  else {
    ByteToHexStr(uVar3,__ptr,iVar1);
    *(undefined1 *)((long)__ptr + (long)(iVar1 << 1)) = 0;
    uVar4 = (**(code **)(*param_1 + 0x538))(param_1,__ptr);
    (**(code **)(*param_1 + 0x600))(param_1,uVar2,uVar3,2);
    free(__ptr);
    uVar2 = (**(code **)(*param_1 + 0x548))(param_1,uVar4,0);
  }
  return uVar2;
}



void get_md5(undefined8 param_1)

{
  undefined8 uVar1;
  
  uVar1 = get_pkgname(param_1);
  getApkSha(param_1,uVar1);
  return;
}



char * base64_encode(byte *param_1,long param_2,long *param_3)

{
  char *pcVar1;
  byte *pbVar2;
  char *pcVar3;
  char *local_28;
  byte *local_20;
  
  pcVar3 = (char *)malloc((ulong)(param_2 << 2) / 3 + 5);
  if (pcVar3 == (char *)0x0) {
    pcVar3 = (char *)0x0;
  }
  else {
    pbVar2 = param_1 + param_2;
    local_28 = pcVar3;
    for (local_20 = param_1; pcVar1 = local_28, 2 < (long)pbVar2 - (long)local_20;
        local_20 = local_20 + 3) {
      *local_28 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/crypto_tool"
                  [(int)(uint)(*local_20 >> 2)];
      local_28[1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/crypto_tool"
                    [(int)((*local_20 & 3) << 4 | (uint)(local_20[1] >> 4))];
      pcVar1 = local_28 + 3;
      local_28[2] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/crypto_tool"
                    [(int)((local_20[1] & 0xf) << 2 | (uint)(local_20[2] >> 6))];
      local_28 = local_28 + 4;
      *pcVar1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/crypto_tool"
                [(int)(local_20[2] & 0x3f)];
    }
    if (pbVar2 != local_20) {
      *local_28 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/crypto_tool"
                  [(int)(uint)(*local_20 >> 2)];
      if ((long)pbVar2 - (long)local_20 == 1) {
        local_28[1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/crypto_tool"
                      [(int)((*local_20 & 3) << 4)];
        local_28[2] = '=';
      }
      else {
        local_28[1] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/crypto_tool"
                      [(int)((*local_20 & 3) << 4 | (uint)(local_20[1] >> 4))];
        local_28[2] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/crypto_tool"
                      [(int)((local_20[1] & 0xf) << 2)];
      }
      local_28 = local_28 + 3;
      *local_28 = '=';
      local_28 = pcVar1 + 4;
    }
    *local_28 = '\0';
    if (param_3 != (long *)0x0) {
      *param_3 = (long)local_28 - (long)pcVar3;
    }
  }
  return pcVar3;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void base64_decode(long param_1,ulong param_2,long *param_3)

{
  byte *pbVar1;
  char cVar2;
  byte *pbVar3;
  byte *local_140;
  ulong local_138;
  ulong local_130;
  char acStack_118 [8];
  char local_110 [8];
  char acStack_108 [61];
  undefined1 local_cb;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  memset(acStack_108,0x80,0x100);
  for (local_138 = 0; local_138 < 0x40; local_138 = local_138 + 1) {
    acStack_108
    [(int)(uint)(byte)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/crypto_tool"
                      [local_138]] = (char)local_138;
  }
  local_cb = 0;
  local_130 = 0;
  for (local_138 = 0; local_138 < param_2; local_138 = local_138 + 1) {
    if (acStack_108[(int)(uint)*(byte *)(param_1 + local_138)] != -0x80) {
      local_130 = local_130 + 1;
    }
  }
  if ((local_130 & 3) == 0) {
    pbVar3 = (byte *)malloc((local_130 >> 2) * 3 + 1);
    if (pbVar3 == (byte *)0x0) {
      pbVar3 = (byte *)0x0;
    }
    else {
      local_130 = 0;
      local_140 = pbVar3;
      for (local_138 = 0; local_138 < param_2; local_138 = local_138 + 1) {
        cVar2 = acStack_108[(int)(uint)*(byte *)(param_1 + local_138)];
        if (cVar2 != -0x80) {
          acStack_118[local_130] = *(char *)(param_1 + local_138);
          local_110[local_130] = cVar2;
          local_130 = local_130 + 1;
          if (local_130 == 4) {
            *local_140 = local_110[0] << 2 | (byte)local_110[1] >> 4;
            pbVar1 = local_140 + 2;
            local_140[1] = local_110[1] << 4 | (byte)local_110[2] >> 2;
            local_140 = local_140 + 3;
            *pbVar1 = local_110[2] << 6 | local_110[3];
            local_130 = 0;
          }
        }
      }
      if (pbVar3 < local_140) {
        if (acStack_118[2] == '=') {
          local_140 = local_140 + -2;
        }
        else if (acStack_118[3] == '=') {
          local_140 = local_140 + -1;
        }
      }
      *local_140 = 0;
      if (param_3 != (long *)0x0) {
        *param_3 = (long)local_140 - (long)pbVar3;
      }
    }
  }
  else {
    pbVar3 = (byte *)0x0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(pbVar3);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00106428(long param_1,int param_2,long param_3)

{
  ulong uVar1;
  int local_1c;
  char local_10;
  undefined1 local_f;
  undefined1 local_e;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_10 = '\0';
  local_f = 0;
  local_e = 0;
  for (local_1c = 0; local_1c < param_2; local_1c = local_1c + 2) {
    local_10 = *(char *)(param_1 + local_1c);
    local_f = *(undefined1 *)(param_1 + (long)local_1c + 1);
    uVar1 = strtoul(&local_10,(char **)0x0,0x10);
    *(char *)(param_3 + local_1c / 2) = (char)uVar1;
  }
  if (local_8 != ___stack_chk_guard) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
}



// WARNING: Removing unreachable block (ram,0x001066c8)

undefined4
FUN_00106520(undefined8 *param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,long param_7)

{
  uint uVar1;
  undefined4 local_24;
  undefined8 local_18;
  undefined8 local_10;
  
  local_18 = 0;
  local_10 = (void *)0x0;
  local_24 = 0;
  init((EVP_PKEY_CTX *)*param_1);
  uVar1 = (**(code **)(*(long *)*param_1 + 0x540))(*param_1,param_6);
  if ((uVar1 & 1) == 0) {
    local_18 = (**(code **)(*(long *)*param_1 + 0x548))(*param_1,param_6,0);
    if (local_18 == 0) {
      local_24 = 0xffffffff;
    }
    else {
      local_10 = malloc((long)((int)uVar1 / 2));
      if (local_10 == (void *)0x0) {
        local_24 = 0xffffffff;
      }
      else {
        FUN_00106428(local_18,uVar1,local_10);
        if (param_7 == 0) {
          if (DAT_0011b028 == 4) {
            local_24 = wbsk_LAES_ecb_encrypt
                                 (param_2,param_3,param_4,param_5,local_10,(int)uVar1 / 2,1);
          }
          else {
            local_24 = 0xffffffff;
          }
        }
      }
    }
  }
  else {
    local_24 = 0xffffffff;
  }
  if (local_18 != 0) {
    (**(code **)(*(long *)*param_1 + 0x550))(*param_1,param_6,local_18);
  }
  if (local_10 != (void *)0x0) {
    free(local_10);
  }
  return local_24;
}



// WARNING: Removing unreachable block (ram,0x001068a4)

undefined4
FUN_001066fc(undefined8 *param_1,undefined8 param_2,undefined4 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,long param_7)

{
  uint uVar1;
  undefined4 local_24;
  undefined8 local_18;
  undefined8 local_10;
  
  local_18 = 0;
  local_10 = (void *)0x0;
  local_24 = 0;
  init((EVP_PKEY_CTX *)*param_1);
  uVar1 = (**(code **)(*(long *)*param_1 + 0x540))(*param_1,param_6);
  if ((uVar1 & 1) == 0) {
    local_18 = (**(code **)(*(long *)*param_1 + 0x548))(*param_1,param_6,0);
    if (local_18 == 0) {
      local_24 = 0xffffffff;
    }
    else {
      local_10 = malloc((long)((int)uVar1 / 2));
      if (local_10 == (void *)0x0) {
        local_24 = 0xffffffff;
      }
      else {
        FUN_00106428(local_18,uVar1,local_10);
        if (param_7 == 0) {
          if (DAT_0011b028 == 4) {
            local_24 = wbsk_LAES_ecb_decrypt
                                 (param_2,param_3,param_4,param_5,local_10,(int)uVar1 / 2,1);
          }
          else {
            local_24 = 0xffffffff;
          }
        }
      }
    }
  }
  else {
    local_24 = 0xffffffff;
  }
  if (local_18 != 0) {
    (**(code **)(*(long *)*param_1 + 0x550))(*param_1,param_6,local_18);
  }
  if (local_10 != (void *)0x0) {
    free(local_10);
  }
  return local_24;
}



undefined8 FUN_001068d8(long param_1,long param_2)

{
  undefined8 uVar1;
  
  if (param_1 == 0) {
    uVar1 = 100;
  }
  else if (param_2 == 0) {
    uVar1 = 0x67;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void Java_com_wbsk_CryptoTool_laesEncryptStringWithBase64
               (long *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5)

{
  int iVar1;
  undefined8 uVar2;
  long *local_48;
  int local_3c;
  int local_38;
  int local_34;
  undefined1 auStack_30 [8];
  long local_28;
  void *local_20;
  void *local_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_28 = 0;
  local_20 = (void *)0x0;
  local_18 = (void *)0x0;
  local_38 = 0;
  DAT_0011b028 = 4;
  local_48 = param_1;
  local_38 = FUN_001068d8(param_3,param_4);
  if (local_38 == 0) {
    local_28 = (**(code **)(*local_48 + 0x548))(local_48,param_3,0);
    if (local_28 == 0) {
      local_38 = -1;
    }
    else {
      local_34 = (**(code **)(*local_48 + 0x540))(local_48,param_3);
      iVar1 = local_34 + 0xf;
      if (-1 < local_34) {
        iVar1 = local_34;
      }
      local_3c = ((iVar1 >> 4) + 1) * 0x10;
      local_20 = malloc((long)local_3c);
      if (local_20 == (void *)0x0) {
        local_38 = -1;
      }
      else {
        local_38 = FUN_00106520(&local_48,local_28,local_34,local_20,&local_3c,param_4,param_5);
        if (local_38 == 0) {
          local_18 = (void *)base64_encode(local_20,(long)local_3c,auStack_30);
        }
      }
    }
  }
  else {
    local_38 = -1;
  }
  if (local_28 != 0) {
    (**(code **)(*local_48 + 0x550))(local_48,param_3,local_28);
  }
  if (local_20 != (void *)0x0) {
    free(local_20);
  }
  local_10 = (**(code **)(*local_48 + 0x538))(local_48,local_18);
  if (local_18 != (void *)0x0) {
    free(local_18);
  }
  uVar2 = local_10;
  if (local_38 != 0) {
    __android_log_print(3,"crypto_tool","wbsk crypto tool error code : %d",local_38);
    uVar2 = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void Java_com_wbsk_CryptoTool_laesDecryptStringWithBase64
               (long *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5)

{
  int iVar1;
  undefined8 uVar2;
  long *local_48;
  int local_40;
  int local_3c;
  ulong local_38;
  long local_30;
  void *local_28;
  void *local_20;
  undefined8 local_18;
  long local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_30 = 0;
  local_28 = (void *)0x0;
  local_20 = (void *)0x0;
  local_3c = 0;
  DAT_0011b028 = 4;
  local_48 = param_1;
  local_3c = FUN_001068d8(param_3,param_4);
  if (local_3c == 0) {
    local_30 = (**(code **)(*local_48 + 0x548))(local_48,param_3,0);
    if (local_30 == 0) {
      local_3c = -1;
    }
    else {
      iVar1 = (**(code **)(*local_48 + 0x540))(local_48,param_3);
      local_10 = (long)iVar1;
      local_28 = (void *)base64_decode(local_30,local_10,&local_38);
      local_40 = (int)local_38;
      local_20 = malloc((long)local_40 + 1);
      if (local_20 == (void *)0x0) {
        local_3c = -1;
      }
      else {
        local_3c = FUN_001066fc(&local_48,local_28,local_38 & 0xffffffff,local_20,&local_40,param_4,
                                param_5);
        if (local_3c == 0) {
          *(undefined1 *)((long)local_20 + (long)local_40) = 0;
        }
      }
    }
  }
  else {
    local_3c = -1;
  }
  if (local_30 != 0) {
    (**(code **)(*local_48 + 0x550))(local_48,param_3,local_30);
  }
  if (local_28 != (void *)0x0) {
    free(local_28);
  }
  if (local_20 == (void *)0x0) {
    local_18 = (**(code **)(*local_48 + 0x538))(local_48,0);
  }
  else {
    iVar1 = checkUtf(local_20);
    if (iVar1 == 0) {
      local_18 = (**(code **)(*local_48 + 0x538))(local_48,local_20);
    }
    else {
      local_18 = (**(code **)(*local_48 + 0x538))(local_48,0);
    }
    free(local_20);
  }
  uVar2 = local_18;
  if (local_3c != 0) {
    __android_log_print(3,"crypto_tool","wbsk crypto tool error code : %d",local_3c);
    uVar2 = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void Java_com_wbsk_CryptoTool_laesEncryptByteArr
               (long *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5)

{
  int iVar1;
  undefined8 uVar2;
  long *local_38;
  int local_2c;
  int local_28;
  int local_24;
  long local_20;
  void *local_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_28 = 0;
  local_20 = 0;
  local_18 = (void *)0x0;
  DAT_0011b028 = 4;
  local_38 = param_1;
  local_28 = FUN_001068d8(param_3,param_4);
  if (local_28 == 0) {
    local_20 = (**(code **)(*local_38 + 0x5c0))(local_38,param_3,0);
    if (local_20 == 0) {
      local_28 = -1;
    }
    else {
      local_24 = (**(code **)(*local_38 + 0x558))(local_38,param_3);
      iVar1 = local_24 + 0xf;
      if (-1 < local_24) {
        iVar1 = local_24;
      }
      local_2c = ((iVar1 >> 4) + 1) * 0x10;
      local_18 = malloc((long)local_2c);
      if (local_18 == (void *)0x0) {
        local_28 = -1;
      }
      else {
        local_28 = FUN_00106520(&local_38,local_20,local_24,local_18,&local_2c,param_4,param_5);
        if (local_28 == 0) {
          local_10 = (**(code **)(*local_38 + 0x580))(local_38,local_2c);
          (**(code **)(*local_38 + 0x680))(local_38,local_10,0,local_2c,local_18);
        }
      }
    }
  }
  else {
    local_28 = -1;
  }
  if (local_20 != 0) {
    (**(code **)(*local_38 + 0x600))(local_38,param_3,local_20,2);
  }
  if (local_18 != (void *)0x0) {
    free(local_18);
  }
  uVar2 = local_10;
  if (local_28 != 0) {
    __android_log_print(3,"crypto_tool","wbsk crypto tool error code : %d",local_28);
    uVar2 = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void Java_com_wbsk_CryptoTool_laesDecryptByteArr
               (long *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5)

{
  undefined8 uVar1;
  long *local_38;
  int local_2c;
  int local_28;
  int local_24;
  long local_20;
  void *local_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_28 = 0;
  local_20 = 0;
  local_18 = (void *)0x0;
  DAT_0011b028 = 4;
  local_38 = param_1;
  local_28 = FUN_001068d8(param_3,param_4);
  if (local_28 == 0) {
    local_20 = (**(code **)(*local_38 + 0x5c0))(local_38,param_3,0);
    if (local_20 == 0) {
      local_28 = -1;
    }
    else {
      local_2c = (**(code **)(*local_38 + 0x558))(local_38,param_3);
      local_24 = local_2c;
      local_18 = malloc((long)local_2c);
      if (local_18 == (void *)0x0) {
        local_28 = -1;
      }
      else {
        local_28 = FUN_001066fc(&local_38,local_20,local_24,local_18,&local_2c,param_4,param_5);
        if (local_28 == 0) {
          local_10 = (**(code **)(*local_38 + 0x580))(local_38,local_2c);
          (**(code **)(*local_38 + 0x680))(local_38,local_10,0,local_2c,local_18);
        }
      }
    }
  }
  else {
    local_28 = -1;
  }
  if (local_20 != 0) {
    (**(code **)(*local_38 + 0x600))(local_38,param_3,local_20,2);
  }
  if (local_18 != (void *)0x0) {
    free(local_18);
  }
  uVar1 = local_10;
  if (local_28 != 0) {
    __android_log_print(3,"crypto_tool","wbsk crypto tool error code : %d",local_28);
    uVar1 = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void Java_com_wbsk_CryptoTool_commonEncryptByteArr
               (long *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5)

{
  int iVar1;
  undefined8 uVar2;
  long *local_38;
  int local_2c;
  int local_28;
  int local_24;
  long local_20;
  void *local_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_28 = 0;
  local_20 = 0;
  local_18 = (void *)0x0;
  DAT_0011b028 = 8;
  local_38 = param_1;
  local_28 = FUN_001068d8(param_3,param_4);
  if (local_28 == 0) {
    local_20 = (**(code **)(*local_38 + 0x5c0))(local_38,param_3,0);
    if (local_20 == 0) {
      local_28 = -1;
    }
    else {
      local_24 = (**(code **)(*local_38 + 0x558))(local_38,param_3);
      iVar1 = local_24 + 0xf;
      if (-1 < local_24) {
        iVar1 = local_24;
      }
      local_2c = ((iVar1 >> 4) + 1) * 0x10;
      local_18 = malloc((long)local_2c);
      if (local_18 == (void *)0x0) {
        local_28 = -1;
      }
      else {
        local_28 = FUN_00106520(&local_38,local_20,local_24,local_18,&local_2c,param_4,param_5);
        if (local_28 == 0) {
          local_10 = (**(code **)(*local_38 + 0x580))(local_38,local_2c);
          (**(code **)(*local_38 + 0x680))(local_38,local_10,0,local_2c,local_18);
        }
      }
    }
  }
  else {
    local_28 = -1;
  }
  if (local_20 != 0) {
    (**(code **)(*local_38 + 0x600))(local_38,param_3,local_20,2);
  }
  if (local_18 != (void *)0x0) {
    free(local_18);
  }
  uVar2 = local_10;
  if (local_28 != 0) {
    __android_log_print(3,"crypto_tool","wbsk crypto tool error code : %d",local_28);
    uVar2 = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar2);
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void Java_com_wbsk_CryptoTool_commonDecryptByteArr
               (long *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
               undefined8 param_5)

{
  undefined8 uVar1;
  long *local_38;
  int local_2c;
  int local_28;
  int local_24;
  long local_20;
  void *local_18;
  undefined8 local_10;
  long local_8;
  
  local_8 = ___stack_chk_guard;
  local_28 = 0;
  local_20 = 0;
  local_18 = (void *)0x0;
  DAT_0011b028 = 8;
  local_38 = param_1;
  local_28 = FUN_001068d8(param_3,param_4);
  if (local_28 == 0) {
    local_20 = (**(code **)(*local_38 + 0x5c0))(local_38,param_3,0);
    if (local_20 == 0) {
      local_28 = -1;
    }
    else {
      local_2c = (**(code **)(*local_38 + 0x558))(local_38,param_3);
      local_24 = local_2c;
      local_18 = malloc((long)local_2c);
      if (local_18 == (void *)0x0) {
        local_28 = -1;
      }
      else {
        local_28 = FUN_001066fc(&local_38,local_20,local_24,local_18,&local_2c,param_4,param_5);
        if (local_28 == 0) {
          local_10 = (**(code **)(*local_38 + 0x580))(local_38,local_2c);
          (**(code **)(*local_38 + 0x680))(local_38,local_10,0,local_2c,local_18);
        }
      }
    }
  }
  else {
    local_28 = -1;
  }
  if (local_20 != 0) {
    (**(code **)(*local_38 + 0x600))(local_38,param_3,local_20,2);
  }
  if (local_18 != (void *)0x0) {
    free(local_18);
  }
  uVar1 = local_10;
  if (local_28 != 0) {
    __android_log_print(3,"crypto_tool","Bangcle crypto tool error code : %d",local_28);
    uVar1 = 0;
  }
  if (local_8 == ___stack_chk_guard) {
    return;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail(uVar1);
}



undefined8 checkUtf(byte *param_1)

{
  byte *pbVar1;
  byte *pbVar2;
  byte *local_18;
  
  pbVar1 = param_1;
  do {
    local_18 = pbVar1;
    if (*local_18 == 0) {
      return 0;
    }
    pbVar1 = local_18 + 1;
    pbVar2 = pbVar1;
    switch(*local_18 >> 4) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
    case 6:
    case 7:
      break;
    case 8:
    case 9:
    case 10:
    case 0xb:
    case 0xf:
      return 1;
    case 0xe:
      pbVar2 = local_18 + 2;
      if ((*pbVar1 & 0xc0) != 0x80) {
        return 1;
      }
    case 0xc:
    case 0xd:
      local_18 = pbVar2;
      pbVar1 = local_18 + 1;
      if ((*local_18 & 0xc0) != 0x80) {
        return 1;
      }
      break;
    default:
      return 1;
    }
  } while( true );
}


