#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <assert.h>

#define __USE_GNU
#include <dlfcn.h>
#include <elf.h>

#include "leb128.h"

int verbose = 1;

#define VERBOSE(expr) \
    do { if (verbose) { expr; } } while (0)

#define ERR_THROW(expr) \
    do { int ret = (int)expr; if (ret < 0) { printf("ret = %d, errno = %d (%s:%d)\n", ret, errno, __FILE__, __LINE__); goto error; } } while (0)

#define SECTION_NAME_EH_FRAME_HDR     ".eh_frame_hdr"
#define SECTION_NAME_EH_FRAME         ".eh_frame"
#define SECTION_NAME_GCC_EXCEPT_TABLE ".gcc_except_table"

/* GNU exception header encoding.  See the Generic
   Elf Specification of the Linux Standard Base (LSB).
   http://refspecs.freestandards.org/LSB_3.0.0/LSB-Core-generic/LSB-Core-generic/dwarfext.html
   The upper 4 bits indicate how the value is to be applied.
   The lower 4 bits indicate the format of the data.
   These identifiers are not defined by any DWARFn standard.
*/
#define DW_EH_PE_absptr   0x00  /* GNU */
#define DW_EH_PE_uleb128  0x01  /* GNU */
#define DW_EH_PE_udata2   0x02  /* GNU */
#define DW_EH_PE_udata4   0x03  /* GNU */
#define DW_EH_PE_udata8   0x04  /* GNU */
#define DW_EH_PE_sleb128  0x09  /* GNU */
#define DW_EH_PE_sdata2   0x0A  /* GNU */
#define DW_EH_PE_sdata4   0x0B  /* GNU */
#define DW_EH_PE_sdata8   0x0C  /* GNU */

#define DW_EH_PE_pcrel    0x10  /* GNU */
#define DW_EH_PE_textrel  0x20  /* GNU */
#define DW_EH_PE_datarel  0x30  /* GNU */
#define DW_EH_PE_funcrel  0x40  /* GNU */
#define DW_EH_PE_aligned  0x50  /* GNU */

#define DW_EH_PE_omit     0xff  /* GNU.  Means no value present. */

const char *get_enc_string(int enc)
{
    if (enc == DW_EH_PE_udata4) return "DW_EH_PE_udata";
    else if (enc == (DW_EH_PE_pcrel | DW_EH_PE_sdata4)) return "DW_EH_PE_pcrel | DW_EH_PE_sdata4";
    else if (enc == (DW_EH_PE_datarel | DW_EH_PE_sdata4)) return "DW_EH_PE_datarel | DW_EH_PE_sdata4";

    return "Unknown";
}

struct eh_frame_hdr_fde_entry
{
    int32_t initial_loc;
    int32_t fde_ptr;
};

struct eh_frame_hdr
{
    uint8_t  version;
    uint8_t  eh_frame_ptr_enc;
    uint8_t  fde_count_enc;
    uint8_t  table_enc;
    int32_t  eh_frame_ptr;
    uint32_t fde_count;
    struct   eh_frame_hdr_fde_entry *fde_entries;
};

#define CIE_AUG_LENGTH      (0x1)
#define CIE_AUG_PERSONALITY (0x2)
#define CIE_AUG_FDE_ENC     (0x4)
#define CIE_AUG_LSDA_ENC    (0x8)

struct cie
{
    uint64_t addr;

    uint64_t length;
    uint8_t  version;
    uint8_t  augmentation;
    uint64_t code_alignment_factor;
    int64_t  data_alignment_factor;
    uint8_t  return_address_register;

    // augmentation
    uint8_t  personality_enc;
    uint64_t personality_routine;
    uint8_t  fde_enc;
    uint8_t  lsda_enc;
};

struct fde
{
    uint64_t   addr;

    uint64_t   length;
    struct cie cie;
    int32_t    initial_loc;
    uint64_t   func_start_addr;
    uint32_t   range_length;

    // augmentation
    int32_t    lsda_ptr;
};

struct elf
{
    int fd;

    // elf file format
    Elf64_Ehdr eh;
    Elf64_Phdr *ph_list;
    Elf64_Shdr *sh_list;

    // specific section refered from elf
    Elf64_Shdr *sh_symbol;
    Elf64_Shdr *sh_string;
    Elf64_Shdr *sh_eh_frame_hdr;
    Elf64_Shdr *sh_eh_frame;
    Elf64_Shdr *sh_gcc_except_table;
};

int open_elf(const char *filepath, struct elf *elf)
{
    Elf64_Phdr *ph;
    Elf64_Shdr *sh;
    uint16_t i;
    char symbol_name[64];
    int ret;

    elf->fd = open(filepath, O_RDONLY);
    if (elf->fd < 0) {
        printf("Cannot open the '%s' file\n", filepath);
        exit(0);
    }

    VERBOSE(printf("%s\n", filepath));
    VERBOSE(printf("----------\n"));
    VERBOSE(printf("\n"));
    VERBOSE(printf("Sections\n"));
    VERBOSE(printf("----------\n"));

    // read ELF header
    ERR_THROW(read(elf->fd, &elf->eh, sizeof(elf->eh)));

    assert(elf->eh.e_type == ET_EXEC || elf->eh.e_type == ET_DYN);
    assert(elf->eh.e_shnum > 0);
    assert(elf->eh.e_shentsize <= sizeof(Elf64_Shdr));

    elf->ph_list = (Elf64_Phdr *)malloc(sizeof(Elf64_Phdr) * elf->eh.e_phnum);
    elf->sh_list = (Elf64_Shdr *)malloc(sizeof(Elf64_Shdr) * elf->eh.e_shnum);

    // read program header
    ERR_THROW(lseek64(elf->fd, elf->eh.e_phoff, SEEK_SET));
    ERR_THROW(read(elf->fd, elf->ph_list, sizeof(Elf64_Phdr) * elf->eh.e_phnum));

    // read section header
    ERR_THROW(lseek64(elf->fd, elf->eh.e_shoff, SEEK_SET));

    for (i = 0; i < elf->eh.e_shnum; ++i)
    {
        sh = elf->sh_list + i;

        ERR_THROW(read(elf->fd, sh, elf->eh.e_shentsize));

        if (sh->sh_type == SHT_SYMTAB)
        {
            elf->sh_symbol = sh;
        }
    }

    elf->sh_string = elf->sh_list + elf->eh.e_shstrndx;

    for (i = 0; i < elf->eh.e_shnum; ++i)
    {
        sh = elf->sh_list + i;

        ERR_THROW(lseek64(elf->fd, elf->sh_string->sh_offset + sh->sh_name, SEEK_SET));

        ERR_THROW(read(elf->fd, symbol_name, sizeof(symbol_name)));

        if (strcmp(symbol_name, SECTION_NAME_EH_FRAME_HDR    ) == 0) elf->sh_eh_frame_hdr     = sh;
        if (strcmp(symbol_name, SECTION_NAME_EH_FRAME        ) == 0) elf->sh_eh_frame         = sh;
        if (strcmp(symbol_name, SECTION_NAME_GCC_EXCEPT_TABLE) == 0) elf->sh_gcc_except_table = sh;

        VERBOSE(if (strcmp(symbol_name, SECTION_NAME_EH_FRAME_HDR) == 0 ||
                    strcmp(symbol_name, SECTION_NAME_EH_FRAME) == 0 ||
                    strcmp(symbol_name, SECTION_NAME_GCC_EXCEPT_TABLE) == 0)
                {
                    printf("[%d] sh_name = %s (0x%x), sh_addr = 0x%lx, sh_type = 0x%x\n",
                        i, symbol_name, sh->sh_name, sh->sh_addr, sh->sh_type);
                });
    }

    return 0;

error:

    if (elf->fd) { close(elf->fd); elf->fd = 0; }

    return -1;
}

uint64_t get_eh_frame_hdr_offset(struct elf *elf)
{
    return elf->sh_eh_frame_hdr->sh_offset;
}

uint64_t get_eh_frame_offset(struct elf *elf)
{
    return elf->sh_eh_frame->sh_offset;
}

uint64_t get_gcc_except_table_offset(struct elf *elf)
{
    return elf->sh_gcc_except_table->sh_offset;
}

int close_elf(struct elf *elf)
{
    ERR_THROW(close(elf->fd));
    elf->fd = 0;
    return 0;

error:

    return -1;
}

int get_fde_offset_from_pc(struct elf *elf, uint64_t pc, uint64_t *fde_offset, uint64_t *fde_addr)
{
    uint32_t i, fde_idx = (uint32_t)-1;
    struct eh_frame_hdr eh_idx;
    uint64_t eh_frame_hdr_offset = get_eh_frame_hdr_offset(elf);
    uint64_t eh_frame_offset = get_eh_frame_offset(elf);

    VERBOSE(printf("\n"));
    VERBOSE(printf(".eh_frame_hdr\n"));
    VERBOSE(printf("----------\n"));

    ERR_THROW(lseek64(elf->fd, eh_frame_hdr_offset, SEEK_SET));

    ERR_THROW(read(elf->fd, &eh_idx.version,          sizeof(uint8_t)));
    ERR_THROW(read(elf->fd, &eh_idx.eh_frame_ptr_enc, sizeof(uint8_t)));
    ERR_THROW(read(elf->fd, &eh_idx.fde_count_enc,    sizeof(uint8_t)));
    ERR_THROW(read(elf->fd, &eh_idx.table_enc,        sizeof(uint8_t)));
    ERR_THROW(read(elf->fd, &eh_idx.eh_frame_ptr,     sizeof(int32_t)));
    ERR_THROW(read(elf->fd, &eh_idx.fde_count,        sizeof(uint32_t)));

    assert(eh_idx.fde_count_enc == DW_EH_PE_udata4);

    eh_idx.fde_entries = (struct eh_frame_hdr_fde_entry *)malloc(sizeof(struct eh_frame_hdr_fde_entry) * eh_idx.fde_count);
    if (!eh_idx.fde_entries)
    {
        errno = ENOMEM;
        goto error;
    }

    ERR_THROW(read(elf->fd, eh_idx.fde_entries, sizeof(struct eh_frame_hdr_fde_entry) * eh_idx.fde_count));

    assert((eh_frame_hdr_offset + 4 + eh_idx.eh_frame_ptr) == eh_frame_offset);
    VERBOSE(printf("table_enc = 0x%x (%s)\n", eh_idx.table_enc, get_enc_string(eh_idx.table_enc)));
    VERBOSE(printf("fde_count = %d\n", eh_idx.fde_count));

    assert(eh_idx.table_enc == (DW_EH_PE_datarel | DW_EH_PE_sdata4));

    for (i = 0; i < eh_idx.fde_count; ++i)
    {
        uint64_t func_start_addr = elf->sh_eh_frame_hdr->sh_addr + eh_idx.fde_entries[i].initial_loc;
        uint64_t fde_addr        = elf->sh_eh_frame_hdr->sh_addr + eh_idx.fde_entries[i].fde_ptr;

        VERBOSE(printf("[%d] initial_loc = %d (0x%lx), fde_ptr = %d (0x%lx)\n",
                    i, eh_idx.fde_entries[i].initial_loc, func_start_addr, eh_idx.fde_entries[i].fde_ptr, fde_addr));

        if (fde_idx == (uint32_t)-1 && func_start_addr > pc)
        {
            fde_idx = i - 1;
        }
    }

    VERBOSE(printf("fde_idx = %d\n", fde_idx));

    *fde_offset = eh_frame_offset + eh_idx.fde_entries[fde_idx].fde_ptr - (eh_idx.eh_frame_ptr + 4);
    *fde_addr = elf->sh_eh_frame_hdr->sh_addr + eh_idx.fde_entries[fde_idx].fde_ptr;

    return 0;

error:

    return -1;
}

int get_lsda_offset_from_fde(struct elf* elf, uint64_t fde_offset, uint64_t fde_addr, struct fde *fde, uint64_t *lsda_offset)
{
    int i;
    uint32_t length = 0;
    uint32_t cie_ptr;
    char *fde_data = NULL, *fde_data_ptr;
    char *cie_data = NULL, *cie_data_ptr;
    unsigned n;
    uint64_t aug_data_length;

    VERBOSE(printf("\n"));
    VERBOSE(printf(".eh_frame\n"));
    VERBOSE(printf("----------\n"));

    fde->addr = fde_addr;

    ERR_THROW(lseek64(elf->fd, fde_offset, SEEK_SET));

    ERR_THROW(read(elf->fd, &length, sizeof(uint32_t)));
    assert(length != 0xffffffff);
    fde->length = length;

    fde_data = (char *)malloc(length);
    if (!fde_data)
    {
        errno = ENOMEM;
        goto error;
    }

    fde_data_ptr = fde_data;
    ERR_THROW(read(elf->fd, fde_data, length));

    memcpy(&cie_ptr, fde_data_ptr, sizeof(uint32_t));
    fde_data_ptr += sizeof(uint32_t);

    fde->cie.addr = fde_addr + sizeof(uint32_t) - cie_ptr;

    // read CIE
    {
        VERBOSE(printf("[CIE] 0x%lx\n", fde->cie.addr));

        ERR_THROW(lseek64(elf->fd, fde_offset + sizeof(uint32_t) - cie_ptr, SEEK_SET)); // sizeof(uint32_t) : length field

        ERR_THROW(read(elf->fd, &length, sizeof(uint32_t)));
        assert(length != 0xffffffff);
        fde->cie.length = length;

        cie_data = (char *)malloc(length);
        if (!cie_data)
        {
            errno = ENOMEM;
            goto error;
        }

        cie_data_ptr = cie_data;
        ERR_THROW(read(elf->fd, cie_data, length));

        cie_data_ptr += sizeof(uint32_t); // just skip CIE_id

        memcpy(&fde->cie.version, cie_data_ptr, sizeof(uint8_t));
        cie_data_ptr += sizeof(uint8_t);

        VERBOSE(printf("  version = %d\n", fde->cie.version));

        assert(fde->cie.version == 1);

        // zPLR
        fde->cie.augmentation = 0;
        while (1)
        {
            switch (*cie_data_ptr)
            {
                case 'z': fde->cie.augmentation |= CIE_AUG_LENGTH;      break;
                case 'P': fde->cie.augmentation |= CIE_AUG_PERSONALITY; break;
                case 'R': fde->cie.augmentation |= CIE_AUG_FDE_ENC;     break;
                case 'L': fde->cie.augmentation |= CIE_AUG_LSDA_ENC;    break;
            }

            if (*cie_data_ptr == 0)
            {
                cie_data_ptr++;
                break;
            }

            cie_data_ptr++;
        }

        fde->cie.code_alignment_factor = decodeULEB128(cie_data_ptr, &n, NULL, NULL);
        cie_data_ptr += n;

        fde->cie.data_alignment_factor = decodeSLEB128(cie_data_ptr, &n, NULL, NULL);
        cie_data_ptr += n;

        VERBOSE(printf("  code alignment factor = %lu\n", fde->cie.code_alignment_factor));
        VERBOSE(printf("  data alignment factor = %ld\n", fde->cie.data_alignment_factor));

        memcpy(&fde->cie.return_address_register, cie_data_ptr, sizeof(uint8_t));
        cie_data_ptr += sizeof(uint8_t);

        VERBOSE(printf("  return address register = %u\n", fde->cie.return_address_register));

        fde->cie.personality_enc = DW_EH_PE_omit;
        fde->cie.personality_routine = 0;
        fde->cie.fde_enc = DW_EH_PE_omit;
        fde->cie.lsda_enc = DW_EH_PE_omit;

        if (fde->cie.augmentation & CIE_AUG_LENGTH)
        {
            aug_data_length = decodeULEB128(cie_data_ptr, &n, NULL, NULL);
            cie_data_ptr += n;

            if (fde->cie.augmentation & CIE_AUG_PERSONALITY)
            {
                memcpy(&fde->cie.personality_enc, cie_data_ptr, sizeof(uint8_t));
                cie_data_ptr += sizeof(uint8_t);

                memcpy(&fde->cie.personality_routine, cie_data_ptr, sizeof(uint32_t));
                cie_data_ptr += sizeof(uint32_t);

                VERBOSE(printf("  personality encoding = 0x%x (%s)\n", fde->cie.personality_enc, get_enc_string(fde->cie.personality_enc)));
                VERBOSE(printf("  personality routine = 0x%lx\n", fde->cie.personality_routine));
            }

            if (fde->cie.augmentation & CIE_AUG_FDE_ENC)
            {
                memcpy(&fde->cie.fde_enc, cie_data_ptr, sizeof(uint8_t));
                cie_data_ptr += sizeof(uint8_t);

                VERBOSE(printf("  fde encoding = 0x%x (%s)\n", fde->cie.fde_enc, get_enc_string(fde->cie.fde_enc)));
            }

            if (fde->cie.augmentation & CIE_AUG_LSDA_ENC)
            {
                memcpy(&fde->cie.lsda_enc, cie_data_ptr, sizeof(uint8_t));
                cie_data_ptr += sizeof(uint8_t);

                VERBOSE(printf("  LSDA encoding = 0x%x (%s)\n", fde->cie.lsda_enc, get_enc_string(fde->cie.lsda_enc)));
            }
            else
            {
                printf("\n");
                printf("No LSDA\n");

                errno = ESRCH;
                goto error;
            }
        }

        free(cie_data);
    }

    VERBOSE(printf("\n"));
    VERBOSE(printf("[FDE] 0x%lx\n", fde->addr));

    assert((fde->cie.fde_enc == DW_EH_PE_udata4) || (fde->cie.fde_enc == (DW_EH_PE_pcrel | DW_EH_PE_sdata4)));

    memcpy(&fde->initial_loc, fde_data_ptr, sizeof(uint32_t));
    fde_data_ptr += sizeof(uint32_t);

    memcpy(&fde->range_length, fde_data_ptr, sizeof(uint32_t));
    fde_data_ptr += sizeof(uint32_t);

    fde->func_start_addr = fde_addr + fde->initial_loc + sizeof(uint32_t) * 2; // sizeof(uint32_t) * 2 = length and cie_ptr field

    VERBOSE(printf("  initial loc = %d (0x%lx)\n", fde->initial_loc, fde->func_start_addr));
    VERBOSE(printf("  range length = %u\n", fde->range_length));

    if (fde->cie.augmentation & CIE_AUG_LENGTH)
    {
        length = decodeULEB128(fde_data_ptr, &n, NULL, NULL);
        fde_data_ptr += n;

        memcpy(&fde->lsda_ptr, fde_data_ptr, sizeof(int32_t));
        fde_data_ptr += sizeof(int32_t);

        uint64_t gcc_except_table_addr = elf->sh_gcc_except_table->sh_addr;  // virtual address of .gcc_except_table section
        uint64_t gcc_except_table_offset = get_gcc_except_table_offset(elf); // file offset of .gcc_excep_table section

        switch (fde->cie.fde_enc)
        {
            case DW_EH_PE_udata4:
                *lsda_offset = fde->lsda_ptr - gcc_except_table_addr;
                *lsda_offset += gcc_except_table_offset;
                break;

            case (DW_EH_PE_pcrel | DW_EH_PE_sdata4):
                *lsda_offset = fde->lsda_ptr + fde_offset + (fde_data_ptr - fde_data);
                break;

            default:
                assert(0);
                break;
        }

        VERBOSE(printf("  LSDA ptr = %d (0x%x)\n", fde->lsda_ptr, fde->lsda_ptr));
        VERBOSE(printf("  LSDA offset of object file = %ld (0x%lx)\n", *lsda_offset, *lsda_offset));
    }

    free(fde_data);

    return 0;

error:

    if (cie_data) { free(cie_data); }
    if (fde_data) { free(fde_data); }

    return -1;
}

int get_landing_pad(struct elf *elf, uint64_t pc, struct fde *fde, uint64_t lsda_offset, uint64_t *landing_pad)
{
    uint8_t  lpstart_enc;
    uint8_t  ttype_enc;
    uint8_t  call_site_enc;
    uint64_t call_site_tbl_len;
    char header[27], *header_ptr = header;
    char *call_site_tbl, *call_site_tbl_ptr;
    unsigned n;

    VERBOSE(printf("\n"));
    VERBOSE(printf(".gcc_except_table\n"));
    VERBOSE(printf("----------\n"));

    assert(fde->cie.lsda_enc == (DW_EH_PE_pcrel | DW_EH_PE_sdata4));

    ERR_THROW(lseek64(elf->fd, lsda_offset, SEEK_SET));

    ERR_THROW(read(elf->fd, header, 27));

    memcpy(&lpstart_enc, header_ptr, sizeof(uint8_t));
    header_ptr += sizeof(uint8_t);

    assert(lpstart_enc == DW_EH_PE_omit);

    memcpy(&ttype_enc, header_ptr, sizeof(uint8_t));
    header_ptr += sizeof(uint8_t);

    assert(ttype_enc == DW_EH_PE_omit);

    memcpy(&call_site_enc, header_ptr, sizeof(uint8_t));
    header_ptr += sizeof(uint8_t);

    call_site_tbl_len = decodeULEB128(header_ptr, &n, NULL, NULL);
    header_ptr += n;

    assert(call_site_enc == DW_EH_PE_uleb128);

    call_site_tbl = (char *)malloc(call_site_tbl_len);
    if (!call_site_tbl)
    {
        errno = ENOMEM;
        goto error;
    }
    
    call_site_tbl_ptr = call_site_tbl;

    ERR_THROW(lseek64(elf->fd, (header_ptr - header) - 27, SEEK_CUR));
    ERR_THROW(read(elf->fd, call_site_tbl, call_site_tbl_len));

    VERBOSE(printf("[call site table]\n"));

    while (call_site_tbl_ptr < (call_site_tbl + call_site_tbl_len))
    {
        uint64_t cs_start  = decodeULEB128(call_site_tbl_ptr, &n, NULL, NULL); call_site_tbl_ptr += n;
        uint64_t cs_len    = decodeULEB128(call_site_tbl_ptr, &n, NULL, NULL); call_site_tbl_ptr += n;
        uint64_t cs_lp     = decodeULEB128(call_site_tbl_ptr, &n, NULL, NULL); call_site_tbl_ptr += n;
        uint64_t cs_action = decodeULEB128(call_site_tbl_ptr, &n, NULL, NULL); call_site_tbl_ptr += n;
        uint64_t cs_end    = cs_start + cs_len;

        if ((cs_start + fde->func_start_addr) <= pc && pc < (cs_end + fde->func_start_addr))
        {
            *landing_pad = cs_lp;
        }

        VERBOSE(printf("  [%lu, %lu) -> %lu : action = %lu\n", cs_start, cs_end, cs_lp, cs_action));
    }

    return 0;

error:

    return -1;
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        printf("Usage: gcc_except_table <object file> addr \n");
        exit(0);
    }

    const char *filepath = argv[1];
    uint64_t pc = strtoll(argv[2], NULL, (argv[2][0] == '0' && argv[2][1] == 'x') ? 16 : 10);

    struct elf elf;
    struct fde fde;
    uint64_t fde_offset, fde_addr;
    uint64_t lsda_offset;
    uint64_t landing_pad = 0, landing_pad_addr;

    elf.fd = 0;

    ERR_THROW(open_elf(filepath, &elf));

    ERR_THROW(get_fde_offset_from_pc(&elf, pc, &fde_offset, &fde_addr));
    ERR_THROW(get_lsda_offset_from_fde(&elf, fde_offset, fde_addr, &fde, &lsda_offset));

    ERR_THROW(get_landing_pad(&elf, pc, &fde, lsda_offset, &landing_pad));

    VERBOSE(printf("\n"));
    VERBOSE(printf("RESULT\n"));
    VERBOSE(printf("----------\n"));

    if (landing_pad != 0)
    {
        landing_pad_addr = fde.func_start_addr + landing_pad;

        printf("The landing pad is 0x%lx <+%lu> when C++ exception at 0x%lx is raised.\n", landing_pad_addr, landing_pad, pc);
    }
    else
    {
        printf("There is no landing pad when C++ exception at 0x%lx is raised.\n", pc);
    }

    close_elf(&elf);

    return 0;

error:

    if (elf.fd) { close_elf(&elf); }

    return -1;
}
