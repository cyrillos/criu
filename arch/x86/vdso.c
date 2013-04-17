#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>

#include <sys/types.h>

#include "compiler.h"
#include "xmalloc.h"
#include "vdso.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "vdso: "

static const char *vdso_x86_symbols[VDSO_SYMBOL_MAX] = {
	[VDSO_SYMBOL_GETTIMEOFDAY]	= "__vdso_gettimeofday",
	[VDSO_SYMBOL_GETCPU]		= "__vdso_getcpu",
	[VDSO_SYMBOL_CLOCK_GETTIME]	= "__vdso_clock_gettime",
	[VDSO_SYMBOL_TIME]		= "__vdso_time",
};

const char *arch_vdso_get_symbol_name(unsigned int index)
{
	if (index < ARRAY_SIZE(vdso_x86_symbols))
		return vdso_x86_symbols[index];

	return "Unknown";
}

unsigned int arch_vdso_get_symbol_index(char *symbol)
{
	unsigned int i;

	/*
	 * It's not a problem for small size of array, but
	 * be ready to change it for some faster algo.
	 */
	for (i = 0; symbol && i < ARRAY_SIZE(vdso_x86_symbols); i++) {
		if (!strcmp(symbol, vdso_x86_symbols[i]))
			return i;
	}

	return VDSO_SYMBOL_MAX;
}

static const char vdso_ident[] = {
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

typedef struct {
	u16	movabs;
	u64	imm64;
	u16	jmp_rax;
	u32	guards;
} __packed jmp_t;

int arch_proxify_vdso(void *base_to, void *base_from, symtable_t *to, symtable_t *from)
{
	jmp_t jmp = {
		.movabs		= 0xb848,
		.jmp_rax	= 0xe0ff,
		.guards		= 0xcccccccc,
	};
	unsigned int i;

	/*
	 * We support forward jumps only, for simplicity
	 * reason, thus the caller must provide us validated
	 * data only.
	 */
	for (i = 0; i < ARRAY_SIZE(to->sym); i++) {
		if (vdso_is_symbol_empty(&from->sym[i]))
			continue;

		pr_debug("jmp: %lx/%lx -> %lx/%lx\n",
			 (unsigned long)base_from, from->sym[i].offset,
			 (unsigned long)base_to, to->sym[i].offset);

		jmp.imm64 = (unsigned long)base_to + to->sym[i].offset;

		memcpy((void *)(base_from + from->sym[i].offset), &jmp, sizeof(jmp));
	}

	return 0;
}

/*
 * FIXME Usually vDSO memory area has predefined structure (ie section
 *       indices, thus we can optimize this routine and don't walk
 *       over all sections but probe predefined first and if fail do
 *       a complete walk over sections, this will speedup procedure
 *       significantly.
 *
 *       Also we need more strict checking for section sizes and addresses
 *       we obtain here -- there is no guarantee that data is always valid
 *       (as it's assumed now).
 */
int arch_parse_vdso(char *mem, size_t size, symtable_t *t)
{
	Elf64_Ehdr *ehdr = (void *)mem;
	Elf64_Shdr *shdr, *shdr_strtab;
	Elf64_Shdr *shdr_dynsym, *shdr_dynstr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *text;
	Elf64_Sym *sym;

	char *section_names, *dynsymbol_names;

	unsigned long base = VDSO_BAD_ADDR;
	unsigned int i, j, k;

	BUILD_BUG_ON(sizeof(vdso_ident) != sizeof(ehdr->e_ident));

	/*
	 * Make sure it's a file we support.
	 */
	if (memcmp(ehdr->e_ident, vdso_ident, sizeof(vdso_ident))) {
		pr_err("Elf header magic mismatch\n");
		goto err;
	}

	/*
	 * Figure out base virtual address.
	 */
	phdr = (void *)&mem[ehdr->e_phoff];
	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_LOAD) {
			base = phdr->p_vaddr;
			break;
		}
	}
	if (base != VDSO_BAD_ADDR) {
		pr_debug("Base address %lx\n", base);
	} else {
		pr_err("No base address found\n");
		goto err;
	}

	/*
	 * Where the section names lays.
	 */
	if (ehdr->e_shstrndx == SHN_UNDEF) {
		pr_err("Section names are not found\n");
		goto err;
	}

	shdr = (void *)&mem[ehdr->e_shoff];
	shdr_strtab = &shdr[ehdr->e_shstrndx];
	section_names = (void *)&mem[shdr_strtab->sh_offset];

	shdr_dynsym = shdr_dynstr = text = NULL;

	shdr = (void *)&mem[ehdr->e_shoff];
	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {

		pr_debug("section: %2d -> %s\n",
			 i, &section_names[shdr->sh_name]);

		if (shdr->sh_type == SHT_DYNSYM &&
		    strcmp(&section_names[shdr->sh_name],
			   ".dynsym") == 0) {
			shdr_dynsym = shdr;
		} else if (shdr->sh_type == SHT_STRTAB &&
		    strcmp(&section_names[shdr->sh_name],
			   ".dynstr") == 0) {
			shdr_dynstr = shdr;
		} else if (shdr->sh_type == SHT_PROGBITS &&
		    strcmp(&section_names[shdr->sh_name],
			   ".text") == 0) {
			text = shdr;
		}
	}

	if (!shdr_dynsym || !shdr_dynstr || !text) {
		pr_err("No required sections found\n");
		goto err;
	}

	dynsymbol_names = (void *)&mem[shdr_dynstr->sh_offset];

	/*
	 * Walk over global symbols and choose ones we need.
	 */
	j = shdr_dynsym->sh_size / sizeof(*sym);
	sym = (void *)&mem[shdr_dynsym->sh_offset];

	for (i = 0; i < j; i++, sym++) {
		if (ELF64_ST_BIND(sym->st_info) != STB_GLOBAL ||
		    ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
			continue;

		k = arch_vdso_get_symbol_index(&dynsymbol_names[sym->st_name]);
		if (k != VDSO_SYMBOL_MAX) {
			memcpy(t->sym[k].name, vdso_x86_symbols[k],
			       sizeof(t->sym[k].name));
			t->sym[k].offset = (unsigned long)sym->st_value - base;
			pr_debug("symbol: %#-16lx %2d %s\n",
				 t->sym[k].offset, sym->st_shndx, t->sym[k].name);
		}
	}

	return 0;
err:
	return -1;
}
