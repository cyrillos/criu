#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

struct symtable_s;
typedef struct symtable_s symtable_t;

extern const char *arch_vdso_get_symbol_name(unsigned int index);
extern unsigned int arch_vdso_get_symbol_index(char *symbol);
extern int arch_fill_self_vdso(symtable_t *t);
extern int arch_parse_vdso(char *mem, size_t size, symtable_t *t);
extern int arch_proxify_vdso(void *base_to, void *base_from, symtable_t *to, symtable_t *from);

#endif /* __CR_ASM_VDSO_H__ */
