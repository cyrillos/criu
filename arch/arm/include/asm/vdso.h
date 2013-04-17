#ifndef __CR_ASM_VDSO_H__
#define __CR_ASM_VDSO_H__

struct symtable_s;
typedef struct symtable_s symtable_t;

static inline const char *arch_vdso_get_symbol_name(unsigned int index) { return NULL; }
static inline unsigned int arch_vdso_get_symbol_index(char *symbol) { return VDSO_SYMBOL_MAX; };
static inline int arch_fill_self_vdso(symtable_t *t) { return 0; }
static inline int arch_parse_vdso(char *mem, size_t size, symtable_t *t) { return 0; }
static inline int arch_proxify_vdso(void *base_to, void *base_from, symtable_t *to, symtable_t *from) { return 0; }

#endif /* __CR_ASM_VDSO_H__ */
