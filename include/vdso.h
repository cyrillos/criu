#ifndef __CR_VDSO_H__
#define __CR_VDSO_H__

#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include "asm/int.h"
#include "asm/vdso.h"
#include "compiler.h"

/*
 * This is a minimal amount of symbols
 * we should support at the moment.
 */
enum {
	VDSO_SYMBOL_GETTIMEOFDAY	= 0,
	VDSO_SYMBOL_GETCPU,
	VDSO_SYMBOL_CLOCK_GETTIME,
	VDSO_SYMBOL_TIME,

	VDSO_SYMBOL_MAX
};

#define VDSO_BAD_ADDR	(-1ul)

typedef struct symbol_s {
	char		name[32];
	unsigned long	offset;
} symbol_t;

#define SYMBOL_INIT						\
	{ .offset = VDSO_BAD_ADDR, }

struct symtable_s {
	unsigned long	vma_start;
	unsigned long	vma_end;
	symbol_t	sym[VDSO_SYMBOL_MAX];
};

#define symtable_vma_size(s)					\
	(unsigned long)((s)->vma_end - (s)->vma_start)

#define SYMTABLE_INIT						\
	{							\
		.vma_start	= VDSO_BAD_ADDR,		\
		.vma_end	= VDSO_BAD_ADDR,		\
		.sym		= {				\
			[0 ... VDSO_SYMBOL_MAX - 1] =		\
				(symbol_t) SYMBOL_INIT,		\
			},					\
	}

#define INIT_SYMTABLE(symtable)					\
	*(symtable) = (symtable_t) SYMTABLE_INIT

static inline bool vdso_is_symbol_empty(symbol_t *s)
{
	return s->offset == VDSO_BAD_ADDR && s->name[0] == '\0';
}

#endif /* __CR_VDSO_H__ */
