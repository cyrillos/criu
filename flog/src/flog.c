#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/param.h>
#include <sys/mman.h>

#include <ffi.h>

#include "common/compiler.h"

#include "flog.h"

int flog_init(flog_ctx_t *ctx)
{
	memset(ctx, 0, sizeof(*ctx));

	/* 20M should be enough for now */
	ctx->size = ctx->left = 20 << 20;
	ctx->pos = ctx->buf = malloc(ctx->size);
	if (!ctx->buf)
		return -ENOMEM;

	return 0;
}

void flog_fini(flog_ctx_t *ctx)
{
	free(ctx->buf);
	memset(ctx, 0, sizeof(*ctx));
}

int flog_decode_msg(flog_msg_t *m, int fdout)
{
	ffi_type *args[34] = {
		[0]		= &ffi_type_sint,
		[1]		= &ffi_type_pointer,
		[2 ... 33]	= &ffi_type_slong
	};
	void *values[34];
	ffi_cif cif;
	ffi_arg rc;

	size_t i, ret = 0;
	char *fmt;

	values[0] = (void *)&fdout;

	if (m->magic != FLOG_MAGIC)
		return -EINVAL;
	if (m->version != FLOG_VERSION)
		return -EINVAL;

	fmt = (void *)m + m->fmt;
	values[1] = &fmt;

	for (i = 0; i < m->nargs; i++) {
		values[i + 2] = (void *)&m->args[i];
		if (m->mask & (1u << i))
			m->args[i] = (long)((void *)m + m->args[i]);
	}

	if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, m->nargs + 2,
			 &ffi_type_sint, args) == FFI_OK) {
		ffi_call(&cif, FFI_FN(dprintf), &rc, values);
	} else
		ret = -1;

	return ret;
}

void flog_decode_all(flog_ctx_t *ctx, int fdout)
{
	flog_msg_t *m;
	char *pos;

	for (pos = ctx->buf; pos < ctx->pos; ) {
		m = (void *)pos;
		flog_decode_msg(m ,fdout);
		pos += m->size;
	}
}

int flog_encode_msg(flog_ctx_t *ctx, unsigned int nargs, unsigned int mask, const char *format, ...)
{
	flog_msg_t *m = (void *)ctx->pos;
	char *str_start, *p;
	va_list argptr;
	size_t i;

	m->nargs = nargs;
	m->mask = mask;

	str_start = (void *)m->args + sizeof(m->args[0]) * nargs;
	p = memccpy(str_start, format, 0, ctx->left - (str_start - ctx->pos));
	if (!p)
		return -ENOMEM;

	m->fmt = str_start - ctx->pos;
	str_start = p;

	va_start(argptr, format);
	for (i = 0; i < nargs; i++) {
		m->args[i] = (long)va_arg(argptr, long);
		/*
		 * If we got a string, we should either
		 * reference it when in rodata, or make
		 * a copy (FIXME implement rodata refs).
		 */
		if (mask & (1u << i)) {
			p = memccpy(str_start, (void *)m->args[i], 0, ctx->left - (str_start - ctx->pos));
			if (!p)
				return -ENOMEM;
			m->args[i] = str_start - ctx->pos;
			str_start = p;
		}
	}
	va_end(argptr);
	m->size = str_start - ctx->pos;

	/*
	 * A magic is required to know where we stop writing into a log file,
	 * if it was not properly closed.  The file is mapped into memory, so a
	 * space in the file is allocated in advance and at the end it can have
	 * some unused tail.
	 */
	m->magic = FLOG_MAGIC;
	m->version = FLOG_VERSION;

	m->size = round_up(m->size, 8);

	/* Advance position and left bytes in context memory */
	ctx->left -= m->size;
	ctx->pos += m->size;

	return 0;
}
