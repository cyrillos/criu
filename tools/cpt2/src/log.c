#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <fcntl.h>

#include "compiler.h"
#include "types.h"
#include "log.h"

static char logbuf[PAGE_SIZE];

static void __print_on_level(unsigned int loglevel, const char *format, va_list params)
{
	size_t size;

	size = vsnprintf(logbuf, PAGE_SIZE, format, params);
	write(STDOUT_FILENO, logbuf, size);
}

void print_on_level(unsigned int loglevel, const char *format, ...)
{
	va_list params;

	if (loglevel != LOG_MSG && loglevel > loglevel_get())
		return;

	va_start(params, format);
	__print_on_level(loglevel, format, params);
	va_end(params);
}
