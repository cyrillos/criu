#ifndef __CPT2_STRING_H__
#define __CPT2_STRING_H__

#include <sys/types.h>
#include <string.h>

size_t strlcpy(char *dest, const char *src, size_t size);
size_t strlcat(char *dest, const char *src, size_t count);

#endif /* __CPT2_STRING_H__ */
