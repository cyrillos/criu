#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include "compiler.h"
#include "cpt-image.h"
#include "context.h"
#include "xmalloc.h"
#include "files.h"
#include "read.h"
#include "task.h"
#include "log.h"
#include "net.h"
#include "tty.h"
#include "obj.h"
#include "io.h"
#include "mm.h"
#include "ns.h"

void get_section_bounds(context_t *ctx, int type, off_t *start, off_t *end)
{
	BUG_ON(type >= CPT_SECT_MAX);

	*start	= ctx->sections[type][0];
	*end	= ctx->sections[type][1];
}

static const char *section_name(int type)
{
#define __gen_section_name(__name)			\
	[CPT_SECT_##__name] = __stringify_1(__name)

	static const char *n[] = {
		__gen_section_name(ERROR),
		__gen_section_name(VEINFO),
		__gen_section_name(FILES),
		__gen_section_name(TASKS),
		__gen_section_name(MM),
		__gen_section_name(FILES_STRUCT),
		__gen_section_name(FS),
		__gen_section_name(SIGHAND_STRUCT),
		__gen_section_name(TTY),
		__gen_section_name(SOCKET),
		__gen_section_name(NAMESPACE),
		__gen_section_name(SYSVSEM_UNDO),
		__gen_section_name(INODE),
		__gen_section_name(SYSV_SHM),
		__gen_section_name(SYSV_SEM),
		__gen_section_name(ORPHANS),
		__gen_section_name(NET_DEVICE),
		__gen_section_name(NET_IFADDR),
		__gen_section_name(NET_ROUTE),
		__gen_section_name(NET_IPTABLES),
		__gen_section_name(NET_CONNTRACK),
		__gen_section_name(NET_CONNTRACK_VE0),
		__gen_section_name(UTSNAME),
		__gen_section_name(TRAILER),
		__gen_section_name(UBC),
		__gen_section_name(SLM_SGREGS),
		__gen_section_name(SLM_REGOBJS),
		__gen_section_name(EPOLL),
		__gen_section_name(VSYSCALL),
		__gen_section_name(INOTIFY),
		__gen_section_name(SYSV_MSG),
		__gen_section_name(SNMP_STATS),
		__gen_section_name(CGROUPS),
		__gen_section_name(POSIX_TIMERS),
	};
#undef __gen_section_name

	return (type < ARRAY_SIZE(n)) ? n[type] : "Unknown";
};

char *read_name(int fd, off_t pos, off_t *next)
{
	struct cpt_object_hdr h;

	if (read_obj_cpt(fd, -1, &h, pos)) {
		pr_err("Can't read header at %li\n", (long)pos);
		return ERR_PTR(-EIO);
	}

	if (h.cpt_object == CPT_OBJ_NAME) {
		size_t len = h.cpt_next - h.cpt_hdrlen;
		char *name = xmalloc(len + 1);
		if (!name)
			return ERR_PTR(-ENOMEM);

		if (read_data(fd, name, len, false)) {
			xfree(name);
			return ERR_PTR(-EIO);
		}

		name[len] = '\0';

		if (next)
			*next = h.cpt_next;
		return name;
	}

	pr_err("Not a name object at @%li\n", (long)pos);
	return ERR_PTR(-EINVAL);
}

static int parse_sections(context_t *ctx)
{
	struct cpt_section_hdr h;
	off_t start, end;

	start = ctx->h.cpt_hdrlen;
	end = ctx->st.st_size - sizeof(ctx->t) - sizeof(h);

	pr_debug("Sections\n");
	pr_debug("------------------------------\n");
	pr_debug("\t    type           start          end"
		 "                             name full\n");
	while (start < end) {
		if (__read_ptr_at(ctx->fd, &h, start))
			return -1;

		if (h.cpt_hdrlen < sizeof(h)	||
		    h.cpt_next < h.cpt_hdrlen	||
		    start + h.cpt_next > ctx->st.st_size)
			goto err;

		if (h.cpt_section >= CPT_SECT_MAX)
			goto err;

		pr_debug("\t%8d    %12li %12li %32s %c\n",
			 h.cpt_section, (long)start,
			 (long)(start + h.cpt_next),
			 section_name(h.cpt_section),
			 (h.cpt_next != h.cpt_hdrlen) ? '+' : '-');

		ctx->sections[h.cpt_section][0] = start + h.cpt_hdrlen;
		start += h.cpt_next;
		ctx->sections[h.cpt_section][1] = start;
	}

	pr_debug("------------------------------\n\n");
	return 0;

err:
	pr_err("Invalid section header\n");
	return -1;
}

static void show_headers_cont(context_t *ctx)
{
	pr_debug("version       : %d (maj %d min %d)\n",
		 ctx->h.cpt_image_version,
		 CPT_VERSION_MAJOR(ctx->h.cpt_image_version),
		 CPT_VERSION_MINOR(ctx->h.cpt_image_version));
	pr_debug("arch          : %d\n", ctx->h.cpt_os_arch);
	pr_debug("features      : %d,%d\n",
		 ctx->h.cpt_ve_features,
		 ctx->h.cpt_ve_features2);
	pr_debug("page size     : %d\n", ctx->h.cpt_pagesize);
	pr_debug("hz            : %d\n", ctx->h.cpt_hz);
	pr_debug("cpu caps      : %d %d %d %d\n",
		 ctx->h.cpt_cpu_caps[0],
		 ctx->h.cpt_cpu_caps[1],
		 ctx->h.cpt_cpu_caps[2],
		 ctx->h.cpt_cpu_caps[3]);
	pr_debug("iptables mask : 0x%lx\n", (long)ctx->h.cpt_iptables_mask);
}

static int read_headers(context_t *ctx)
{
	pr_debug("Headers\n");
	pr_debug("------------------------------\n");

	/*
	 * Make sure the file at least has proper size.
	 */
	if (fstat(ctx->fd, &ctx->st)) {
		pr_perror("Can't obtain stat\n");
		return -1;
	}

	if (ctx->st.st_size < (sizeof(ctx->h) + sizeof(ctx->t))) {
		pr_err("The file is too small (it must be at "
		       "least %d bytes)\n",
		       (int)(sizeof(ctx->h) + sizeof(ctx->t)));
		return -1;
	}

	if (ctx->st.st_size & 7) {
		pr_err("Size granularity failed (%li)\n",
		       (unsigned long)ctx->st.st_size);
		return -1;
	}

	/*
	 * Read headers and check signatures.
	 */
	if (__read_ptr_at(ctx->fd, &ctx->h, 0) ||
	    __read_ptr_at(ctx->fd, &ctx->t,
			  ctx->st.st_size - sizeof(ctx->t))) {
		pr_err("Can't read headers\n");
		return -1;
	}

	if (ctx->h.cpt_signature[0] != CPT_SIGNATURE0 ||
	    ctx->h.cpt_signature[1] != CPT_SIGNATURE1 ||
	    ctx->h.cpt_signature[2] != CPT_SIGNATURE2 ||
	    ctx->h.cpt_signature[3] != CPT_SIGNATURE3 ||
	    ctx->t.cpt_signature[0] != CPT_SIGNATURE0 ||
	    ctx->t.cpt_signature[1] != CPT_SIGNATURE1 ||
	    ctx->t.cpt_signature[2] != CPT_SIGNATURE2 ||
	    ctx->t.cpt_signature[3] != CPT_SIGNATURE3 ||
	    ctx->t.cpt_nsect != CPT_SECT_MAX_INDEX) {
		pr_err("Invalid signature detected\n");
		return -1;
	}

	/*
	 * Check if it is a version we support.
	 */
	if (ctx->h.cpt_image_version != CPT_CURRENT_VERSION) {
		pr_err("Unsupported image version %d:%d\n",
		       CPT_VERSION_MAJOR(ctx->h.cpt_image_version),
		       CPT_VERSION_MINOR(ctx->h.cpt_image_version));
		return -1;
	}

	/*
	 * Finally architecture.
	 */
	if (ctx->h.cpt_os_arch != CPT_OS_ARCH_EMT64) {
		pr_err("Only x86-64 images are supported at moment\n");
		return -1;
	}

	show_headers_cont(ctx);
	pr_debug("------------------------------\n\n");

	return 0;
}

void read_fini(context_t *ctx)
{
	free_ns(ctx);
	free_sockets(ctx);
	free_fs(ctx);
	free_files(ctx);
	free_ttys(ctx);
	free_inodes(ctx);
	free_tasks(ctx);
	free_mm(ctx);
}

int read_dumpfile(context_t *ctx)
{
	if (read_headers(ctx))
		return -1;

	if (parse_sections(ctx))
		return -1;

	if (read_ns(ctx))
		return -1;

	if (read_sockets(ctx))
		return -1;

	if (read_fs(ctx))
		return -1;

	if (read_inodes(ctx))
		return -1;

	if (read_files(ctx))
		return -1;

	if (read_ttys(ctx))
		return -1;

	if (read_tasks(ctx))
		return -1;

	if (read_mm(ctx))
		return -1;

	return 0;
}
