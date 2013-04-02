#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/major.h>

#include "cpt-image.h"
#include "hashtable.h"
#include "xmalloc.h"
#include "image.h"
#include "read.h"
#include "task.h"
#include "net.h"
#include "log.h"
#include "obj.h"

/*
 * Magic numbers from iproute2 source code.
 * Will need them for iptool dumb output.
 */
static const u32 ipadd_dump_magic = 0x47361222;
static const u32 ROUTE_DUMP_MAGIC = 0x45311224;

#define SOCK_HASH_BITS		10
static DEFINE_HASHTABLE(sock_hash, SOCK_HASH_BITS);

struct sock_struct *sk_lookup_file(u64 cpt_file)
{
	struct sock_struct *sk;

	hash_for_each_key(sock_hash, sk, hash, cpt_file) {
		if (sk->si.cpt_file == cpt_file)
			return sk;
	}

	return NULL;
}

int write_task_route(context_t *ctx, struct task_struct *t)
{
	u32 magic = ROUTE_DUMP_MAGIC;
	int ret = 0, fd = -1;

	fd = open_image(ctx, CR_FD_ROUTE, O_DUMP, t->ti.cpt_pid);
	if (fd < 0)
		return -1;

	ret = write_data(fd, &magic, sizeof(magic));
	if (ret)
		pr_err("Failed to write route magic (pid %d)\n",
		       t->ti.cpt_pid);

	close_safe(&fd);
	return ret;
}

void free_sockets(context_t *ctx)
{
	struct sock_struct *sk;

	while ((sk = obj_pop_unhash_to(CPT_OBJ_SOCKET)))
		obj_free_to(sk);
}

static void show_sock_cont(context_t *ctx, struct sock_struct *sk)
{
	pr_debug("\t@%-8li file %8li parent %8d index %8d "
		 "type %6d family %6d state %d\n",
		 (long)obj_of(sk)->o_pos, (long)sk->si.cpt_file, sk->si.cpt_parent,
		 sk->si.cpt_index, (int)sk->si.cpt_type, (int)sk->si.cpt_family,
		 (int)sk->si.cpt_state);
}

int read_sockets(context_t *ctx)
{
	off_t start, end;

	pr_debug("Sockets\n");
	pr_debug("------------------------------\n");

	get_section_bounds(ctx, CPT_SECT_SOCKET, &start, &end);

	while (start < end) {
		struct sock_struct *sk;

		sk = obj_alloc_to(struct sock_struct, si);
		if (!sk)
			return -1;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_SOCKET, &sk->si, start)) {
			obj_free_to(sk);
			pr_err("Can't read socket object at %li\n", (long)start);
			return -1;
		}

		hash_add(sock_hash, &sk->hash, sk->si.cpt_file);
		obj_push_hash_to(sk, CPT_OBJ_SOCKET, start);
		start += sk->si.cpt_next;

		show_sock_cont(ctx, sk);
	}

	pr_debug("------------------------------\n\n");

	return 0;
}
