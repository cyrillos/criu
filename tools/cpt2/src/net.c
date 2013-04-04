#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <netinet/tcp.h>

#include "cpt-image.h"
#include "hashtable.h"
#include "xmalloc.h"
#include "image.h"
#include "read.h"
#include "task.h"
#include "net.h"
#include "log.h"
#include "obj.h"

#include "protobuf.h"
#include "../../../protobuf/sk-unix.pb-c.h"

/*
 * Magic numbers from iproute2 source code.
 * Will need them for iptool dumb output.
 */
static const u32 ipadd_dump_magic = 0x47361222;
static const u32 ROUTE_DUMP_MAGIC = 0x45311224;

#define NET_HASH_BITS		10
static DEFINE_HASHTABLE(sock_hash, NET_HASH_BITS);
static DEFINE_HASHTABLE(sock_index_hash, NET_HASH_BITS);
static DEFINE_HASHTABLE(netdev_hash, NET_HASH_BITS);

static LIST_HEAD(netdev_list);

struct sock_struct *sk_lookup_file(u64 cpt_file)
{
	struct sock_struct *sk;

	hash_for_each_key(sock_hash, sk, hash, cpt_file) {
		if (sk->si.cpt_file == cpt_file)
			return sk;
	}

	return NULL;
}

struct sock_struct *sk_lookup_index(u32 cpt_index)
{
	struct sock_struct *sk;

	hash_for_each_key(sock_index_hash, sk, index_hash, cpt_index) {
		if (sk->si.cpt_index == cpt_index)
			return sk;
	}

	return NULL;
}

struct netdev_struct *netdev_lookup(u32 cpt_index)
{
	struct netdev_struct *dev;

	hash_for_each_key(netdev_hash, dev, hash, cpt_index) {
		if (dev->ni.cpt_index == cpt_index)
			return dev;
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

static bool can_dump_unix_sk(const struct sock_struct *sk)
{
	if (sk->si.cpt_type != SOCK_STREAM &&
	    sk->si.cpt_type != SOCK_DGRAM) {
		pr_err("Only stream/dgram sockets supported, "
			"but type %d found on socket at @%li\n",
		       (int)sk->si.cpt_type, obj_pos_of(sk));
		return false;
	}

	switch (sk->si.cpt_state) {
	case TCP_LISTEN:
	case TCP_ESTABLISHED:
	case TCP_CLOSE:
		break;
	default:
		pr_err("Unknown state %d on socket at @%li\n",
		       sk->si.cpt_state, obj_pos_of(sk));
		return 0;
	}

	return true;
}

static struct cpt_inode_image *socket_inode(struct sock_struct *sk)
{
	struct file_struct *file;

	if (sk->si.cpt_file == -1)
		return NULL;

	file = obj_lookup_to(CPT_OBJ_FILE, sk->si.cpt_file);
	if (file) {
		if (file->fi.cpt_inode == -1)
			return NULL;
		return obj_lookup_img(CPT_OBJ_INODE, file->fi.cpt_inode);
	}

	return NULL;
}

static int write_unix_socket(context_t *ctx,
			     struct file_struct *file,
			     struct sock_struct *sk)
{
	FilePermsEntry perms = FILE_PERMS_ENTRY__INIT;
	SkOptsEntry skopts = SK_OPTS_ENTRY__INIT;
	UnixSkEntry ue = UNIX_SK_ENTRY__INIT;
	FownEntry fown = FOWN_ENTRY__INIT;

	int fd = fdset_fd(ctx->fdset_glob, CR_FD_UNIXSK);

	struct cpt_inode_image *inode, *peer_inode;
	struct sock_struct *peer;
	struct netdev_struct *dev;

	int ret = -1;

	if (file->dumped)
		return 0;

	if (!can_dump_unix_sk(sk)) {
		pr_err("Can't dump socket at @%li\n", obj_pos_of(sk));
		return -1;
	}

	inode = obj_lookup_img(CPT_OBJ_INODE, file->fi.cpt_inode);
	if (!inode) {
		pr_err("No inode @%li for file at @%li\n",
		       (long)file->fi.cpt_inode, obj_pos_of(file));
		return -1;
	}

	if (sk->si.cpt_peer != -1) {
		peer = sk_lookup_index(sk->si.cpt_peer);
		if (!peer) {
			pr_err("No peer with index %d found at @%li\n",
			       (int)sk->si.cpt_peer, obj_pos_of(file));
			return -1;
		}

		peer_inode = socket_inode(peer);
		if (!peer_inode) {
			pr_err("No inode for peer %d found at @%li\n",
			       (int)sk->si.cpt_peer, obj_pos_of(file));
			return -1;
		}
	} else {
		peer = NULL;
		peer_inode = NULL;
	}

	fill_fown(&fown, file);

	ue.name.len		= (size_t)sk->si.cpt_laddrlen;
	ue.name.data		= (void *)sk->si.cpt_laddr;

	if (sk->si.cpt_laddrlen) {
		ue.file_perms	= &perms;
		perms.mode	= sk->si.cpt_i_mode;
		perms.uid	= sk->si.cpt_peer_uid;
		perms.gid	= sk->si.cpt_peer_gid;
	}

	ue.id			= obj_id_of(file);
	ue.ino			= inode->cpt_ino;
	ue.type			= sk->si.cpt_type;
	ue.state		= sk->si.cpt_state;

	ue.flags		= file->fi.cpt_flags;

	/* FIXME This is valid for TCP_LISTEN only */
	ue.backlog		= sk->si.cpt_max_ack_backlog;

	ue.peer			= peer_inode ? peer_inode->cpt_ino : 0;
	ue.fown			= &fown;
	ue.opts			= &skopts;
	ue.uflags		= 0;

	ue.shutdown		= sk->si.cpt_shutdown;
	if (sk->si.cpt_shutdown != SK_SHUTDOWN__NONE);
		ue.has_shutdown	= true;

	skopts.so_sndbuf	= sk->si.cpt_sndbuf;
	skopts.so_rcvbuf	= sk->si.cpt_rcvbuf;

	skopts.has_so_priority	= true;
	skopts.so_priority	= sk->si.cpt_priority;

	skopts.has_so_rcvlowat	= true;
	skopts.so_rcvlowat	= sk->si.cpt_rcvlowat;

	/* FIXME No so_mark in image */
	skopts.has_so_mark	= false;

	if (sk->si.cpt_sndtimeo == MAX_SCHEDULE_TIMEOUT) {
		skopts.so_snd_tmo_sec = 0;
		skopts.so_snd_tmo_usec = 0;
	} else {
		skopts.so_snd_tmo_sec = sk->si.cpt_sndtimeo / ctx->h.cpt_hz;
		skopts.so_snd_tmo_usec = ((sk->si.cpt_sndtimeo % ctx->h.cpt_hz) * 1000000) / ctx->h.cpt_hz;
	}

	if (sk->si.cpt_sndtimeo == MAX_SCHEDULE_TIMEOUT) {
		skopts.so_rcv_tmo_sec = 0;
		skopts.so_rcv_tmo_usec = 0;
	} else {
		skopts.so_rcv_tmo_sec = sk->si.cpt_rcvtimeo / ctx->h.cpt_hz;
		skopts.so_rcv_tmo_usec = ((sk->si.cpt_rcvtimeo % ctx->h.cpt_hz) * 1000000) / ctx->h.cpt_hz;
	}

	skopts.has_reuseaddr		= true;
	skopts.reuseaddr		= sk->si.cpt_reuse ? true : false;

	skopts.has_so_passcred		= true;
	skopts.so_passcred		= !!(sk->si.cpt_ssflags & (1 << SOCK_PASSCRED));

	skopts.has_so_passsec		= true;
	skopts.so_passsec		= !!(sk->si.cpt_ssflags & (1 << SOCK_PASSSEC));

	skopts.has_so_dontroute		= true;
	skopts.so_dontroute		= !!(sk->si.cpt_flags & (1 << SOCK_LOCALROUTE));

	skopts.has_so_no_check		= true;
	skopts.so_no_check		= sk->si.cpt_no_check;

	if (sk->si.cpt_bound_dev_if) {
		dev = netdev_lookup(sk->si.cpt_bound_dev_if);
		if (!dev) {
			pr_err("No net device with index %#x found\n",
				sk->si.cpt_bound_dev_if);
			return -1;
		}

		skopts.so_bound_dev = (char *)dev->ni.cpt_name;
	}

	/*
	 * FIXME No socket filters on cpt image
	 */

	ret = pb_write_one(fd, &ue, PB_UNIXSK);

	if (!ret)
		file->dumped = true;

	return ret;
}

int write_socket(context_t *ctx, struct file_struct *file)
{
	struct sock_struct *sk = sk_lookup_file(obj_of(file)->o_pos);
	int ret = -1;

	BUG_ON(!sk);

	switch (sk->si.cpt_family) {
	case PF_UNIX:
		ret = write_unix_socket(ctx, file, sk);
		break;
	default:
		pr_err("File at @%li with unsupported sock family %d\n",
		       (long)obj_of(file)->o_pos, (int)sk->si.cpt_family);
		break;
	}

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
			pr_err("Can't read socket object at @%li\n", (long)start);
			return -1;
		}

		INIT_HLIST_NODE(&sk->hash);
		INIT_HLIST_NODE(&sk->index_hash);

		hash_add(sock_hash, &sk->hash, sk->si.cpt_file);
		hash_add(sock_index_hash, &sk->index_hash, sk->si.cpt_index);

		obj_push_hash_to(sk, CPT_OBJ_SOCKET, start);
		start += sk->si.cpt_next;

		show_sock_cont(ctx, sk);
	}

	pr_debug("------------------------------\n\n");

	return 0;
}

void free_netdev(context_t *ctx)
{
	struct netdev_struct *dev, *tmp;

	list_for_each_entry_safe(dev, tmp, &netdev_list, list) {
		obj_unhash_to(dev);
		obj_free_to(dev);
	}
}

static void show_netdev_cont(context_t *ctx, struct netdev_struct *dev)
{
	pr_debug("\t@%-8li index %#8x flags %#8x mtu %#8x -> %s\n",
		 (long)obj_of(dev)->o_pos, dev->ni.cpt_index,
		 dev->ni.cpt_flags, dev->ni.cpt_mtu, dev->ni.cpt_name);
}

int read_netdev(context_t *ctx)
{
	off_t start, end;

	pr_debug("Net devices\n");
	pr_debug("------------------------------\n");

	get_section_bounds(ctx, CPT_SECT_NET_DEVICE, &start, &end);

	while (start < end) {
		struct netdev_struct *dev;

		dev = obj_alloc_to(struct netdev_struct, ni);
		if (!dev)
			return -1;

		if (read_obj_cpt(ctx->fd, CPT_OBJ_NET_DEVICE, &dev->ni, start)) {
			obj_free_to(dev);
			pr_err("Can't read netdev object at @%li\n", (long)start);
			return -1;
		}

		INIT_LIST_HEAD(&dev->list);
		INIT_HLIST_NODE(&dev->hash);
		obj_set_eos(dev->ni.cpt_name);

		hash_add(netdev_hash, &dev->hash, dev->ni.cpt_index);
		list_add_tail(&dev->list, &netdev_list);

		obj_hash_typed_to(dev, CPT_OBJ_NET_DEVICE, start);
		start += dev->ni.cpt_next;

		show_netdev_cont(ctx, dev);
	}

	pr_debug("------------------------------\n\n");

	return 0;
}
