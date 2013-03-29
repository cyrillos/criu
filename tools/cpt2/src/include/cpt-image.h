#ifndef __CPT2_CPT_IMAGE_H__
#define __CPT2_CPT_IMAGE_H__

#include <linux/types.h>

#include "compiler.h"
#include "types.h"

#define __cpt_aligned			__aligned(8)

enum _cpt_object_type {
	CPT_OBJ_TASK			= 0,
	CPT_OBJ_MM,
	CPT_OBJ_FS,
	CPT_OBJ_FILES,
	CPT_OBJ_FILE,
	CPT_OBJ_SIGHAND_STRUCT,
	CPT_OBJ_SIGNAL_STRUCT,
	CPT_OBJ_TTY,
	CPT_OBJ_SOCKET,
	CPT_OBJ_SYSVSEM_UNDO,
	CPT_OBJ_NAMESPACE,
	CPT_OBJ_SYSV_SHM,
	CPT_OBJ_INODE,
	CPT_OBJ_UBC,
	CPT_OBJ_SLM_SGREG,
	CPT_OBJ_SLM_REGOBJ,
	CPT_OBJ_SLM_MM,
	CPT_OBJ_VFSMOUNT_REF,
	CPT_OBJ_CGROUP,
	CPT_OBJ_CGROUPS,
	CPT_OBJ_POSIX_TIMER_LIST,
	CPT_OBJ_MAX,

	CPT_OBJ_VMA			= 1024,
	CPT_OBJ_FILEDESC,
	CPT_OBJ_SIGHANDLER,
	CPT_OBJ_SIGINFO,
	CPT_OBJ_LASTSIGINFO,
	CPT_OBJ_SYSV_SEM,
	CPT_OBJ_SKB,
	CPT_OBJ_FLOCK,
	CPT_OBJ_OPENREQ,
	CPT_OBJ_VFSMOUNT,
	CPT_OBJ_TRAILER,
	CPT_OBJ_SYSVSEM_UNDO_REC,
	CPT_OBJ_NET_DEVICE,
	CPT_OBJ_NET_IFADDR,
	CPT_OBJ_NET_ROUTE,
	CPT_OBJ_NET_CONNTRACK,
	CPT_OBJ_NET_CONNTRACK_EXPECT,
	CPT_OBJ_AIO_CONTEXT,
	CPT_OBJ_VEINFO,
	CPT_OBJ_EPOLL,
	CPT_OBJ_EPOLL_FILE,
	CPT_OBJ_SKFILTER,
	CPT_OBJ_SIGALTSTACK,
	CPT_OBJ_SOCK_MCADDR,
	CPT_OBJ_BIND_MNT,
	CPT_OBJ_SYSVMSG,
	CPT_OBJ_SYSVMSG_MSG,
	CPT_OBJ_MM_AUXV,

	CPT_OBJ_X86_REGS		= 4096,
	CPT_OBJ_X86_64_REGS,
	CPT_OBJ_PAGES,
	CPT_OBJ_COPYPAGES,
	CPT_OBJ_REMAPPAGES,
	CPT_OBJ_LAZYPAGES,
	CPT_OBJ_NAME,
	CPT_OBJ_BITS,
	CPT_OBJ_REF,
	CPT_OBJ_ITERPAGES,
	CPT_OBJ_ITERYOUNGPAGES,
	CPT_OBJ_VSYSCALL,
	CPT_OBJ_IA64_REGS,
	CPT_OBJ_INOTIFY,
	CPT_OBJ_INOTIFY_WATCH,
	CPT_OBJ_INOTIFY_EVENT,
	CPT_OBJ_TASK_AUX,
	CPT_OBJ_NET_TUNTAP,
	CPT_OBJ_NET_HWADDR,
	CPT_OBJ_NET_VETH,
	CPT_OBJ_NET_STATS,
	CPT_OBJ_NET_IPIP_TUNNEL,
	CPT_OBJ_TIMERFD,
	CPT_OBJ_EVENTFD,
	CPT_OBJ_NET_BR,
	CPT_OBJ_NET_BR_DEV,
	CPT_OBJ_POSIX_TIMER,

	CPT_OBJ_NET_TAP_FILTER		= 0x01000000,
};

#define CPT_VERSION_MINOR(a)		((a) & 0x000f)
#define CPT_VERSION_MAJOR(a)		((a) & 0xff00)

#define CPT_VERSION_8			0
#define CPT_VERSION_9			0x100
#define CPT_VERSION_9_1			0x101
#define CPT_VERSION_9_2			0x102
#define CPT_VERSION_16			0x200
#define CPT_VERSION_18			0x300
#define CPT_VERSION_18_1		0x301
#define CPT_VERSION_18_2		0x302
#define CPT_VERSION_18_3		0x303
#define CPT_VERSION_18_4		0x304
#define CPT_VERSION_20			0x400
#define CPT_VERSION_24			0x500
#define CPT_VERSION_26			0x600
#define CPT_VERSION_27			0x700
#define CPT_VERSION_27_3		0x703
#define CPT_VERSION_32			0x800
#define CPT_VERSION_32_1		0x801
#define CPT_VERSION_32_2		0x802
#define CPT_VERSION_32_3		0x803

#define CPT_CURRENT_VERSION		CPT_VERSION_32_3

#define CPT_OS_ARCH_I386		0
#define CPT_OS_ARCH_EMT64		1
#define CPT_OS_ARCH_IA64		2

struct cpt_major_hdr {
	__u8				cpt_signature[4];	/* Magic number */
	__u16				cpt_hdrlen;		/* Length of this header */
	__u16				cpt_image_version;	/* Format of this file */
	__u16				cpt_os_arch;		/* Architecture */
	__u16				__cpt_pad1;
	__u32				cpt_ve_features;	/* VE features */
	__u32				cpt_ve_features2;	/* VE features */
	__u16				cpt_pagesize;		/* Page size used by OS */
	__u16				cpt_hz;			/* HZ used by OS */
	__u64				cpt_start_jiffies64;	/* Jiffies */
	__u32				cpt_start_sec;		/* Seconds */
	__u32				cpt_start_nsec;		/* Nanoseconds */
	__u32				cpt_cpu_caps[4];	/* CPU capabilities */
	__u32				cpt_kernel_config[4];	/* Kernel config */
	__u64				cpt_iptables_mask;	/* Used netfilter modules */
} __cpt_aligned;

#define CPT_SIGNATURE0			0x79
#define CPT_SIGNATURE1			0x1c
#define CPT_SIGNATURE2			0x01
#define CPT_SIGNATURE3			0x63

#define CPT_CPU_X86_CMOV		0
#define CPT_CPU_X86_FXSR		1
#define CPT_CPU_X86_SSE			2
#define CPT_CPU_X86_SSE2		3
#define CPT_CPU_X86_MMX			4
#define CPT_CPU_X86_3DNOW		5
#define CPT_CPU_X86_3DNOW2		6
#define CPT_CPU_X86_SEP			7
#define CPT_CPU_X86_EMT64		8
#define CPT_CPU_X86_IA64		9
#define CPT_CPU_X86_SYSCALL		10
#define CPT_CPU_X86_SYSCALL32		11
#define CPT_CPU_X86_SEP32		12
#define CPT_CPU_X86_SSE4_1		13
#define CPT_CPU_X86_SSE4_2		14
#define CPT_CPU_X86_SSE4A		15
#define CPT_EXTERNAL_PROCESS		16
#define CPT_NAMESPACES			17
#define CPT_SCHEDULER_POLICY		18
#define CPT_PTRACED_FROM_VE0		19
#define CPT_UNSUPPORTED_FSTYPE		20
#define CPT_BIND_MOUNT			21
#define CPT_UNSUPPORTED_NETDEV		22
#define CPT_UNSUPPORTED_MISC		23
#define CPT_SLM_DMPRST			24
#define CPT_CPU_X86_XSAVE		25
#define CPT_CPU_X86_AVX			26
#define CPT_CPU_X86_AESNI		27
#define CPT_NO_IPV6			28

#define CPT_UNSUPPORTED_MASK		0xe1fd0000UL

#define CPT_KERNEL_CONFIG_PAE		0

struct cpt_section_hdr {
	__u64				cpt_next;
	__u32				cpt_section;
	__u16				cpt_hdrlen;
	__u16				cpt_align;
} __cpt_aligned;

enum {
	CPT_SECT_ERROR,
	CPT_SECT_VEINFO,
	CPT_SECT_FILES,
	CPT_SECT_TASKS,
	CPT_SECT_MM,
	CPT_SECT_FILES_STRUCT,
	CPT_SECT_FS,
	CPT_SECT_SIGHAND_STRUCT,
	CPT_SECT_TTY,
	CPT_SECT_SOCKET,
	CPT_SECT_NAMESPACE,
	CPT_SECT_SYSVSEM_UNDO,
	CPT_SECT_INODE,
	CPT_SECT_SYSV_SHM,
	CPT_SECT_SYSV_SEM,
	CPT_SECT_ORPHANS,
	CPT_SECT_NET_DEVICE,
	CPT_SECT_NET_IFADDR,
	CPT_SECT_NET_ROUTE,
	CPT_SECT_NET_IPTABLES,
	CPT_SECT_NET_CONNTRACK,
	CPT_SECT_NET_CONNTRACK_VE0,
	CPT_SECT_UTSNAME,
	CPT_SECT_TRAILER,
	CPT_SECT_UBC,
	CPT_SECT_SLM_SGREGS,
	CPT_SECT_SLM_REGOBJS,
	CPT_SECT_EPOLL,
	CPT_SECT_VSYSCALL,
	CPT_SECT_INOTIFY,
	CPT_SECT_SYSV_MSG,
	CPT_SECT_SNMP_STATS,
	CPT_SECT_CGROUPS,
	CPT_SECT_POSIX_TIMERS,
	CPT_SECT_MAX
};

/* Due to silly mistake we cannot index sections beyond this value */
#define CPT_SECT_MAX_INDEX		(CPT_SECT_SLM_REGOBJS + 1)

struct cpt_major_tail {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_lazypages;
	__u32				cpt_64bit;
	__u64				cpt_sections[CPT_SECT_MAX_INDEX];
	__u32				cpt_nsect;
	__u8				cpt_signature[4];
} __cpt_aligned;


struct cpt_object_hdr {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;
} __cpt_aligned;

struct cpt_obj_tar {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_len;
	__u32				cpt_pad;
} __cpt_aligned;

enum _cpt_content_type {
	CPT_CONTENT_VOID,
	CPT_CONTENT_ARRAY,
	CPT_CONTENT_DATA,
	CPT_CONTENT_NAME,

	CPT_CONTENT_STACK,
	CPT_CONTENT_X86_FPUSTATE_OLD,
	CPT_CONTENT_X86_FPUSTATE,
	CPT_CONTENT_MM_CONTEXT,
	CPT_CONTENT_SEMARRAY,
	CPT_CONTENT_SEMUNDO,
	CPT_CONTENT_NLMARRAY,
	CPT_CONTENT_X86_XSAVE,
	CPT_CONTENT_PRAM,
	CPT_CONTENT_MAX
};

struct cpt_obj_bits {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;
	__u32				cpt_size;
	__u32				__cpt_pad1;
} __cpt_aligned;

struct cpt_obj_ref {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;
	__u64				cpt_pos;
} __cpt_aligned;

struct cpt_timerfd_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;
	__u64				cpt_it_value;
	__u64				cpt_it_interval;
	__u64				cpt_ticks;
	__u32				cpt_expired;
	__u32				cpt_clockid;
} __cpt_aligned;

struct cpt_eventfd_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;
	__u64				cpt_count;
	__u32				cpt_flags;
} __cpt_aligned;

struct cpt_veinfo_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				shm_ctl_max;
	__u32				shm_ctl_all;
	__u32				shm_ctl_mni;
	__u32				msg_ctl_max;
	__u32				msg_ctl_mni;
	__u32				msg_ctl_mnb;
	__u32				sem_ctl_arr[4];

	__u64				start_timespec_delta;
	__u64				start_jiffies_delta;

	__u32				last_pid;
	__u32				rnd_va_space;
	__u32				vpid_max;
	__u32				__cpt_pad1;
	__u64				real_start_timespec_delta;
	__u64				reserved[6];
} __cpt_aligned;

#define CPT_CGRP_NOTIFY_ON_RELEASE	0x1
#define CPT_CGRP_SELF_DESTRUCTION	0x2

struct cpt_cgroup_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_index;
	__s32				cpt_parent;
	__u32				cpt_flags;
};

#define CPT_DENTRY_DELETED		(1 <<  0)
#define CPT_DENTRY_ROOT			(1 <<  1)
#define CPT_DENTRY_CLONING		(1 <<  2)
#define CPT_DENTRY_PROC			(1 <<  3)
#define CPT_DENTRY_EPOLL		(1 <<  4)
#define CPT_DENTRY_REPLACED		(1 <<  5)
#define CPT_DENTRY_INOTIFY		(1 <<  6)
#define CPT_DENTRY_FUTEX		(1 <<  7)
#define CPT_DENTRY_TUNTAP		(1 <<  8)
#define CPT_DENTRY_PROCPID_DEAD		(1 <<  9)
#define CPT_DENTRY_HARDLINKED		(1 << 10)
#define CPT_DENTRY_SIGNALFD		(1 << 11)
#define CPT_DENTRY_TIMERFD		(1 << 12)
#define CPT_DENTRY_EVENTFD		(1 << 13)
#define CPT_DENTRY_SILLYRENAME		(1 << 17)

#define CPT_FOWN_STRAY_PID		0

struct cpt_file_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_flags;
	__u32				cpt_mode;
	__u64				cpt_pos;
	__u32				cpt_uid;
	__u32				cpt_gid;

	__u32				cpt_i_mode;
	__u32				cpt_lflags;
	__u64				cpt_inode;
	__u64				cpt_priv;

	__u32				cpt_fown_fd;
	__u32				cpt_fown_pid;
	__u32				cpt_fown_uid;
	__u32				cpt_fown_euid;
	__u32				cpt_fown_signo;
	__u32				__cpt_pad1;
	__u64				cpt_vfsmount;
} __cpt_aligned;

struct cpt_epoll_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_file;
} __cpt_aligned;

struct cpt_epoll_file_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_file;
	__u32				cpt_fd;
	__u32				cpt_events;
	__u64				cpt_data;
	__u32				cpt_revents;
	__u32				cpt_ready;
} __cpt_aligned;

struct cpt_inotify_wd_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_wd;
	__u32				cpt_mask;
} __cpt_aligned;

struct cpt_inotify_ev_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_wd;
	__u32				cpt_mask;
	__u32				cpt_cookie;
	__u32				cpt_namelen;
} __cpt_aligned;

struct cpt_inotify_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_file;
	__u32				cpt_user;
	__u32				cpt_max_events;
	__u32				cpt_last_wd;
	__u32				__cpt_pad1;
} __cpt_aligned;

#define CPT_FD_FLAG_CLOSEEXEC		1

struct cpt_fd_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_fd;
	__u32				cpt_flags;
	__u64				cpt_file;
} __cpt_aligned;

struct cpt_files_struct_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_index;
	__u32				cpt_max_fds;
	__u32				cpt_next_fd;
	__u32				__cpt_pad1;
} __cpt_aligned;

struct cpt_fs_struct_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_umask;
	__u32				__cpt_pad1;
} __cpt_aligned;

struct cpt_inode_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_dev;
	__u64				cpt_ino;
	__u32				cpt_mode;
	__u32				cpt_nlink;
	__u32				cpt_uid;
	__u32				cpt_gid;
	__u64				cpt_rdev;
	__u64				cpt_size;
	__u64				cpt_blksize;
	__u64				cpt_atime;
	__u64				cpt_mtime;
	__u64				cpt_ctime;
	__u64				cpt_blocks;
	__u32				cpt_sb;
	__u32				__cpt_pad1;
	__u64				cpt_vfsmount;
} __cpt_aligned;

#define CPT_MNT_BIND			0x80000000
#define CPT_MNT_EXT			0x40000000
#define CPT_MNT_DELAYFS			0x20000000

struct cpt_vfsmount_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_mntflags;
	__u32				cpt_flags;
	__u64				cpt_mnt_bind;
	__u64				cpt_mnt_parent;
	__u64				cpt_mnt_shared;
	__u64				cpt_mnt_master;
} __cpt_aligned;

#define CPT_FLOCK_DELAYED		0x00010000

struct cpt_flock_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_owner;
	__u32				cpt_pid;
	__u64				cpt_start;
	__u64				cpt_end;
	__u32				cpt_flags;
	__u32				cpt_type;
	__u32				cpt_svid;
} __cpt_aligned;

struct cpt_tty_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_flags;
	__u32				cpt_link;
	__u32				cpt_index;
	__u32				cpt_drv_type;
	__u32				cpt_drv_subtype;
	__u32				cpt_drv_flags;
	__u8				cpt_packet;
	__u8				cpt_stopped;
	__u8				cpt_hw_stopped;
	__u8				cpt_flow_stopped;

	__u32				cpt_canon_data;
	__u32				cpt_canon_head;
	__u32				cpt_canon_column;
	__u32				cpt_column;
	__u8				cpt_ctrl_status;
	__u8				cpt_erasing;
	__u8				cpt_lnext;
	__u8				cpt_icanon;
	__u8				cpt_raw;
	__u8				cpt_real_raw;
	__u8				cpt_closing;
	__u8				__cpt_pad1;
	__u16				cpt_minimum_to_wake;
	__u16				__cpt_pad2;
	__u32				cpt_pgrp;
	__u32				cpt_session;
	__u32				cpt_c_line;
	__u8				cpt_name[64];
	__u16				cpt_ws_row;
	__u16				cpt_ws_col;
	__u16				cpt_ws_prow;
	__u16				cpt_ws_pcol;
	__u8				cpt_c_cc[32];
	__u32				cpt_c_iflag;
	__u32				cpt_c_oflag;
	__u32				cpt_c_cflag;
	__u32				cpt_c_lflag;
	__u32				cpt_read_flags[4096 / 32];
} __cpt_aligned;

#define CPT_SOCK_DELETED		0x1
#define CPT_SOCK_DELAYED		0x2

struct cpt_sock_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_file;
	__u32				cpt_parent;
	__u32				cpt_index;

	__u64				cpt_ssflags;
	__u16				cpt_type;
	__u16				cpt_family;
	__u8				cpt_sstate;
	__u8				cpt_passcred;
	__u8				cpt_state;
	__u8				cpt_reuse;

	__u8				cpt_zapped;
	__u8				cpt_shutdown;
	__u8				cpt_userlocks;
	__u8				cpt_no_check;
	__u8				cpt_debug;
	__u8				cpt_rcvtstamp;
	__u8				cpt_localroute;
	__u8				cpt_protocol;

	__u32				cpt_err;
	__u32				cpt_err_soft;

	__u16				cpt_max_ack_backlog;
	__u16				__cpt_pad1;
	__u32				cpt_priority;

	__u32				cpt_rcvlowat;
	__u32				cpt_bound_dev_if;

	__u64				cpt_rcvtimeo;
	__u64				cpt_sndtimeo;
	__u32				cpt_rcvbuf;
	__u32				cpt_sndbuf;
	__u64				cpt_flags;
	__u64				cpt_lingertime;
	__u32				cpt_peer_pid;
	__u32				cpt_peer_uid;

	__u32				cpt_peer_gid;
	__u32				cpt_laddrlen;
	__u32				cpt_laddr[128 / 4];
	__u32				cpt_raddrlen;
	__u32				cpt_raddr[128 / 4];
	__u32				cpt_peer;

	__u8				cpt_socketpair;
	__u8				cpt_sockflags;

	__u16				__cpt_pad4;
	__u32				__cpt_pad5;

	__u64				cpt_stamp;
	__u32				cpt_daddr;
	__u16				cpt_dport;
	__u16				cpt_sport;

	union {
		struct {
			__u32		cpt_saddr;
			__u32		cpt_rcv_saddr;
		};

		__u64			cpt_vfsmount_ref;
	};


	__u32				cpt_uc_ttl;
	__u32				cpt_tos;

	__u32				cpt_cmsg_flags;
	__u32				cpt_mc_index;

	__u32				cpt_mc_addr;
	__u8				cpt_hdrincl;
	__u8				cpt_mc_ttl;
	__u8				cpt_mc_loop;
	__u8				cpt_pmtudisc;

	__u8				cpt_recverr;
	__u8				cpt_freebind;
	__u16				cpt_idcounter;
	__u32				cpt_cork_flags;

	__u32				cpt_cork_fragsize;
	__u32				cpt_cork_length;
	__u32				cpt_cork_addr;
	__u32				cpt_cork_saddr;
	__u32				cpt_cork_daddr;
	__u32				cpt_cork_oif;

	__u32				cpt_udp_pending;
	__u32				cpt_udp_corkflag;
	__u16				cpt_udp_encap;
	__u16				cpt_udp_len;
	__u32				__cpt_pad7;

	__u64				cpt_saddr6[2];
	__u64				cpt_rcv_saddr6[2];
	__u64				cpt_daddr6[2];
	__u32				cpt_flow_label6;
	__u32				cpt_frag_size6;
	__u32				cpt_hop_limit6;
	__u32				cpt_mcast_hops6;

	__u32				cpt_mcast_oif6;
	__u8				cpt_rxopt6;
	__u8				cpt_mc_loop6;
	__u8				cpt_recverr6;
	__u8				cpt_sndflow6;

	__u8				cpt_pmtudisc6;
	__u8				cpt_ipv6only6;
	__u8				cpt_mapped;
	__u8				__cpt_pad8;
	__u32				cpt_pred_flags;

	__u32				cpt_rcv_nxt;
	__u32				cpt_snd_nxt;

	__u32				cpt_snd_una;
	__u32				cpt_snd_sml;

	__u32				cpt_rcv_tstamp;
	__u32				cpt_lsndtime;

	__u8				cpt_tcp_header_len;
	__u8				cpt_ack_pending;
	__u8				cpt_quick;
	__u8				cpt_pingpong;
	__u8				cpt_blocked;
	__u8				__cpt_pad9;
	__u16				__cpt_pad10;

	__u32				cpt_ato;
	__u32				cpt_ack_timeout;

	__u32				cpt_lrcvtime;
	__u16				cpt_last_seg_size;
	__u16				cpt_rcv_mss;

	__u32				cpt_snd_wl1;
	__u32				cpt_snd_wnd;

	__u32				cpt_max_window;
	__u32				cpt_pmtu_cookie;

	__u32				cpt_mss_cache;
	__u16				cpt_mss_cache_std;
	__u16				cpt_mss_clamp;

	__u16				cpt_ext_header_len;
	__u16				cpt_ext2_header_len;
	__u8				cpt_ca_state;
	__u8				cpt_retransmits;
	__u8				cpt_reordering;
	__u8				cpt_frto_counter;

	__u32				cpt_frto_highmark;
	__u8				cpt_adv_cong;
	__u8				cpt_defer_accept;
	__u8				cpt_backoff;
	__u8				__cpt_pad11;

	__u32				cpt_srtt;
	__u32				cpt_mdev;

	__u32				cpt_mdev_max;
	__u32				cpt_rttvar;

	__u32				cpt_rtt_seq;
	__u32				cpt_rto;

	__u32				cpt_packets_out;
	__u32				cpt_left_out;

	__u32				cpt_retrans_out;
	__u32				cpt_snd_ssthresh;

	__u32				cpt_snd_cwnd;
	__u16				cpt_snd_cwnd_cnt;
	__u16				cpt_snd_cwnd_clamp;

	__u32				cpt_snd_cwnd_used;
	__u32				cpt_snd_cwnd_stamp;

	__u32				cpt_timeout;
	__u32				cpt_ka_timeout;

	__u32				cpt_rcv_wnd;
	__u32				cpt_rcv_wup;

	__u32				cpt_write_seq;
	__u32				cpt_pushed_seq;

	__u32				cpt_copied_seq;
	__u8				cpt_tstamp_ok;
	__u8				cpt_wscale_ok;
	__u8				cpt_sack_ok;
	__u8				cpt_saw_tstamp;

	__u8				cpt_snd_wscale;
	__u8				cpt_rcv_wscale;
	__u8				cpt_nonagle;
	__u8				cpt_keepalive_probes;
	__u32				cpt_rcv_tsval;

	__u32				cpt_rcv_tsecr;
	__u32				cpt_ts_recent;

	__u64				cpt_ts_recent_stamp;
	__u16				cpt_user_mss;
	__u8				cpt_dsack;
	__u8				unused; /* was cpt_eff_sacks */
	__u32				cpt_sack_array[2 * 5];
	__u32				cpt_window_clamp;

	__u32				cpt_rcv_ssthresh;
	__u8				cpt_probes_out;
	__u8				cpt_num_sacks;
	__u16				cpt_advmss;

	__u8				cpt_syn_retries;
	__u8				cpt_ecn_flags;
	__u16				cpt_prior_ssthresh;
	__u32				cpt_lost_out;

	__u32				cpt_sacked_out;
	__u32				cpt_fackets_out;

	__u32				cpt_high_seq;
	__u32				cpt_retrans_stamp;

	__u32				cpt_undo_marker;
	__u32				cpt_undo_retrans;

	__u32				cpt_urg_seq;
	__u16				cpt_urg_data;
	__u8				cpt_pending;
	__u8				unused2; /* was cpt_urg_mode */

	__u32				cpt_snd_up;
	__u32				cpt_keepalive_time;

	__u32				cpt_keepalive_intvl;
	__u32				cpt_linger2;

	__u32				cpt_rcvrtt_rtt;
	__u32				cpt_rcvrtt_seq;

	__u32				cpt_rcvrtt_time;
	__u32				__cpt_pad12;

	__u16				cpt_i_mode;
	__u16				__cpt_pad13;
	__u32				__cpt_pad14;
} __cpt_aligned;

struct cpt_sockmc_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u16				cpt_family;
	__u16				cpt_mode;
	__u32				cpt_ifindex;
	__u32				cpt_mcaddr[4];
} __cpt_aligned;

struct cpt_openreq_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_rcv_isn;
	__u32				cpt_snt_isn;

	__u16				cpt_rmt_port;
	__u16				cpt_mss;
	__u8				cpt_family;
	__u8				cpt_retrans;
	__u8				cpt_snd_wscale;
	__u8				cpt_rcv_wscale;

	__u8				cpt_tstamp_ok;
	__u8				cpt_sack_ok;
	__u8				cpt_wscale_ok;
	__u8				cpt_ecn_ok;
	__u8				cpt_acked;
	__u8				__cpt_pad1;
	__u16				__cpt_pad2;

	__u32				cpt_window_clamp;
	__u32				cpt_rcv_wnd;
	__u32				cpt_ts_recent;
	__u32				cpt_iif;
	__u64				cpt_expires;

	__u64				cpt_loc_addr[2];
	__u64				cpt_rmt_addr[2];
} __cpt_aligned;

#define CPT_SKB_NQ			0
#define CPT_SKB_RQ			1
#define CPT_SKB_WQ			2
#define CPT_SKB_OFOQ			3

struct cpt_skb_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_owner;
	__u32				cpt_queue;

	__u64				cpt_stamp;
	__u32				cpt_len;
	__u32				cpt_hspace;
	__u32				cpt_tspace;
	__u32				cpt_h;
	__u32				cpt_nh;
	__u32				cpt_mac;

	__u64				cpt_cb[5];
	__u32				cpt_mac_len;
	__u32				cpt_csum;
	__u8				cpt_local_df;
	__u8				cpt_pkt_type;
	__u8				cpt_ip_summed;
	__u8				__cpt_pad1;
	__u32				cpt_priority;
	__u16				cpt_protocol;
	__u16				cpt_security;
	__u16				cpt_gso_segs;
	__u16				cpt_gso_size;
} __cpt_aligned;


struct cpt_sysvshm_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_key;
	__u64				cpt_uid;
	__u64				cpt_gid;
	__u64				cpt_cuid;
	__u64				cpt_cgid;
	__u64				cpt_mode;
	__u64				cpt_seq;

	__u32				cpt_id;
	__u32				cpt_mlockuser;
	__u64				cpt_segsz;
	__u64				cpt_atime;
	__u64				cpt_ctime;
	__u64				cpt_dtime;
	__u64				cpt_creator;
	__u64				cpt_last;
} __cpt_aligned;


struct cpt_sysvsem_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_key;
	__u64				cpt_uid;
	__u64				cpt_gid;
	__u64				cpt_cuid;
	__u64				cpt_cgid;
	__u64				cpt_mode;
	__u64				cpt_seq;
	__u32				cpt_id;
	__u32				__cpt_pad1;

	__u64				cpt_otime;
	__u64				cpt_ctime;
} __cpt_aligned;

struct cpt_sysvsem_undo_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_id;
	__u32				cpt_nsem;
} __cpt_aligned;

struct cpt_sysvmsg_msg_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_type;
	__u64				cpt_size;
} __cpt_aligned;


struct cpt_sysvmsg_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_key;
	__u64				cpt_uid;
	__u64				cpt_gid;
	__u64				cpt_cuid;
	__u64				cpt_cgid;
	__u64				cpt_mode;
	__u64				cpt_seq;
	__u32				cpt_id;
	__u32				__cpt_pad1;

	__u64				cpt_stime;
	__u64				cpt_rtime;
	__u64				cpt_ctime;
	__u64				cpt_last_sender;
	__u64				cpt_last_receiver;
	__u64				cpt_qbytes;
} __cpt_aligned;

struct cpt_mm_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_start_code;
	__u64				cpt_end_code;
	__u64				cpt_start_data;
	__u64				cpt_end_data;
	__u64				cpt_start_brk;
	__u64				cpt_brk;
	__u64				cpt_start_stack;
	__u64				cpt_start_arg;
	__u64				cpt_end_arg;
	__u64				cpt_start_env;
	__u64				cpt_end_env;
	__u64				cpt_def_flags;
	__u64				cpt_mmub;
	__u8				cpt_dumpable;
	__u8				cpt_vps_dumpable;
	__u8				cpt_used_hugetlb;
	__u8				__cpt_pad;
	__u32				cpt_vdso;
	__u64				cpt_mm_flags;
} __cpt_aligned;

struct cpt_page_block {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_start;
	__u64				cpt_end;
} __cpt_aligned;

struct cpt_remappage_block {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_start;
	__u64				cpt_end;
	__u64				cpt_pgoff;
} __cpt_aligned;

struct cpt_copypage_block {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_start;
	__u64				cpt_end;
	__u64				cpt_source;
} __cpt_aligned;

struct cpt_lazypage_block {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_start;
	__u64				cpt_end;
	__u64				cpt_index;
} __cpt_aligned;

struct cpt_iterpage_block {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_start;
	__u64				cpt_end;
} __cpt_aligned;

#define CPT_VMA_TYPE_0			0
#define CPT_VMA_TYPE_SHM		1
#define CPT_VMA_VDSO			2
#define CPT_VMA_VDSO_OLD		3 /* 64 bit rhel5 vdso */

struct cpt_vma_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_file;
	__u32				cpt_type;
	__u32				cpt_anonvma;
	__u64				cpt_anonvmaid;

	__u64				cpt_start;
	__u64				cpt_end;
	__u64				cpt_flags;
	__u64				cpt_pgprot;
	__u64				cpt_pgoff;
} __cpt_aligned;

struct cpt_aio_ctx_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_max_reqs;
	__u32				cpt_ring_pages;
	__u32				cpt_tail;
	__u32				cpt_nr;
	__u64				cpt_mmap_base;
} __cpt_aligned;

#define CPT_RBL_0			0
#define CPT_RBL_NANOSLEEP		1
#define CPT_RBL_COMPAT_NANOSLEEP	2
#define CPT_RBL_POLL			3
#define CPT_RBL_FUTEX_WAIT		4
#define CPT_RBL_POSIX_CPU_NSLEEP	5

struct cpt_restart_block {
	__u64				fn;
	__u64				arg0;
	__u64				arg1;
	__u64				arg2;
	__u64				arg3;
} __cpt_aligned;

struct cpt_siginfo_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_qflags;
	__u32				cpt_signo;
	__u32				cpt_errno;
	__u32				cpt_code;

	__u64				cpt_sigval;
	__u32				cpt_pid;
	__u32				cpt_uid;
	__u64				cpt_utime;
	__u64				cpt_stime;

	__u64				cpt_user;
} __cpt_aligned;

#define CPT_SEG_ZERO			0
#define CPT_SEG_TLS1			1
#define CPT_SEG_TLS2			2
#define CPT_SEG_TLS3			3
#define CPT_SEG_USER32_DS		4
#define CPT_SEG_USER32_CS		5
#define CPT_SEG_USER64_DS		6
#define CPT_SEG_USER64_CS		7
#define CPT_SEG_LDT			256

struct cpt_x86_regs {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_debugreg[8];
	__u32				cpt_fs;
	__u32				cpt_gs;

	__u32				cpt_ebx;
	__u32				cpt_ecx;
	__u32				cpt_edx;
	__u32				cpt_esi;
	__u32				cpt_edi;
	__u32				cpt_ebp;
	__u32				cpt_eax;
	__u32				cpt_xds;
	__u32				cpt_xes;
	__u32				cpt_orig_eax;
	__u32				cpt_eip;
	__u32				cpt_xcs;
	__u32				cpt_eflags;
	__u32				cpt_esp;
	__u32				cpt_xss;
	__u32				cpt_ugs;
};

struct cpt_x86_64_regs {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_debugreg[8];

	__u64				cpt_fsbase;
	__u64				cpt_gsbase;
	__u32				cpt_fsindex;
	__u32				cpt_gsindex;
	__u32				cpt_ds;
	__u32				cpt_es;

	__u64				cpt_r15;
	__u64				cpt_r14;
	__u64				cpt_r13;
	__u64				cpt_r12;
	__u64				cpt_rbp;
	__u64				cpt_rbx;
	__u64				cpt_r11;
	__u64				cpt_r10;
	__u64				cpt_r9;
	__u64				cpt_r8;
	__u64				cpt_rax;
	__u64				cpt_rcx;
	__u64				cpt_rdx;
	__u64				cpt_rsi;
	__u64				cpt_rdi;
	__u64				cpt_orig_rax;
	__u64				cpt_rip;
	__u64				cpt_cs;
	__u64				cpt_eflags;
	__u64				cpt_rsp;
	__u64				cpt_ss;
};

#define CPT_TASK_FLAGS_MASK		(PF_EXITING | PF_FORKNOEXEC | \
					 PF_SUPERPRIV | PF_DUMPCORE | PF_SIGNALED)

#define CPT_RLIM_NLIMITS		16

struct cpt_task_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_state;
	__u64				cpt_flags;
	__u64				cpt_ptrace;
	__u32				cpt_prio;
	__u32				cpt_static_prio;
	__u32				cpt_policy;
	__u32				cpt_rt_priority;

	__u64				cpt_exec_domain;
	__u64				cpt_thrflags;
	__u64				cpt_thrstatus;
	__u64				cpt_addr_limit;

	__u64				cpt_personality;

	__u64				cpt_mm;
	__u64				cpt_files;
	__u64				cpt_fs;
	__u64				cpt_signal;
	__u64				cpt_sighand;
	__u64				cpt_sigblocked;
	__u64				cpt_sigrblocked;
	__u64				cpt_sigpending;
	__u64				cpt_namespace;
	__u64				cpt_sysvsem_undo;
	__u32				cpt_pid;
	__u32				cpt_tgid;
	__u32				cpt_ppid;
	__u32				cpt_rppid;
	__u32				cpt_pgrp;
	__u32				cpt_session;
	__u32				cpt_old_pgrp;
	__u32				__cpt_pad;
	__u32				cpt_leader;
	__u8				cpt_pn_state;
	__u8				cpt_stopped_state;
	__u8				cpt_sigsuspend_state;
	__u8				cpt_64bit;
	__u64				cpt_set_tid;
	__u64				cpt_clear_tid;
	__u32				cpt_exit_code;
	__u32				cpt_exit_signal;
	__u32				cpt_pdeath_signal;
	__u32				cpt_user;
	__u32				cpt_uid;
	__u32				cpt_euid;
	__u32				cpt_suid;
	__u32				cpt_fsuid;
	__u32				cpt_gid;
	__u32				cpt_egid;
	__u32				cpt_sgid;
	__u32				cpt_fsgid;
	__u32				cpt_ngids;
	__u32				cpt_gids[32];
	__u8				cpt_prctl_uac;
	__u8				cpt_prctl_fpemu;
	__u16				__cpt_pad1;
	__u64				cpt_ecap;
	__u64				cpt_icap;
	__u64				cpt_pcap;
	__u8				cpt_comm[16];
	__u64				cpt_tls[3];
	struct cpt_restart_block	cpt_restart;
	__u64				cpt_it_real_value;
	__u64				cpt_it_real_incr;
	__u64				cpt_it_prof_value;
	__u64				cpt_it_prof_incr;
	__u64				cpt_it_virt_value;
	__u64				cpt_it_virt_incr;

	__u16				cpt_used_math;
	__u8				cpt_keepcap;
	__u8				cpt_did_exec;
	__u32				cpt_ptrace_message;

	__u64				cpt_utime;
	__u64				cpt_stime;
	__u64				cpt_starttime;
	__u64				cpt_nvcsw;
	__u64				cpt_nivcsw;
	__u64				cpt_min_flt;
	__u64				cpt_maj_flt;

	__u64				cpt_sigsuspend_blocked;
	__u64				cpt_cutime, cpt_cstime;
	__u64				cpt_cnvcsw, cpt_cnivcsw;
	__u64				cpt_cmin_flt, cpt_cmaj_flt;

	__u64				cpt_rlim_cur[CPT_RLIM_NLIMITS];
	__u64				cpt_rlim_max[CPT_RLIM_NLIMITS];

	__u64				cpt_task_ub;
	__u64				cpt_exec_ub;
	__u64				cpt_mm_ub;
	__u64				cpt_fork_sub;
	__u64				cpt_posix_timers;
} __cpt_aligned;

struct cpt_sigaltstack_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_stack;
	__u32				cpt_stacksize;
	__u32				__cpt_pad1;
} __cpt_aligned;

struct cpt_task_aux_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_robust_list;
	__u64				__cpt_future[16];
} __cpt_aligned;

#define CPT_PGRP_NORMAL			0
#define CPT_PGRP_ORPHAN			1
#define CPT_PGRP_STRAY			2

struct cpt_signal_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_leader;
	__u8				cpt_pgrp_type;
	__u8				cpt_old_pgrp_type;
	__u8				cpt_session_type;
	__u8				__cpt_pad1;
	__u64				cpt_pgrp;
	__u64				cpt_old_pgrp;
	__u64				cpt_session;
	__u64				cpt_sigpending;
	__u64				cpt_ctty;

	__u32				cpt_curr_target;
	__u32				cpt_group_exit;
	__u32				cpt_group_exit_code;
	__u32				cpt_group_exit_task;
	__u32				cpt_notify_count;
	__u32				cpt_group_stop_count;
	__u32				cpt_stop_state;
	__u32				__cpt_pad2;

	__u64				cpt_utime, cpt_stime, cpt_cutime, cpt_cstime;
	__u64				cpt_nvcsw, cpt_nivcsw, cpt_cnvcsw, cpt_cnivcsw;
	__u64				cpt_min_flt, cpt_maj_flt, cpt_cmin_flt, cpt_cmaj_flt;

	__u64				cpt_rlim_cur[CPT_RLIM_NLIMITS];
	__u64				cpt_rlim_max[CPT_RLIM_NLIMITS];
} __cpt_aligned;
/* Followed by list of posix timers. */

struct cpt_sighand_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;
} __cpt_aligned;

struct cpt_sighandler_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_signo;
	__u32				__cpt_pad1;
	__u64				cpt_handler;
	__u64				cpt_restorer;
	__u64				cpt_flags;
	__u64				cpt_mask;
} __cpt_aligned;

struct cpt_posix_timer_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_timer_id;
	__u32				cpt_timer_clock;
	__u32				cpt_timer_overrun;
	__u32				cpt_timer_overrun_last;
	__u32				cpt_timer_signal_pending;
	__u64				cpt_timer_interval;
	__u64				cpt_timer_value;

	__u64				cpt_sigev_value;
	__u32				cpt_sigev_signo;
	__u32				cpt_sigev_notify;
} __cpt_aligned;

struct cpt_netdev_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_index;
	__u32				cpt_flags;
	__u8				cpt_name[16];
	__u32				cpt_mtu;
	__u32				cpt_pad;
} __cpt_aligned;

struct cpt_tuntap_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_owner;
	__u32				unused; /* was cpt_attached */
	__u64				cpt_flags;
	__u64				cpt_bindfile;
	__u64				cpt_if_flags;
	__u8				cpt_dev_addr[6];
	__u16				cpt_pad;
	__u32				cpt_chr_filter[2];
	__u32				cpt_net_filter[2];
} __cpt_aligned;

struct cpt_tap_filter_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_count;
	__u32				cpt_mask[2];
	__u8				cpt_addr[8][6];
} __cpt_aligned;

struct cpt_veth_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_allow_mac_change;
	__u32				__cpt_pad;
} __cpt_aligned;

#define CPT_TUNNEL_FBDEV		0x1
#define CPT_TUNNEL_SIT			0x2
#define CPT_TUNNEL_GRE			0x4

struct cpt_tunnel_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_tnl_flags;
	__u16				cpt_i_flags;
	__u16				cpt_o_flags;
	__u32				cpt_i_key;
	__u32				cpt_o_key;
	__u32				cpt_iphdr[5];
	__u32				cpt_i_seqno;
	__u32				cpt_o_seqno;
} __cpt_aligned;

struct cpt_br_nested_dev {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u8				name[16];
};

struct cpt_br_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				designated_root;
	__u64				bridge_id;
	__u32				root_path_cost;
	__u32				max_age;
	__u32				hello_time;
	__u32				forward_delay;
	__u32				bridge_max_age;
	__u32				bridge_hello_time;
	__u32				bridge_forward_delay;
	__u32				ageing_time;
	__u8				root_port;
	__u8				stp_enabled;
	__u8				via_phys_dev;
	__u8				pad[5];
} __cpt_aligned;

struct cpt_hwaddr_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u8				cpt_dev_addr[32];
} __cpt_aligned;

struct cpt_netstats_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_rx_packets;
	__u64				cpt_tx_packets;
	__u64				cpt_rx_bytes;
	__u64				cpt_tx_bytes;
	__u64				cpt_rx_errors;
	__u64				cpt_tx_errors;
	__u64				cpt_rx_dropped;
	__u64				cpt_tx_dropped;
	__u64				cpt_multicast;
	__u64				cpt_collisions;
	__u64				cpt_rx_length_errors;
	__u64				cpt_rx_over_errors;
	__u64				cpt_rx_crc_errors;
	__u64				cpt_rx_frame_errors;
	__u64				cpt_rx_fifo_errors;
	__u64				cpt_rx_missed_errors;
	__u64				cpt_tx_aborted_errors;
	__u64				cpt_tx_carrier_errors;
	__u64				cpt_tx_fifo_errors;
	__u64				cpt_tx_heartbeat_errors;
	__u64				cpt_tx_window_errors;
	__u64				cpt_rx_compressed;
	__u64				cpt_tx_compressed;
	__u64				pad[4];
} __cpt_aligned;

struct cpt_ifaddr_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_index;
	__u8				cpt_family;
	__u8				cpt_masklen;
	__u8				cpt_flags;
	__u8				cpt_scope;
	__u32				cpt_address[4];
	__u32				cpt_peer[4];
	__u32				cpt_broadcast[4];
	__u8				cpt_label[16];
	__u32				cpt_valid_lft;
	__u32				cpt_prefered_lft;
} __cpt_aligned;

struct cpt_ipct_tuple {
	__u32				cpt_src;
	__u16				cpt_srcport;
	__u16				__cpt_pad1;

	__u32				cpt_dst;
	__u16				cpt_dstport;
	__u8				cpt_protonum;
	__u8				cpt_dir;
	__u16				cpt_l3num;
} __cpt_aligned;

struct cpt_ipct_tuple_compat {
	__u32				cpt_src;
	__u16				cpt_srcport;
	__u16				__cpt_pad1;

	__u32				cpt_dst;
	__u16				cpt_dstport;
	__u8				cpt_protonum;
	__u8				cpt_dir;
} __cpt_aligned;

struct cpt_nat_manip {
	__u8				cpt_direction;
	__u8				cpt_hooknum;
	__u8				cpt_maniptype;
	__u8				__cpt_pad1;

	__u32				cpt_manip_addr;
	__u16				cpt_manip_port;
	__u16				__cpt_pad2;
	__u32				__cpt_pad3;
} __cpt_aligned;

struct cpt_nat_seq {
	__u32				cpt_correction_pos;
	__u32				cpt_offset_before;
	__u32				cpt_offset_after;
	__u32				__cpt_pad1;
} __cpt_aligned;

struct cpt_ip_connexpect_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_timeout;
	__u32				cpt_sibling_conntrack;
	__u32				cpt_pad1;

	struct cpt_ipct_tuple		cpt_tuple;
	struct cpt_ipct_tuple		cpt_mask;

	__u8				cpt_dir;
	__u8				cpt_flags;
	__u8				cpt_pad2[6];

	__u32				cpt_class;
	__u32				cpt_pad3;
} __cpt_aligned;

struct cpt_ip_connexpect_image_compat {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_timeout;
	__u32				cpt_sibling_conntrack;
	__u32				cpt_seq;

	struct cpt_ipct_tuple_compat	cpt_ct_tuple;
	struct cpt_ipct_tuple_compat	cpt_tuple;
	struct cpt_ipct_tuple_compat	cpt_mask;

	__u32				cpt_help[3];
	__u16				cpt_manip_proto;
	__u8				cpt_dir;
	__u8				cpt_flags;
} __cpt_aligned;

struct cpt_ip_conntrack_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	struct cpt_ipct_tuple		cpt_tuple[2];
	__u64				cpt_status;
	__u64				cpt_timeout;
	__u32				cpt_index;
	__u8				cpt_ct_helper;
	__u8				cpt_nat_helper;
	__u16				cpt_pad1;

	__u32				cpt_proto_data[16];
	__u32				cpt_help_data[8];

	struct cpt_nat_seq		cpt_nat_seq[2];

	__u32				cpt_masq_index;
	__u32				cpt_id;
	__u32				cpt_mark;
} __cpt_aligned;

struct cpt_ip_conntrack_image_compat {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	struct cpt_ipct_tuple_compat	cpt_tuple[2];
	__u64				cpt_status;
	__u64				cpt_timeout;
	__u32				cpt_index;
	__u8				cpt_ct_helper;
	__u8				cpt_nat_helper;
	__u16				cpt_pad1;

	__u32				cpt_proto_data[12];
	__u32				cpt_help_data[6];

	__u32				cpt_initialized;
	__u32				cpt_num_manips;
	struct cpt_nat_manip		cpt_nat_manips[6];

	struct cpt_nat_seq		cpt_nat_seq[2];

	__u32				cpt_masq_index;
	__u32				cpt_id;
	__u32				cpt_mark;
} __cpt_aligned;

struct cpt_ubparm {
	__u64				barrier;
	__u64				limit;
	__u64				held;
	__u64				maxheld;
	__u64				minheld;
	__u64				failcnt;
} __cpt_aligned;

#define CPT_UB_NOSTORE		(1 << 0)

struct cpt_beancounter_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u64				cpt_parent;
	__u32				cpt_id;
	__u16				cpt_ub_resources;
	__u16				cpt_ub_flags;
	struct cpt_ubparm		cpt_parms[32 * 2];
} __cpt_aligned;

struct cpt_slm_sgreg_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_size;
	__u32				__cpt_pad1;
	__u32				cpt_id;
	__u16				cpt_resource;
	__u8				cpt_regname[32];
	__u8				__cpt_pad2[2];
} __cpt_aligned;

struct cpt_slm_obj_image {
	__u64				cpt_next;
	__u32				cpt_object;
	__u16				cpt_hdrlen;
	__u16				cpt_content;

	__u32				cpt_size;
	__u32				__cpt_pad1;
} __cpt_aligned;

#endif /* __CPT2_CPT_IMAGE_H__ */
