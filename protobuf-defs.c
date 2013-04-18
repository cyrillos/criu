#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>

#include "protobuf-defs.h"

#include "protobuf.h"
#include "protobuf/inventory.pb-c.h"
#include "protobuf/regfile.pb-c.h"
#include "protobuf/eventfd.pb-c.h"
#include "protobuf/eventpoll.pb-c.h"
#include "protobuf/signalfd.pb-c.h"
#include "protobuf/fsnotify.pb-c.h"
#include "protobuf/core.pb-c.h"
#include "protobuf/mm.pb-c.h"
#include "protobuf/pipe.pb-c.h"
#include "protobuf/fifo.pb-c.h"
#include "protobuf/fdinfo.pb-c.h"
#include "protobuf/pipe-data.pb-c.h"
#include "protobuf/pstree.pb-c.h"
#include "protobuf/sa.pb-c.h"
#include "protobuf/sk-unix.pb-c.h"
#include "protobuf/sk-inet.pb-c.h"
#include "protobuf/packet-sock.pb-c.h"
#include "protobuf/sk-packet.pb-c.h"
#include "protobuf/creds.pb-c.h"
#include "protobuf/itimer.pb-c.h"
#include "protobuf/utsns.pb-c.h"
#include "protobuf/ipc-var.pb-c.h"
#include "protobuf/ipc-shm.pb-c.h"
#include "protobuf/ipc-msg.pb-c.h"
#include "protobuf/ipc-sem.pb-c.h"
#include "protobuf/fs.pb-c.h"
#include "protobuf/remap-file-path.pb-c.h"
#include "protobuf/ghost-file.pb-c.h"
#include "protobuf/mnt.pb-c.h"
#include "protobuf/netdev.pb-c.h"
#include "protobuf/tcp-stream.pb-c.h"
#include "protobuf/tty.pb-c.h"
#include "protobuf/file-lock.pb-c.h"
#include "protobuf/rlimit.pb-c.h"
#include "protobuf/pagemap.pb-c.h"
#include "protobuf/siginfo.pb-c.h"
#include "protobuf/sk-netlink.pb-c.h"
#include "protobuf/vma.pb-c.h"

struct cr_pb_message_desc cr_pb_descs[PB_MAX];

void cr_pb_init(void)
{
	CR_PB_DESC(INVENTORY,		Inventory,		inventory);
	CR_PB_DESC(FDINFO,		Fdinfo,			fdinfo);
	CR_PB_DESC(REG_FILES,		RegFile,		reg_file);
	CR_PB_DESC(EVENTFD,		EventfdFile,		eventfd_file);
	CR_PB_DESC(EVENTPOLL,		EventpollFile,		eventpoll_file);
	CR_PB_DESC(EVENTPOLL_TFD,	EventpollTfd,		eventpoll_tfd);
	CR_PB_DESC(SIGNALFD,		Signalfd,		signalfd);
	CR_PB_DESC(INOTIFY,		InotifyFile,		inotify_file);
	CR_PB_DESC(INOTIFY_WD,		InotifyWd,		inotify_wd);
	CR_PB_DESC(FANOTIFY,		FanotifyFile,		fanotify_file);
	CR_PB_DESC(FANOTIFY_MARK,	FanotifyMark,		fanotify_mark);
	CR_PB_DESC(CORE,		Core,			core);
	CR_PB_DESC(IDS,			TaskKobjIds,		task_kobj_ids);
	CR_PB_DESC(MM,			Mm,			mm);
	CR_PB_DESC(VMAS,		Vma,			vma);
	CR_PB_DESC(PIPES,		Pipe,			pipe);
	CR_PB_DESC(PIPES_DATA,		PipeData,		pipe_data);
	CR_PB_DESC(FIFO,		Fifo,			fifo);
	CR_PB_DESC(PSTREE,		Pstree,			pstree);
	CR_PB_DESC(SIGACT,		Sa,			sa);
	CR_PB_DESC(UNIXSK,		UnixSk,			unix_sk);
	CR_PB_DESC(INETSK,		InetSk,			inet_sk);
	CR_PB_DESC(SK_QUEUES,		SkPacket,		sk_packet);
	CR_PB_DESC(ITIMERS,		Itimer,			itimer);
	CR_PB_DESC(CREDS,		Creds,			creds);
	CR_PB_DESC(UTSNS,		Utsns,			utsns);
	CR_PB_DESC(IPCNS_VAR,		IpcVar,			ipc_var);
	CR_PB_DESC(IPCNS_SHM,		IpcShm,			ipc_shm);

	CR_PB_MDESC_INIT(cr_pb_descs[PB_IPCNS_MSG],	IpcMsg,		ipc_msg);

	CR_PB_DESC(IPCNS_MSG_ENT,	IpcMsg,			ipc_msg);
	CR_PB_DESC(IPCNS_SEM,		IpcSem,			ipc_sem);
	CR_PB_DESC(FS,			Fs,			fs);
	CR_PB_DESC(REMAP_FPATH,		RemapFilePath,		remap_file_path);
	CR_PB_DESC(GHOST_FILE,		GhostFile,		ghost_file);
	CR_PB_DESC(TCP_STREAM,		TcpStream,		tcp_stream);
	CR_PB_DESC(MOUNTPOINTS,		Mnt,			mnt);
	CR_PB_DESC(NETDEV,		NetDevice,		net_device);
	CR_PB_DESC(PACKETSK,		PacketSock,		packet_sock);
	CR_PB_DESC(TTY,			TtyFile,		tty_file);
	CR_PB_DESC(TTY_INFO,		TtyInfo,		tty_info);
	CR_PB_DESC(FILE_LOCK,		FileLock,		file_lock);
	CR_PB_DESC(RLIMIT,		Rlimit,			rlimit);

	CR_PB_MDESC_INIT(cr_pb_descs[PB_PAGEMAP_HEAD],	PagemapHead,	pagemap_head);

	CR_PB_DESC(PAGEMAP,		Pagemap,		pagemap);
	CR_PB_DESC(SIGINFO,		Siginfo,		siginfo);
	CR_PB_DESC(NETLINKSK,		NetlinkSk,		netlink_sk);
}
