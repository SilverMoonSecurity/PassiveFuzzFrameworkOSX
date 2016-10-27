/*
 *   _____   _                          ___     _      _  _     _              __ _
 *  |_   _| | |_      ___      o O O   | __|   | |    | || |   (_)    _ _     / _` |
 *    | |   | ' \    / -_)    o        | _|    | |     \_, |   | |   | ' \    \__, |
 *   _|_|_  |_||_|   \___|   TS__[O]  _|_|_   _|_|_   _|__/   _|_|_  |_||_|   |___/
 * _|"""""|_|"""""|_|"""""| {======|_| """ |_|"""""|_| """"|_|"""""|_|"""""|_|"""""|
 * "`-0-0-'"`-0-0-'"`-0-0-'./o--000'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'
 *            ___      _
 *    o O O  / __|    (_)      _ _    __     _  _     ___
 *   o      | (__     | |     | '_|  / _|   | +| |   (_-<
 *  TS__[O]  \___|   _|_|_   _|_|_   \__|_   \_,_|   /__/_
 *  {======|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|
 * ./o--000'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'
 *
 * And now for something completely different...
 *
 * A Mountain Lion rootkit for Phrack #69!
 *
 * Copyright (c) fG!, 2012, 2013 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * proc.h
 *
 * Copy of private proc structures we will need
 *
 * This is officially a mess :-]
 *
 */

#ifndef the_flying_circus_proc_h
#define the_flying_circus_proc_h

#define __APPLE_API_UNSTABLE
#define SYSCTL_DEF_ENABLED
#define PROC_DEF_ENABLED
#define MACH_KERNEL_PRIVATE

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <security/_label.h>
#include <kern/queue.h>

// options that are set in the different MASTER files

#define CONFIG_MACF 1
#define CONFIG_VFS_FUNNEL 1
//#define CONFIG_TRIGGERS 1
#define TASK_SWAPPER 1
#define CONFIG_COUNTERS 1
#define CONFIG_MACF_MACH 1
#define CONFIG_DTRACE 1

// we need this to complete the proc structure
// osfmk/i386/locks.h
// ML ready
struct __lck_mtx_t__ {
    union {
        struct {
            volatile uintptr_t              lck_mtxd_owner;
            union {
                struct {
                    volatile uint32_t
                lck_mtxd_waiters:16,
                lck_mtxd_pri:8,
                lck_mtxd_ilocked:1,
                lck_mtxd_mlocked:1,
                lck_mtxd_promoted:1,
                lck_mtxd_spin:1,
                lck_mtxd_is_ext:1,
                lck_mtxd_pad3:3;
                };
                uint32_t        lck_mtxd_state;
            };
            /* Pad field used as a canary, initialized to ~0 */
            uint32_t                        lck_mtxd_pad32;
        } lck_mtxd;
        struct {
            struct _lck_mtx_ext_            *lck_mtxi_ptr;
            uint32_t                        lck_mtxi_tag;
            uint32_t                        lck_mtxi_pad32;
        } lck_mtxi;
    } lck_mtx_sw;
};

// osfmk/i386/locks.h
// ML ready
struct lck_spin_t {
    volatile uintptr_t      interlock;
	unsigned long   lck_spin_pad[9];        /* XXX - usimple_lock_data_t */
};



// ripped from xnu/bsd/sys/proc_internal.h
// Needed so we can access the proc structure passed to the syscall
// I had to comment some fields because other kernel includes would be needed
// This should be valid since we are not doing any copies of this structure (just having it's definition to avoid dereference pointer to incomplete types)
// else things might go wrong (big kabooommm)
// FOR SNOW LEOPARD
// XXX: different from SL to Lion. Lion != ML
// XXX: FIXME
struct	proc {
    LIST_ENTRY(proc) p_list;                /* List of all processes. */
    
    pid_t           p_pid;                  /* Process identifier. (static)*/
    void *          task;                   /* corresponding task (static)*/
    struct  proc *  p_pptr;                 /* Pointer to parent process.(LL) */
    pid_t           p_ppid;                 /* process's parent pid number */
    pid_t           p_pgrpid;               /* process group id of the process (LL)*/
    uid_t           p_uid;
    gid_t           p_gid;
    uid_t           p_ruid;
    gid_t           p_rgid;
    uid_t           p_svuid;
    gid_t           p_svgid;
    uint64_t        p_uniqueid;             /* process uniqe ID */
    
    lck_mtx_t       p_mlock;                /* mutex lock for proc */
    
    char            p_stat;                 /* S* process status. (PL)*/
    char            p_shutdownstate;
    char            p_kdebug;               /* P_KDEBUG eq (CC)*/
    char            p_btrace;               /* P_BTRACE eq (CC)*/
    
    LIST_ENTRY(proc) p_pglist;              /* List of processes in pgrp.(PGL) */
    LIST_ENTRY(proc) p_sibling;             /* List of sibling processes. (LL)*/
    LIST_HEAD(, proc) p_children;           /* Pointer to list of children. (LL)*/
    TAILQ_HEAD( , uthread) p_uthlist;       /* List of uthreads  (PL) */
    
    LIST_ENTRY(proc) p_hash;                /* Hash chain. (LL)*/
    TAILQ_HEAD( ,eventqelt) p_evlist;       /* (PL) */
    
    lck_mtx_t       p_fdmlock;              /* proc lock to protect fdesc */
    
    /* substructures: */
    kauth_cred_t    p_ucred;                /* Process owner's identity. (PL) */
    struct  filedesc *p_fd;                 /* Ptr to open files structure. (PFDL) */
    struct  pstats *p_stats;                /* Accounting/statistics (PL). */
    struct  plimit *p_limit;                /* Process limits.(PL) */
    
    struct  sigacts *p_sigacts;             /* Signal actions, state (PL) */
    int            p_siglist;              /* signals captured back from threads */
    struct lck_spin_t      p_slock;                /* spin lock for itimer/profil protection */
    
#define p_rlimit        p_limit->pl_rlimit
    
    struct  plimit *p_olimit;               /* old process limits  - not inherited by child  (PL) */
    unsigned int    p_flag;                 /* P_* flags. (atomic bit ops) */
    unsigned int    p_lflag;                /* local flags  (PL) */
    unsigned int    p_listflag;             /* list flags (LL) */
    unsigned int    p_ladvflag;             /* local adv flags (atomic) */
    int             p_refcount;             /* number of outstanding users(LL) */
    int             p_childrencnt;          /* children holding ref on parent (LL) */
    int             p_parentref;            /* children lookup ref on parent (LL) */
    
    pid_t           p_oppid;                /* Save parent pid during ptrace. XXX */
    u_int           p_xstat;                /* Exit status for wait; also stop signal. */
    
#ifdef _PROC_HAS_SCHEDINFO_
    /* may need cleanup, not used */
    u_int           p_estcpu;               /* Time averaged value of p_cpticks.(used by aio and proc_comapre) */
    fixpt_t         p_pctcpu;               /* %cpu for this process during p_swtime (used by aio)*/
    u_int           p_slptime;              /* used by proc_compare */
#endif /* _PROC_HAS_SCHEDINFO_ */
    
    struct  itimerval p_realtimer;          /* Alarm timer. (PSL) */
    struct  timeval p_rtime;                /* Real time.(PSL)  */
    struct  itimerval p_vtimer_user;        /* Virtual timers.(PSL)  */
    struct  itimerval p_vtimer_prof;        /* (PSL) */
    
    struct  timeval p_rlim_cpu;             /* Remaining rlim cpu value.(PSL) */
    int             p_debugger;             /*  NU 1: can exec set-bit programs if suser */
    boolean_t       sigwait;        /* indication to suspend (PL) */
    void    *sigwait_thread;        /* 'thread' holding sigwait(PL)  */
    void    *exit_thread;           /* Which thread is exiting(PL)  */
    int     p_vforkcnt;             /* number of outstanding vforks(PL)  */
    void *  p_vforkact;             /* activation running this vfork proc)(static)  */
    int     p_fpdrainwait;          /* (PFDL) */
    pid_t   p_contproc;     /* last PID to send us a SIGCONT (PL) */
    
    /* Following fields are info from SIGCHLD (PL) */
    pid_t   si_pid;                 /* (PL) */
    u_int   si_status;              /* (PL) */
    u_int   si_code;                /* (PL) */
    uid_t   si_uid;                 /* (PL) */
    
    void * vm_shm;                  /* (SYSV SHM Lock) for sysV shared memory */
    
#if CONFIG_DTRACE
    user_addr_t                     p_dtrace_argv;                  /* (write once, read only after that) */
    user_addr_t                     p_dtrace_envp;                  /* (write once, read only after that) */
    lck_mtx_t                       p_dtrace_sprlock;               /* sun proc lock emulation */
    int                             p_dtrace_probes;                /* (PL) are there probes for this proc? */
    u_int                           p_dtrace_count;                 /* (sprlock) number of DTrace tracepoints */
    uint8_t                         p_dtrace_stop;                  /* indicates a DTrace-desired stop */
    struct dtrace_ptss_page*        p_dtrace_ptss_pages;            /* (sprlock) list of user ptss pages */
    struct dtrace_ptss_page_entry*  p_dtrace_ptss_free_list;        /* (atomic) list of individual ptss entries */
    struct dtrace_helpers*          p_dtrace_helpers;               /* (dtrace_lock) DTrace per-proc private */
    struct dof_ioctl_data*          p_dtrace_lazy_dofs;             /* (sprlock) unloaded dof_helper_t's */
#endif /* CONFIG_DTRACE */
    
    /* XXXXXXXXXXXXX BCOPY'ed on fork XXXXXXXXXXXXXXXX */
    /* The following fields are all copied upon creation in fork. */
#define p_startcopy     p_argslen
    
    u_int   p_argslen;       /* Length of process arguments. */
    int     p_argc;                 /* saved argc for sysctl_procargs() */
    user_addr_t user_stack;         /* where user stack was allocated */
    struct  vnode *p_textvp;        /* Vnode of executable. */
    off_t   p_textoff;              /* offset in executable vnode */
    
    sigset_t p_sigmask;             /* DEPRECATED */
    sigset_t p_sigignore;   /* Signals being ignored. (PL) */
    sigset_t p_sigcatch;    /* Signals being caught by user.(PL)  */
    
    u_char  p_priority;     /* (NU) Process priority. */
    u_char  p_resv0;        /* (NU) User-priority based on p_cpu and p_nice. */
    char    p_nice;         /* Process "nice" value.(PL) */
    u_char  p_resv1;        /* (NU) User-priority based on p_cpu and p_nice. */
    
#if CONFIG_MACF
    int     p_mac_enforce;                  /* MAC policy enforcement control */
#endif
    
    char    p_comm[MAXCOMLEN+1];
    char    p_name[(2*MAXCOMLEN)+1];        /* PL */
    
    struct  pgrp *p_pgrp;   /* Pointer to process group. (LL) */
    uint32_t        p_csflags;      /* flags for codesign (PL) */
    uint32_t        p_pcaction;     /* action  for process control on starvation */
    uint8_t p_uuid[16];             /* from LC_UUID load command */
    
#if !CONFIG_EMBEDDED
#define PROC_LEGACY_BEHAVIOR_IOTHROTTLE (0x00000001)
    uint32_t       p_legacy_behavior;
#endif
    /* End area that is copied on creation. */
    /* XXXXXXXXXXXXX End of BCOPY'ed on fork (AIOLOCK)XXXXXXXXXXXXXXXX */
#define p_endcopy       p_aio_total_count
    int             p_aio_total_count;              /* all allocated AIO requests for this proc */
    int             p_aio_active_count;             /* all unfinished AIO requests for this proc */
    TAILQ_HEAD( , aio_workq_entry ) p_aio_activeq;  /* active async IO requests */
    TAILQ_HEAD( , aio_workq_entry ) p_aio_doneq;    /* completed async IO requests */
    
    //    struct klist p_klist;  /* knote list (PL ?)*/
    
    struct  rusage *p_ru;   /* Exit information. (PL) */
    int             p_sigwaitcnt;
    thread_t        p_signalholder;
    thread_t        p_transholder;
    
    /* DEPRECATE following field  */
    u_short p_acflag;       /* Accounting flags. */
    
    struct lctx *p_lctx;            /* Pointer to login context. */
    LIST_ENTRY(proc) p_lclist;      /* List of processes in lctx. */
    user_addr_t     p_threadstart;          /* pthread start fn */
    user_addr_t     p_wqthread;             /* pthread workqueue fn */
    int     p_pthsize;                      /* pthread size */
    user_addr_t     p_targconc;             /* target concurrency ptr */
    void *  p_wqptr;                        /* workq ptr */
    int     p_wqsize;                       /* allocated size */
    boolean_t       p_wqiniting;            /* semaphore to serialze wq_open */
    struct lck_spin_t      p_wqlock;               /* lock to protect work queue */
    struct  timeval p_start;                /* starting time */
    void *  p_rcall;
    int             p_ractive;
    int     p_idversion;            /* version of process identity */
    void *  p_pthhash;                      /* pthread waitqueue hash */
#if DIAGNOSTIC
    unsigned int p_fdlock_pc[4];
    unsigned int p_fdunlock_pc[4];
#if SIGNAL_DEBUG
    unsigned int lockpc[8];
    unsigned int unlockpc[8];
#endif /* SIGNAL_DEBUG */
#endif /* DIAGNOSTIC */
    uint64_t        p_dispatchqueue_offset;
#if VM_PRESSURE_EVENTS
    struct timeval  vm_pressure_last_notify_tstamp;
#endif
    int             p_dirty;                        /* dirty state */
};


// bsd/sys/proc.h
#define	P_TRACED	0x00000800
#define P_NOCLDSTOP     0x00000008      /* No SIGCHLD when children stop */
#define	P_LP64		0x00000004	/* Process is LP64 */

// bsd/sys/sysctl.h
// ML ready
struct _pcred {
    char    pc_lock[72];            /* opaque content */
    struct  ucred *pc_ucred;        /* Current credentials. */
    uid_t   p_ruid;                 /* Real user id. */
    uid_t   p_svuid;                /* Saved effective user id. */
    gid_t   p_rgid;                 /* Real group id. */
    gid_t   p_svgid;                /* Saved effective group id. */
    int     p_refcnt;               /* Number of references. */
};

// bsd/sys/sysctl.h
// ML ready
struct _ucred {
    int32_t cr_ref;                 /* reference count */
    uid_t   cr_uid;                 /* effective user id */
    short   cr_ngroups;             /* number of groups */
    gid_t   cr_groups[NGROUPS];     /* groups */
};

// @ bsd/sys/filedesc.h
// ML ready
struct filedesc {
    struct  fileproc **fd_ofiles;   /* file structures for open files */
    char    *fd_ofileflags;         /* per-process open file flags */
    struct  vnode *fd_cdir;         /* current directory */
    struct  vnode *fd_rdir;         /* root directory */
    int     fd_nfiles;              /* number of open files allocated */
    int     fd_lastfile;            /* high-water mark of fd_ofiles */
    int     fd_freefile;            /* approx. next free file */
    u_short fd_cmask;               /* mask for file creation */
    uint32_t        fd_refcnt;              /* reference count */
    
    int     fd_knlistsize;          /* size of knlist */
    struct  klist *fd_knlist;       /* list of attached knotes */
    u_long  fd_knhashmask;          /* size of knhash */
    struct  klist *fd_knhash;       /* hash table for attached knotes */
    int     fd_flags;
};

// @ bsd/sys/file_internal.h
// ML ready
struct fileproc {
    unsigned int f_flags;
    int32_t f_iocount;
    struct fileglob * f_fglob;
    void *  f_waddr;
};

// @ bsd/sys/file_internal.h
/* file types */
typedef enum {
    DTYPE_VNODE     = 1,    /* file */
    DTYPE_SOCKET,           /* communications endpoint */
    DTYPE_PSXSHM,           /* POSIX Shared memory */
    DTYPE_PSXSEM,           /* POSIX Semaphores */
    DTYPE_KQUEUE,           /* kqueue */
    DTYPE_PIPE,             /* pipe */
    DTYPE_FSEVENTS          /* fsevents */
} file_type_t;

// @ bsd/sys/file_internal.h
// ML ready
struct fileglob {
    LIST_ENTRY(fileglob) f_msglist;/* list of active files */
    int32_t fg_flag;                /* see fcntl.h */
    file_type_t fg_type;            /* descriptor type */
    int32_t fg_count;       /* reference count */
    int32_t fg_msgcount;    /* references from message queue */
    kauth_cred_t fg_cred;   /* credentials associated with descriptor */
    struct  fileops {
        int     (*fo_read)      (struct fileproc *fp, struct uio *uio,
                                 int flags, vfs_context_t ctx);
        int     (*fo_write)     (struct fileproc *fp, struct uio *uio,
                                 int flags, vfs_context_t ctx);
#define FOF_OFFSET      0x00000001      /* offset supplied to vn_write */
#define FOF_PCRED       0x00000002      /* cred from proc, not current thread */
        int     (*fo_ioctl)     (struct fileproc *fp, u_long com,
                                 caddr_t data, vfs_context_t ctx);
        int     (*fo_select)    (struct fileproc *fp, int which,
                                 void *wql, vfs_context_t ctx);
        int     (*fo_close)     (struct fileglob *fg, vfs_context_t ctx);
        int     (*fo_kqfilter)  (struct fileproc *fp, struct knote *kn,
                                 vfs_context_t ctx);
        int     (*fo_drain)     (struct fileproc *fp, vfs_context_t ctx);
    } *fg_ops;
    off_t   fg_offset;
    void    *fg_data;               /* vnode or socket or SHM or semaphore */
    lck_mtx_t fg_lock;
    int32_t fg_lflags;              /* file global flags */
#if CONFIG_MACF
    struct label *fg_label;  /* JMM - use the one in the cred? */
#endif
};

#define NULLVP  ((struct vnode *)NULL)

// @ bsd/sys/vnode_internal.h
// XXX
struct vnode {
    lck_mtx_t v_lock;                       /* vnode mutex */
    TAILQ_ENTRY(vnode) v_freelist;          /* vnode freelist */
    TAILQ_ENTRY(vnode) v_mntvnodes;         /* vnodes for mount point */
    LIST_HEAD(, namecache) v_nclinks;       /* name cache entries that name this vnode */
    LIST_HEAD(, namecache) v_ncchildren;    /* name cache entries that regard us as there parent */
    vnode_t  v_defer_reclaimlist;           /* in case we have to defer the reclaim to avoid recursion */
    uint32_t v_listflag;                    /* flags protected by the vnode_list_lock (see below) */
    uint32_t v_flag;                        /* vnode flags (see below) */
    uint16_t v_lflag;                       /* vnode local and named ref flags */
    uint8_t  v_iterblkflags;                /* buf iterator flags */
    uint8_t  v_references;                  /* number of times io_count has been granted */
    int32_t  v_kusecount;                   /* count of in-kernel refs */
    int32_t  v_usecount;                    /* reference count of users */
    int32_t  v_iocount;                     /* iocounters */
    void *   v_owner;                       /* act that owns the vnode */
    uint16_t v_type;                        /* vnode type */
    uint16_t v_tag;                         /* type of underlying data */
    uint32_t v_id;                          /* identity of vnode contents */
    union {
        struct mount    *vu_mountedhere;/* ptr to mounted vfs (VDIR) */
        struct socket   *vu_socket;     /* unix ipc (VSOCK) */
        struct specinfo *vu_specinfo;   /* device (VCHR, VBLK) */
        struct fifoinfo *vu_fifoinfo;   /* fifo (VFIFO) */
        struct ubc_info *vu_ubcinfo;    /* valid for (VREG) */
    } v_un;
    //    struct  buflists v_cleanblkhd;          /* clean blocklist head */
    //    struct  buflists v_dirtyblkhd;          /* dirty blocklist head */
    //    struct klist v_knotes;                  /* knotes attached to this vnode */
    int64_t v_cleanblkhd;          /* clean blocklist head */
    int64_t v_dirtyblkhd;          /* dirty blocklist head */
    int64_t v_knotes;                  /* knotes attached to this vnode */
    /*
     * the following 4 fields are protected
     * by the name_cache_lock held in
     * excluive mode
     */
    kauth_cred_t    v_cred;                 /* last authorized credential */
    int  v_authorized_actions;   /* current authorized actions for v_cred */
    int             v_cred_timestamp;       /* determine if entry is stale for MNTK_AUTH_OPAQUE */
    int             v_nc_generation;        /* changes when nodes are removed from the name cache */
    /*
     * back to the vnode lock for protection
     */
    int32_t         v_numoutput;                    /* num of writes in progress */
    int32_t         v_writecount;                   /* reference count of writers */
    const char *v_name;                     /* name component of the vnode */
    vnode_t v_parent;                       /* pointer to parent vnode */
    struct lockf    *v_lockf;               /* advisory lock list head */
#if CONFIG_VFS_FUNNEL
    struct unsafe_fsnode *v_unsafefs;       /* pointer to struct used to lock */
#else
    int32_t         v_reserved1;
#ifdef __LP64__
    int32_t         v_reserved2;
#endif
#endif /* CONFIG_VFS_FUNNEL */
    int     (**v_op)(void *);               /* vnode operations vector */
    mount_t v_mount;                        /* ptr to vfs we are in */
    void *  v_data;                         /* private data for fs */
#if CONFIG_MACF
    struct label *v_label;                  /* MAC security label */
#endif
#if CONFIG_TRIGGERS
    vnode_resolve_t v_resolve;              /* trigger vnode resolve info (VDIR only) */
#endif /* CONFIG_TRIGGERS */
};

// @ bsd/sys/user.h
// ML ready
struct vfs_context {
    thread_t        vc_thread;              /* pointer to Mach thread */
    kauth_cred_t    vc_ucred;               /* per thread credential */
};

// @ osfmk/kern/queue.h
// ML ready
//@flyic moony_li@trendmicro.com
/*
struct queue_entry_my {
	struct queue_entry	*next;		 //next element
	struct queue_entry	*prev;		 //previous element
};


typedef struct queue_entry_my	*queue_t;
typedef	struct queue_entry_my	queue_head_t;
typedef	struct queue_entry_my	queue_chain_t;
typedef	struct queue_entry_my	*queue_entry_t;

*/

// @ osfmk/kern/exception.h
// ML ready
struct exception_action {
	struct ipc_port		*port;		/* exception port */
	thread_state_flavor_t	flavor;		/* state flavor to send */
	exception_behavior_t	behavior;	/* exception type to raise */
	boolean_t		privileged;	/* survives ipc_task_reset */
};



// @ osfmk/i386/locks.h
// ML ready
#pragma pack(1)         /* Make sure the structure stays as we defined it */
typedef struct _lck_rw_t_internal_ {
    volatile uint16_t       lck_rw_shared_count;    /* No. of accepted readers */
    uint8_t                 lck_rw_interlock;       /* Interlock byte */
    volatile uint8_t
lck_rw_priv_excl:1,     /* Writers prioritized if set */
lck_rw_want_upgrade:1,  /* Read-to-write upgrade waiting */
lck_rw_want_write:1,    /* Writer waiting or locked for write */
lck_r_waiting:1,        /* Reader is sleeping on lock */
lck_w_waiting:1,        /* Writer is sleeping on lock */
lck_rw_can_sleep:1,     /* Can attempts to lock go to sleep? */
lck_rw_padb6:2;                 /* padding */
    
    uint32_t                lck_rw_tag; /* This can be obsoleted when stats
                                         * are in
                                         */
    uint32_t                lck_rw_pad8;
    uint32_t                lck_rw_pad12;
} _lck_rw_t;
#pragma pack()

typedef _lck_rw_t lock_t;

// @ osfmk/vm/vm_map.h
// ML ready
struct vm_map_links {
    struct vm_map_entry     *prev;          /* previous entry */
    struct vm_map_entry     *next;          /* next entry */
    vm_map_offset_t         start;          /* start address */
    vm_map_offset_t         end;            /* end address */
};

// @ osfmk/vm/vm_map.h
// ML ready
struct vm_map_header {
    struct vm_map_links     links;          /* first, last, min, max */
    int                     nentries;       /* Number of entries */
    boolean_t               entries_pageable;
    /* are map entries pageable? */
    vm_map_offset_t         highest_entry_end_addr; /* The ending address of the highest allocated vm_entry_t */
#ifdef VM_MAP_STORE_USE_RB
    struct rb_head  rb_head_store;
#endif
};

typedef struct vm_object 	*vm_object_t;

// @ osfmk/vm/vm_map.h
// ML ready
typedef union vm_map_object {
    vm_object_t             vm_object;      /* object object */
    vm_map_t                sub_map;        /* belongs to another map */
} vm_map_object_t;

// @ osfmk/vm/vm_map.h
// ML ready
struct vm_map_entry {
    struct vm_map_links     links;          /* links to other entries */
#define vme_prev                links.prev
#define vme_next                links.next
#define vme_start               links.start
#define vme_end                 links.end
    // XXX: fixme
    //    struct vm_map_store     store;
    union vm_map_object     object;         /* object I point to */
    vm_object_offset_t      offset;         /* offset into object */
    unsigned int
    /* boolean_t */         is_shared:1,    /* region is shared */
    /* boolean_t */         is_sub_map:1,   /* Is "object" a submap? */
    /* boolean_t */         in_transition:1, /* Entry being changed */
    /* boolean_t */         needs_wakeup:1,  /* Waiters on in_transition */
    /* vm_behavior_t */     behavior:2,     /* user paging behavior hint */
    /* behavior is not defined for submap type */
    /* boolean_t */         needs_copy:1,   /* object need to be copied? */
    /* Only in task maps: */
    /* vm_prot_t */         protection:3,   /* protection code */
    /* vm_prot_t */         max_protection:3,/* maximum protection */
    /* vm_inherit_t */      inheritance:2,  /* inheritance */
    /* boolean_t */         use_pmap:1,     /* nested pmaps */
    /*
     * IMPORTANT:
     * The "alias" field can be updated while holding the VM map lock
     * "shared".  It's OK as along as it's the only field that can be
     * updated without the VM map "exclusive" lock.
     */
    /* unsigned char */     alias:8,        /* user alias */
    /* boolean_t */         no_cache:1,     /* should new pages be cached? */
    /* boolean_t */         permanent:1,    /* mapping can not be removed */
    /* boolean_t */         superpage_size:3,/* use superpages of a certain size */
    /* boolean_t */         zero_wired_pages:1, /* zero out the wired pages of this entry it is being deleted without unwiring them */
    /* boolean_t */         used_for_jit:1,
    /* boolean_t */ from_reserved_zone:1;   /* Allocated from
                                             * kernel reserved zone  */
    unsigned short          wired_count;    /* can be paged if = 0 */
    unsigned short          user_wired_count; /* for vm_wire */
#if     DEBUG
#define MAP_ENTRY_CREATION_DEBUG (1)
#endif
#if     MAP_ENTRY_CREATION_DEBUG
    uintptr_t               vme_bt[16];
#endif
};


//@osfmk/mach/vm_types.h
typedef struct pmap		*pmap_t;

typedef struct {
    unsigned int            type;
    unsigned int            pad4;
    vm_offset_t             pc;
    vm_offset_t             thread;
} lck_mtx_deb_t;

// @ osfmk/i386/locks.h
// ML ready
typedef struct _lck_mtx_ext_ {
    lck_mtx_t               lck_mtx;
    struct _lck_grp_        *lck_mtx_grp;
    unsigned int            lck_mtx_attr;
#ifdef __x86_64__
    unsigned int            lck_mtx_pad1;
#endif
    lck_mtx_deb_t           lck_mtx_deb;
    uint64_t                lck_mtx_stat;
#ifdef __x86_64__
    unsigned int            lck_mtx_pad2[2];
#endif
} _lck_mtx_ext_t;

// @ osfmk/vm/vm_map.h
// ML ready
typedef struct vm_map_entry     *vm_map_entry_t;

struct _vm_map {
    lock_t                  lock;           /* uni- and smp-lock */
    struct vm_map_header    hdr;            /* Map entry header */
#define min_offset              hdr.links.start /* start of range */
#define max_offset              hdr.links.end   /* end of range */
    pmap_t                  pmap;           /* Physical map */
    vm_map_size_t           size;           /* virtual size */
    vm_map_size_t           user_wire_limit;/* rlimit on user locked memory */
    vm_map_size_t           user_wire_size; /* current size of user locked memory in this map */
    int                     ref_count;      /* Reference count */
#if     TASK_SWAPPER
    int                     res_count;      /* Residence count (swap) */
    int                     sw_state;       /* Swap state */
#endif  /* TASK_SWAPPER */
    decl_lck_mtx_data(,     s_lock)         /* Lock ref, res fields */
    _lck_mtx_ext_t           s_lock_ext;
    vm_map_entry_t          hint;           /* hint for quick lookups */
    vm_map_entry_t          first_free;     /* First free space hint */
    unsigned int
    /* boolean_t */         wait_for_space:1, /* Should callers wait for space? */
    /* boolean_t */         wiring_required:1, /* All memory wired? */
    /* boolean_t */         no_zero_fill:1, /*No zero fill absent pages */
    /* boolean_t */         mapped_in_other_pmaps:1, /*has this submap been mapped in maps that use a different pmap */
    /* boolean_t */         switch_protect:1, /*  Protect map from write faults while switched */
    /* boolean_t */         disable_vmentry_reuse:1, /*  All vm entries should keep using newer and higher addresses in the map */
    /* boolean_t */         map_disallow_data_exec:1, /* Disallow execution from data pages on exec-permissive architectures */
    /* reserved */          pad:25;
    unsigned int            timestamp;      /* Version number */
    unsigned int            color_rr;       /* next color (not protected by a lock) */
#if CONFIG_FREEZE
    void                    *default_freezer_handle;
#endif
    boolean_t               jit_entry_exists;
} ;

typedef struct _vm_map *_vm_map_t;

// @ osfmk/kern/zalloc.h
typedef struct zinfo_usage_store_t {
    /* These fields may be updated atomically, and so must be 8 byte aligned */
    uint64_t        alloc __attribute__((aligned(8)));              /* allocation counter */
    uint64_t        free __attribute__((aligned(8)));               /* free counter */
} zinfo_usage_store_t;
typedef zinfo_usage_store_t *zinfo_usage_t;

// @ osfmk/kern/thread_call.h
typedef struct thread_call *thread_call_t;

// @ osfmk/ipc/ipc_labelh.h
typedef struct ipc_labelh
{
    natural_t         lh_references;
    int               lh_type;
    struct label      lh_label;
    ipc_port_t        lh_port;
    decl_lck_mtx_data(,     lh_lock_data)
} *ipc_labelh_t;

/* task_t */
// @ osfmk/kern/task.h
typedef struct process_policy {
    uint64_t  apptype:4,
rfu1:4,
ru_power:4,   /* Resource Usage Power */
ru_net:4,     /* Resource Usage Network */
ru_disk:4,    /* Resource Usage Disk */
ru_cpu:4,     /* Resource Usage CPU */
ru_virtmem:4, /* Resource Usage VM */
ru_wiredmem:4,/* Resource Usage Wired Memory */
low_vm:4,     /* Low Virtual Memory */
rfu2:4,
hw_cpu:4,     /* HW Access to CPU */
hw_net:4,     /* HW Access to Network */
hw_gpu:4,     /* HW Access to GPU */
hw_disk:4,    /* HW Access to Disk */
hw_bg:8;      /* Darwin Background Policy */
} process_policy_t;

struct task {
    /* Synchronization/destruction information */
    decl_lck_mtx_data(,lock)                /* Task's lock */
    uint32_t        ref_count;      /* Number of references to me */
    boolean_t       active;         /* Task has not been terminated */
    boolean_t       halting;        /* Task is being halted */
    
    /* Miscellaneous */
    _vm_map_t        map;            /* Address space description */
    queue_chain_t   tasks;  /* global list of tasks */
    void            *user_data;     /* Arbitrary data settable via IPC */
    
    /* Threads in this task */
    queue_head_t            threads;
    
    processor_set_t         pset_hint;
    struct affinity_space   *affinity_space;
    
    int                     thread_count;
    uint32_t                active_thread_count;
    int                     suspend_count;  /* Internal scheduling only */
    
    /* User-visible scheduling information */
    integer_t               user_stop_count;        /* outstanding stops */
    
    task_role_t             role;
    
    integer_t               priority;                       /* base priority for threads */
    integer_t               max_priority;           /* maximum priority for threads */
    
    /* Task security and audit tokens */
    security_token_t sec_token;
    audit_token_t   audit_token;
    
    /* Statistics */
    uint64_t                total_user_time;        /* terminated threads only */
    uint64_t                total_system_time;
    
    /* Virtual timers */
    uint32_t                vtimers;
    
    /* IPC structures */
    decl_lck_mtx_data(,itk_lock_data)
    struct ipc_port *itk_self;      /* not a right, doesn't hold ref */
    struct ipc_port *itk_nself;     /* not a right, doesn't hold ref */
    struct ipc_port *itk_sself;     /* a send right */
    struct exception_action exc_actions[EXC_TYPES_COUNT];
    /* a send right each valid element  */
    struct ipc_port *itk_host;      /* a send right */
    struct ipc_port *itk_bootstrap; /* a send right */
    struct ipc_port *itk_seatbelt;  /* a send right */
    struct ipc_port *itk_gssd;      /* yet another send right */
    struct ipc_port *itk_task_access; /* and another send right */
#define TASK_PORT_REGISTER_MAX	3
    struct ipc_port *itk_registered[TASK_PORT_REGISTER_MAX];
    /* all send rights */
    
    struct ipc_space *itk_space;
    
    /* Synchronizer ownership information */
    queue_head_t    semaphore_list;         /* list of owned semaphores   */
    queue_head_t    lock_set_list;          /* list of owned lock sets    */
    int             semaphores_owned;       /* number of semaphores owned */
    int             lock_sets_owned;        /* number of lock sets owned  */
    
    /* Ledgers */
    ledger_t        ledger;
    
    unsigned int    priv_flags;                     /* privilege resource flags */
#define VM_BACKING_STORE_PRIV   0x1
#define MACHINE_TASK \
struct user_ldt *       i386_ldt; \
void*                   task_debug;
    
    MACHINE_TASK
    
    integer_t faults;              /* faults counter */
    integer_t pageins;             /* pageins counter */
    integer_t cow_faults;          /* copy on write fault counter */
    integer_t messages_sent;       /* messages sent counter */
    integer_t messages_received;   /* messages received counter */
    integer_t syscalls_mach;       /* mach system call counter */
    integer_t syscalls_unix;       /* unix system call counter */
    uint32_t  c_switch;                        /* total context switches */
    uint32_t  p_switch;                        /* total processor switches */
    uint32_t  ps_switch;               /* total pset switches */
    
    zinfo_usage_t tkm_zinfo;        /* per-task, per-zone usage statistics */
    
    void *bsd_info;
    struct vm_shared_region         *shared_region;
    uint32_t taskFeatures[2];               /* Special feature for this task */
#define tf64BitAddr     0x80000000              /* Task has 64-bit addressing */
#define tf64BitData     0x40000000              /* Task has 64-bit data registers */
#define task_has_64BitAddr(task)        \
(((task)->taskFeatures[0] & tf64BitAddr) != 0)
#define task_set_64BitAddr(task)        \
((task)->taskFeatures[0] |= tf64BitAddr)
#define task_clear_64BitAddr(task)      \
((task)->taskFeatures[0] &= ~tf64BitAddr)
    
    mach_vm_address_t       all_image_info_addr; /* dyld __all_image_info     */
    mach_vm_size_t          all_image_info_size; /* section location and size */
#if CONFIG_MACF_MACH
    ipc_labelh_t label;
#endif
    
#if CONFIG_COUNTERS
#define TASK_PMC_FLAG 0x1       /* Bit in "t_chud" signifying PMC interest */
    uint32_t t_chud;                /* CHUD flags, used for Shark */
#endif
    boolean_t pidsuspended; /* pid_suspend called; no threads can execute */
    boolean_t frozen;       /* frozen; private resident pages committed to swap */
    process_policy_t ext_appliedstate;      /* externally applied actions */
    process_policy_t ext_policystate;       /* externally defined process policy states*/
    process_policy_t appliedstate;          /* self applied acions */
    process_policy_t policystate;           /* process wide policy states */
    uint8_t  rusage_cpu_flags;
    uint8_t  rusage_cpu_percentage;         /* Task-wide CPU limit percentage */
    uint64_t rusage_cpu_interval;           /* Task-wide CPU limit interval */
    uint8_t  rusage_cpu_perthr_percentage;  /* Per-thread CPU limit percentage */
    uint64_t rusage_cpu_perthr_interval;    /* Per-thread CPU limit interval */
    uint64_t rusage_cpu_deadline;
    thread_call_t rusage_cpu_callt;
#if CONFIG_EMBEDDED
    uint32_t        appstate;               /* the current appstate */
    queue_head_t    task_watchers;          /* app state watcher threads */
    int     num_taskwatchers;
    int             watchapplying;
#endif /* CONFIG_EMBEDDED */
    
    vm_extmod_statistics_data_t     extmod_statistics;
    natural_t       proc_terminate; /* the process is marked for proc_terminate */
    
    
};

/* Exported fields for kern sysctls */
// bsd/sys/proc_internal.h
// FIXME
struct extern_proc {
	union {
		struct {
			struct	proc *__p_forw;	/* Doubly-linked run/sleep queue. */
			struct	proc *__p_back;
		} p_st1;
		struct timeval __p_starttime; 	/* process start time */
	} p_un;
#define p_forw p_un.p_st1.__p_forw
#define p_back p_un.p_st1.__p_back
#define p_starttime p_un.__p_starttime
	struct	vmspace *p_vmspace;	/* Address space. */
	// bsd/sys/signalvar.h
	struct	sigacts *p_sigacts;	/* Signal actions, state (PROC ONLY). */
	int	p_flag;			/* P_* flags. */
	char	p_stat;			/* S* process status. */
	pid_t	p_pid;			/* Process identifier. */
	pid_t	p_oppid;	 /* Save parent pid during ptrace. XXX */
	int	p_dupfd;	 /* Sideways return value from fdopen. XXX */
	/* Mach related  */
	caddr_t user_stack;	/* where user stack was allocated */
	void	*exit_thread;	/* XXX Which thread is exiting? */
	int		p_debugger;		/* allow to debug */
	boolean_t	sigwait;	/* indication to suspend */
	/* scheduling */
	u_int	p_estcpu;	 /* Time averaged value of p_cpticks. */
	int	p_cpticks;	 /* Ticks of cpu time. */
	fixpt_t	p_pctcpu;	 /* %cpu for this process during p_swtime */
	void	*p_wchan;	 /* Sleep address. */
	char	*p_wmesg;	 /* Reason for sleep. */
	u_int	p_swtime;	 /* Time swapped in or out. */
	u_int	p_slptime;	 /* Time since last blocked. */
	struct	itimerval p_realtimer;	/* Alarm timer. */
	struct	timeval p_rtime;	/* Real time. */
	u_quad_t p_uticks;		/* Statclock hits in user mode. */
	u_quad_t p_sticks;		/* Statclock hits in system mode. */
	u_quad_t p_iticks;		/* Statclock hits processing intr. */
	int	p_traceflag;		/* Kernel trace points. */
	struct	vnode *p_tracep;	/* Trace to vnode. */
	int	p_siglist;		/* DEPRECATED. */
	struct	vnode *p_textvp;	/* Vnode of executable. */
	int	p_holdcnt;		/* If non-zero, don't swap. */
	sigset_t p_sigmask;	/* DEPRECATED. */
	sigset_t p_sigignore;	/* Signals being ignored. */
	sigset_t p_sigcatch;	/* Signals being caught by user. */
	u_char	p_priority;	/* Process priority. */
	u_char	p_usrpri;	/* User-priority based on p_cpu and p_nice. */
	char	p_nice;		/* Process "nice" value. */
	char	p_comm[MAXCOMLEN+1];
	struct 	pgrp *p_pgrp;	/* Pointer to process group. */
	struct	user *p_addr;	/* Kernel virtual addr of u-area (PROC ONLY). */
	u_short	p_xstat;	/* Exit status for wait; also stop signal. */
	u_short	p_acflag;	/* Accounting flags. */
	struct	rusage *p_ru;	/* Exit information. XXX */
};


// @ bsd/sys/sysctl.h
// ML ready
struct kinfo_proc {
	struct  extern_proc kp_proc;                    /* proc structure */
	struct  eproc {
		struct  proc *e_paddr;          /* address of proc */
		struct  session *e_sess;        /* session pointer */
		struct  _pcred e_pcred;         /* process credentials */
		struct  _ucred e_ucred;         /* current credentials */
		struct   vmspace e_vm;          /* address space */
		pid_t   e_ppid;                 /* parent process id */
		pid_t   e_pgid;                 /* process group id */
		short   e_jobc;                 /* job control counter */
		dev_t   e_tdev;                 /* controlling tty dev */
		pid_t   e_tpgid;                /* tty process group id */
		struct  session *e_tsess;       /* tty session pointer */
#define WMESGLEN        7
		char    e_wmesg[WMESGLEN+1];    /* wchan message */
		segsz_t e_xsize;                /* text size */
		short   e_xrssize;              /* text rss */
		short   e_xccount;              /* text references */
		short   e_xswrss;
		int32_t e_flag;
#define EPROC_CTTY      0x01    /* controlling tty vnode active */
#define EPROC_SLEADER   0x02    /* session leader */
#define COMAPT_MAXLOGNAME       12
		char    e_login[COMAPT_MAXLOGNAME];     /* short setlogin() name */
#if CONFIG_LCTX
		pid_t   e_lcid;
		int32_t e_spare[3];
#else
		int32_t e_spare[4];
#endif
	} kp_eproc;
};


// 64 bits stuff
// FIXME
struct user_vmspace {
	int             vm_refcnt;      /* number of references */
	user_addr_t     vm_shm __attribute((aligned(8)));                       /* SYS5 shared memory private data XXX */
	segsz_t         vm_rssize;              /* current resident set size in pages */
	segsz_t         vm_swrss;               /* resident set size before last swap */
	segsz_t         vm_tsize;               /* text size (pages) XXX */
	segsz_t         vm_dsize;               /* data size (pages) XXX */
	segsz_t         vm_ssize;               /* stack size (pages) */
	user_addr_t     vm_taddr __attribute((aligned(8)));       /* user virtual address of text XXX */
	user_addr_t     vm_daddr;       /* user virtual address of data XXX */
	user_addr_t vm_maxsaddr;        /* user VA at max stack growth */
};

// FIXME
struct user64_pcred {
	char    pc_lock[72];            /* opaque content */
	user64_addr_t   pc_ucred;       /* Current credentials. */
	uid_t   p_ruid;                 /* Real user id. */
	uid_t   p_svuid;                /* Saved effective user id. */
	gid_t   p_rgid;                 /* Real group id. */
	gid_t   p_svgid;                /* Saved effective group id. */
	int     p_refcnt;               /* Number of references. */
};

// FIXME
struct user64_extern_proc {
	union {
		struct {
			user_addr_t __p_forw;   /* Doubly-linked run/sleep queue. */
			user_addr_t __p_back;
		} p_st1;
		struct user64_timeval __p_starttime;    /* process start time */
	} p_un;
	user_addr_t     p_vmspace;      /* Address space. */
	user_addr_t             p_sigacts;      /* Signal actions, state (PROC ONLY). */
	int             p_flag;                 /* P_* flags. */
	char    p_stat;                 /* S* process status. */
	pid_t   p_pid;                  /* Process identifier. */
	pid_t   p_oppid;                /* Save parent pid during ptrace. XXX */
	int             p_dupfd;                /* Sideways return value from fdopen. XXX */
	/* Mach related  */
	user_addr_t user_stack __attribute((aligned(8)));       /* where user stack was allocated */
	user_addr_t exit_thread;  /* XXX Which thread is exiting? */
	int             p_debugger;             /* allow to debug */
	boolean_t       sigwait;        /* indication to suspend */
	/* scheduling */
	u_int   p_estcpu;        /* Time averaged value of p_cpticks. */
	int             p_cpticks;       /* Ticks of cpu time. */
	fixpt_t p_pctcpu;        /* %cpu for this process during p_swtime */
	user_addr_t     p_wchan __attribute((aligned(8)));       /* Sleep address. */
	user_addr_t     p_wmesg;         /* Reason for sleep. */
	u_int   p_swtime;        /* Time swapped in or out. */
	u_int   p_slptime;       /* Time since last blocked. */
	struct  user64_itimerval p_realtimer;   /* Alarm timer. */
	struct  user64_timeval p_rtime; /* Real time. */
	u_quad_t p_uticks;              /* Statclock hits in user mode. */
	u_quad_t p_sticks;              /* Statclock hits in system mode. */
	u_quad_t p_iticks;              /* Statclock hits processing intr. */
	int             p_traceflag;            /* Kernel trace points. */
	user_addr_t     p_tracep __attribute((aligned(8)));     /* Trace to vnode. */
	int             p_siglist;              /* DEPRECATED */
	user_addr_t     p_textvp __attribute((aligned(8)));     /* Vnode of executable. */
	int             p_holdcnt;              /* If non-zero, don't swap. */
	sigset_t p_sigmask;     /* DEPRECATED. */
	sigset_t p_sigignore;   /* Signals being ignored. */
	sigset_t p_sigcatch;    /* Signals being caught by user. */
	u_char  p_priority;     /* Process priority. */
	u_char  p_usrpri;       /* User-priority based on p_cpu and p_nice. */
	char    p_nice;         /* Process "nice" value. */
	char    p_comm[MAXCOMLEN+1];
	user_addr_t     p_pgrp __attribute((aligned(8)));       /* Pointer to process group. */
	user_addr_t     p_addr; /* Kernel virtual addr of u-area (PROC ONLY). */
	u_short p_xstat;        /* Exit status for wait; also stop signal. */
	u_short p_acflag;       /* Accounting flags. */
	user_addr_t     p_ru __attribute((aligned(8))); /* Exit information. XXX */
};

// FIXME
struct user64_kinfo_proc {
	struct  user64_extern_proc kp_proc;     /* proc structure */
	struct  user64_eproc {
		user_addr_t e_paddr;            /* address of proc */
		user_addr_t e_sess;                     /* session pointer */
		struct  user64_pcred e_pcred;           /* process credentials */
		struct  _ucred e_ucred;         /* current credentials */
		struct   user_vmspace e_vm; /* address space */
		pid_t   e_ppid;                 /* parent process id */
		pid_t   e_pgid;                 /* process group id */
		short   e_jobc;                 /* job control counter */
		dev_t   e_tdev;                 /* controlling tty dev */
		pid_t   e_tpgid;                /* tty process group id */
		user64_addr_t   e_tsess __attribute((aligned(8)));      /* tty session pointer */
		char    e_wmesg[WMESGLEN+1];    /* wchan message */
		segsz_t e_xsize;                /* text size */
		short   e_xrssize;              /* text rss */
		short   e_xccount;              /* text references */
		short   e_xswrss;
		int32_t e_flag;
		char    e_login[COMAPT_MAXLOGNAME];     /* short setlogin() name */
#if CONFIG_LCTX
		pid_t   e_lcid;
		int32_t e_spare[3];
#else
		int32_t e_spare[4];
#endif
	} kp_eproc;
};

// @ osfmk/mach/vm_types.h
typedef struct vm_map_copy	*vm_map_copy_t;

struct vm_map_copy {
    int                     type;
#define VM_MAP_COPY_ENTRY_LIST          1
#define VM_MAP_COPY_OBJECT              2
#define VM_MAP_COPY_KERNEL_BUFFER       3
    vm_object_offset_t      offset;
    vm_map_size_t           size;
    union {
        struct vm_map_header        hdr;    /* ENTRY_LIST */
        vm_object_t                 object; /* OBJECT */
        struct {
            void                    *kdata;       /* KERNEL_BUFFER */
            vm_size_t               kalloc_size;  /* size of this copy_t */
        } c_k;
    } c_u;
};

#endif
