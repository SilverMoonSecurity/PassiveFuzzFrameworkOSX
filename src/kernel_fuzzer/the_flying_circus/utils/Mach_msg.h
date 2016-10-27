
#ifndef mach_msg_utils_h
#define mach_msg_utils_h
#include <stdint.h>
#include <mach/message.h>
#include <mach/mig.h>
#include <mach/kern_return.h>
#include <sys/types.h>
#include <mach/mach_vm.h>
#include <libkern/libkern.h>
#include <IOKit/IOTypes.h>
#include <Device/device_types.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/attr.h>
#include "noise_filter.h"
#include "rename_functions.h"
#include "sysproto.h"
#include "syscall.h"
#include "configuration.h"

#define KMSG_IOKIT_SUBSYSTEM_RANGE  0xAF0, 0x0B47
#define KMSG_MACH_VM_SUBSYSTEM_RANGE  0x12C0, 0x12D4
#define KMSG_MACH_PORT_SUBSYSTEM_RANGE  0xC80, 0x0CA4
#define KMSG_MACH_HOST_SUBSYSTEM_RANGE  0xC8, 0xE4
#define KMSG_HOST_PRIV_SUBSYSTEM_RANGE  0x190, 0x1AA
#define KMSG_HOST_SECURITY_SUBSYSTEM_RANGE  0x258, 0x25A
#define KMSG_CLOCK_SUBSYSTEM_RANGE  0x3E8, 0x3EB
#define KMSG_CLOCK_PRIV_SUBSYSTEM_RANGE  0x4B0, 0x4B2
#define KMSG_PROCESSOR_SUBSYSTEM_RANGE  0xBB8, 0xBBE
#define KMSG_PROCESSOR_SET_SUBSYSTEM_RANGE  0xFA0, 0xFAA
#define KMSG_LOCK_SET_SUBSYSTEM_RANGE  0x96A28, 0x96A2E
#define KMSG_TASK_SUBSYSTEM_RANGE  0x0D48, 0x0D72
#define KMSG_THREAD_ACT_SUBSYSTEM_RANGE  0x0E10, 0x0E2C
#define KMSG_VM32_MAP_SUBSYSTEM_RANGE  0x0ED8, 0x0EF7
#define KMSG_UNDREPLY_SUBSYSTEM_RANGE  0x1838, 0x183A
#define KMSG_DEFAULT_PAGER_OBJECT_SUBSYSTEM_RANGE  0x8E3, 0x8EE
#define KMSG_MACH_VOUCHER_SUBSYSTEM_RANGE  0x1518, 0x151D
#define KMSG_MACH_VOUCHER_SUBSYSTEM_RANGE  0x8E3, 0x8EE
#define KMSG_MACH_VOUCHER_ATTR_CONTROL_SUBSYSTEM_RANGE  0x15E0, 0x15E2
///NOT IN MIG_E below
#define KMSG_CATCH_EXC_SUBSYSTEM_RANGE  0x961, 0x964
#define KMSG_CATCH_MACH_EXC_SUBSYSTEM_RANGE  0x965, 0x968
#define KMSG_DP_MEMORY_OBJECT_SUBSYSTEM_RANGE  0x898, 0x8A2
#define KMSG_MEMORY_OBJECT_CONTROL_SUBSYSTEM_RANGE  0x7D0, 0x7DC
#define KMSG_UPL_SUBSYSTEM_RANGE  0x802, 0x806

#define KMSG_ANY_RANGE  ANY_MATCH_INTEGER,ANY_MATCH_INTEGER
#define KMSG_ADDR_OFFSET_ANY_RANGE ANY_MATCH_INTEGER,ANY_MATCH_INTEGER
#define KMSG_LEAVING 0


typedef struct {
    mach_msg_id_t num;
    mig_routine_t routine;
    int size;
#if	MACH_COUNTERS
    mach_counter_t callcount;
#endif
} mig_hash_t;


struct ipc_importance_elem {
    uint32_t				iie_bits;	/* type and refs */
    mach_voucher_attr_value_reference_t	iie_made;	/* references given to vouchers */
    queue_head_t				iie_kmsgs;	/* list of kmsgs inheriting from this */
    queue_head_t				iie_inherits; 	/* list of inherit elems hung off this */
    uint32_t				iie_externcnt;	/* number of externalized boosts */
    uint32_t				iie_externdrop;	/* number of those dropped already */
    
#if 0
    //#define IIE_REF_DEBUG 0
    //#if IIE_REF_DEBUG
    uint32_t iie_refs_added;			/* all refs added via all means */
    uint32_t iie_refs_dropped;			/* all refs dropped via all means */
    uint32_t iie_kmsg_refs_added;			/* all refs added by kmsgs taking a ref */
    uint32_t iie_kmsg_refs_inherited;		/* kmsg refs consumed by a new inherit */
    uint32_t iie_kmsg_refs_coalesced;		/* kmsg refs coalesced into an existing inherit */
    uint32_t iie_kmsg_refs_dropped;			/* kmsg refs dropped by not accepting msg importance */
    uint32_t iie_task_refs_added;			/* refs added by a task reference call */
    uint32_t iie_task_refs_added_inherit_from;	/* task references added by inherit from */
    uint32_t iie_task_refs_added_transition;	/* task references added by imp transition code */
    uint32_t iie_task_refs_self_added;		/* task refs added by self-boost */
    uint32_t iie_task_refs_inherited;		/* task refs consumed by a new inherit */
    uint32_t iie_task_refs_coalesced;		/* task refs coalesced into an existing inherit */
    uint32_t iie_task_refs_dropped;			/* all refs dropped via all task means */
#endif
    
};

typedef struct ipc_kmsg
{
    mach_msg_size_t  ikm_size;
    struct ipc_kmsg *  ikm_next;
    struct ipc_kmsg * ikm_prev;
    mach_msg_header_t * ikm_header;
    ipc_port_t  ikm_prealloc;
    ipc_port_t  ikm_voucher;
    struct ipc_importance_elem * ikm_importance;
    queue_chain_t ikm_inheritance;
} *ipc_kmsg_t;

uint64_t getRoutineByMsghid(mach_msg_id_t id);

#endif
