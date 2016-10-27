//twitter @flyic
//moony_li@trendmicor.com
#ifndef ipc_kmsg_send_trampline_h
#define ipc_kmsg_send_trampline_h

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
#include "Mach_msg.h"

/*
mach_msg_return_t
ipc_kmsg_send(
	ipc_kmsg_t		kmsg,
	mach_msg_option_t	option,
	mach_msg_timeout_t	send_timeout)
*/
/*

(lldb) expr -A -T -L -- *(ipc_kmsg_t)(0xffffff801d7b6800)
0x00007fc31de372d0: (ipc_kmsg) $7 = {
0x00007fc31de372d0:   (mach_msg_size_t) ikm_size = 184
0x00007fc31de372d8:   (ipc_kmsg *) ikm_next = 0x00000000ffffff10
0x00007fc31de372e0:   (ipc_kmsg *) ikm_prev = 0x00000000ffffff10
0x00007fc31de372e8:   (mach_msg_header_t *) ikm_header = 0xffffff801d7b6890
0x00007fc31de372f0:   (ipc_port_t) ikm_prealloc = 0x0000000000000000
0x00007fc31de372f8:   (ipc_port_t) ikm_voucher = 0x0000000000000000
0x00007fc31de37300:   (ipc_importance_elem *) ikm_importance = 0x0000000000000000
0x00007fc31de37308:   (queue_chain_t) ikm_inheritance = {
0x00007fc31de37308:     (queue_entry *) next = 0x0000000000000000
0x00007fc31de37310:     (queue_entry *) prev = 0x0000000000000000
  }
}
*/


#define IPC_KMSG_SEND_ARGS \
	ipc_kmsg_t		kmsg,\
	mach_msg_option_t	option,\
	mach_msg_timeout_t	send_timeout
	
	
#define IPC_KMSG_SEND_ARGS_VAR_LIST   \
	kmsg,\
	option,\
	send_timeout
	
	
#define IPC_KMSG_SEND_ARGS_IN_STRUCT \
	ipc_kmsg_t		kmsg;\
	mach_msg_option_t	option;\
	mach_msg_timeout_t	send_timeout
	
#define IPC_KMSG_SEND_ARGS_FOR_ANALYSIS_IN_STRUCT

//extern union fuzz_noise_t;
//extern struct noise_bypass_by_class_name_t ;
//extern struct noise_bypass_by_proc_t uProc;

typedef struct
{
    IPC_KMSG_SEND_ARGS_IN_STRUCT;
    void * pRoutineAddr;
    uint64_t uSendSize;
    uint64_t uMsghid;
}ipc_kmsg_send_t;



typedef struct
{
    char procName[PATH_MAX];
    uint64_t uid;
	uint64_t msg_id_from;
	uint64_t msg_id_to;
    char routineName[PATH_MAX];
    uint64_t addr_offset_from;
    uint64_t addr_offset_to;
    struct
    {
        //uint64_t uTemp;
        unsigned long long uTemp;
    }u;
} detail_control_entry_for_ipc_kmsg_send_t, *pdetail_control_entry_for_ipc_kmsg_send_t;


typedef struct
{
    boolean_t bMatched;
    detail_control_entry_for_ipc_kmsg_send_t matchedRule;
}
filter_info_entry_for_ipc_kmsg_send, filter_info_entry_for_ipc_kmsg_send_t;


typedef struct
{
    filter_info_entry_for_ipc_kmsg_send_t entry;
}
white_filter_info_for_ipc_kmsg_send, white_filter_info_for_ipc_kmsg_send_t;

typedef struct
{
    filter_info_entry_for_ipc_kmsg_send_t entry;
}
black_filter_info_for_ipc_kmsg_send, black_filter_info_for_ipc_kmsg_send_t;

typedef struct
{
    //noise_bypass_by_class_name_t eClass;
    //noise_bypass_by_proc_t eProc;
    white_filter_info_for_ipc_kmsg_send_t white;
    black_filter_info_for_ipc_kmsg_send_t black;
}
fuzz_noise_for_ipc_kmsg_send, fuzz_noise_for_ipc_kmsg_send_t;




typedef struct{
    char fuzzTag[0x100];
    char recordReproducedName[PATH_MAX +1];
    fuzz_env env;
    fuzz_noise_for_ipc_kmsg_send_t noise;
    union
    {
        ipc_kmsg_send_t entry;
    } original;
    union
    {
        ipc_kmsg_send_t entry;
    } now;
} _ipc_kmsg_send_fuzz_sample_info, ipc_kmsg_send_fuzz_sample_info_t;



kern_return_t init_mutext_for_ipc_kmsg_send();
kern_return_t un_init_mutext_for_ipc_kmsg_send();
kern_return_t trampline_ipc_kmsg_send(IPC_KMSG_SEND_ARGS);
__attribute__ ((naked)) void inlined_part_ipc_kmsg_send();

#endif
