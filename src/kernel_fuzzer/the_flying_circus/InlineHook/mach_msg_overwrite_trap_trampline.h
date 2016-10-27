//twitter @flyic
//moony_li@trendmicor.com
#ifndef mach_msg_overwrite_trap_trampline_h
#define mach_msg_overwrite_trap_trampline_h

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

/*

 mach_msg_return_t
 mach_msg_overwrite_trap(
	struct mach_msg_overwrite_trap_args *args);
 
 struct mach_msg_overwrite_trap_args {
	PAD_ARG_(user_addr_t, msg);
	PAD_ARG_(mach_msg_option_t, option);
	PAD_ARG_(mach_msg_size_t, send_size);
	PAD_ARG_(mach_msg_size_t, rcv_size);
	PAD_ARG_(mach_port_name_t, rcv_name);
	PAD_ARG_(mach_msg_timeout_t, timeout);
	PAD_ARG_(mach_port_name_t, notify);
	PAD_ARG_8
	PAD_ARG_(user_addr_t, rcv_msg);  //  Unused on mach_msg_trap
};
 (lldb) expr -A -T -L -- *(mach_msg_overwrite_trap_args*)0xffffff887fbc3f28
 0x00007ff93023b210: (mach_msg_overwrite_trap_args) $407 = {
 0x00007ff93023b210:   (char []) msg_l_ = "?"
 0x00007ff93023b210:   (user_addr_t) msg = 123145305590184
 0x00007ff93023b218:   (char []) msg_r_ = "\x03"
 0x00007ff93023b218:   (char []) option_l_ = "\x03"
 0x00007ff93023b218:   (mach_msg_option_t) option = 3
 0x00007ff93023b21c:   (char [4]) option_r_ = ""
 0x00007ff93023b220:   (char []) send_size_l_ = "\\"
 0x00007ff93023b220:   (mach_msg_size_t) send_size = 92
 0x00007ff93023b224:   (char [4]) send_size_r_ = ""
 0x00007ff93023b228:   (char []) rcv_size_l_ = "0"
 0x00007ff93023b228:   (mach_msg_size_t) rcv_size = 48
 0x00007ff93023b22c:   (char [4]) rcv_size_r_ = ""
 0x00007ff93023b230:   (char []) rcv_name_l_ = "?
 0x00007ff93023b230:   (mach_port_name_t) rcv_name = 29895
 0x00007ff93023b234:   (char [4]) rcv_name_r_ = ""
 0x00007ff93023b238:   (char []) timeout_l_ = ""
 0x00007ff93023b238:   (mach_msg_timeout_t) timeout = 0
 0x00007ff93023b23c:   (char [4]) timeout_r_ = ""
 0x00007ff93023b240:   (char []) notify_l_ = ""
 0x00007ff93023b240:   (mach_port_name_t) notify = 0
 0x00007ff93023b244:   (char [4]) notify_r_ = ""
 0x00007ff93023b248:   (char []) rcv_msg_l_ = ""
 0x00007ff93023b248:   (user_addr_t) rcv_msg = 0
 0x00007ff93023b250:   (char []) rcv_msg_r_ = "\x80"
 }

*/
struct mach_msg_overwrite_trap_args {
    user_addr_t  msg;
    mach_msg_option_t  option ;
    mach_msg_size_t send_size;
    mach_msg_size_t rcv_size;
    mach_port_name_t rcv_name;
    mach_msg_timeout_t timeout;
    mach_port_name_t notify;
    user_addr_t rcv_msg;  //  Unused on mach_msg_trap
};

#define MACH_MSG_OVERWRITE_TRAP_ARGS \
    struct mach_msg_overwrite_trap_args *args
	
	
#define MACH_MSG_OVERWRITE_TRAP_ARGS_VAR_LIST   \
	args
	
	
#define MACH_MSG_OVERWRITE_TRAP_ARGS_IN_STRUCT \
user_addr_t  msg;\
mach_msg_option_t  option ;\
mach_msg_size_t send_size;\
mach_msg_size_t rcv_size;\
mach_port_name_t rcv_name;\
mach_msg_timeout_t timeout;\
mach_port_name_t notify;\
user_addr_t rcv_msg;  //  Unused on mach_msg_trap


#define MACH_MSG_OVERWRITE_TRAP_ARGS_FOR_ANALYSIS_IN_STRUCT

//extern union fuzz_noise_t;
//extern struct noise_bypass_by_class_name_t ;
//extern struct noise_bypass_by_proc_t uProc;

typedef struct
{
    MACH_MSG_OVERWRITE_TRAP_ARGS_IN_STRUCT
}mach_msg_overwrite_trap_t;

typedef struct{
    char fuzzTag[0x100];
    char recordReproducedName[PATH_MAX +1];
    fuzz_env env;
    fuzz_noise_t noise;
    union
    {
        mach_msg_overwrite_trap_t entry;
    } original;
    union
    {
        mach_msg_overwrite_trap_t entry;
    } now;
} _mach_msg_overwrite_trap_fuzz_sample_info, mach_msg_overwrite_trap_fuzz_sample_info_t;



kern_return_t trampline_mach_msg_overwrite_trap(MACH_MSG_OVERWRITE_TRAP_ARGS);
__attribute__ ((naked)) void inlined_part_mach_msg_overwrite_trap();

#endif
