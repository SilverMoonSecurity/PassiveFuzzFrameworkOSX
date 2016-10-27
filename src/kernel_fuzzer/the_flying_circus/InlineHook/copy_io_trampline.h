//
//  copy_io_trampline.h
//  the_flying_circus
//
//  Created by jack on 1/27/16.
//  Copyright © 2016 reverser. All rights reserved.
//

#ifndef copy_io_trampline_h
#define copy_io_trampline_h

#include <mach/kern_return.h>
#include <sys/types.h>
#include <mach/i386/vm_types.h>
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
#include "inline_hook.h"



#define copy_io_ARGS \
int		copy_type,\
user_addr_t	user_addr,\
char*	kernel_addr,\
vm_size_t nbytes,\
vm_size_t * lencopied,\
int user_kernel_map


#define copy_io_ARGS_List \
copy_type, \
user_addr, \
kernel_addr, \
nbytes,   \
lencopied, \
user_kernel_map




typedef struct
{
    int copy_type;
    user_addr_t user_addr;
    char* kernel_addr;
    vm_size_t nbytes;
    vm_size_t lencopied;
    int use_kernel_map;
}copy_io_t;


typedef detail_control_entry_common_t detail_control_entry_for_copy_io_t, *pdetail_control_entry_for_copy_io_t;


typedef struct
{
    boolean_t bMatched;
    detail_control_entry_for_copy_io_t matchedRule;
}
filter_info_entry_for_copy_io_send, filter_info_entry_for_copy_io_t;


typedef struct
{
    filter_info_entry_for_copy_io_t entry;
}
white_filter_info_for_copy_io, white_filter_info_for_copy_io_t;

typedef struct
{
    filter_info_entry_for_copy_io_t entry;
}
black_filter_info_for_copy_io, black_filter_info_for_copy_io_t;


typedef struct
{
    //noise_bypass_by_class_name_t eClass;
    //noise_bypass_by_proc_t eProc;
    white_filter_info_for_copy_io_t white;
    black_filter_info_for_copy_io_t black;
}
fuzz_noise_for_copy_io, fuzz_noise_for_copy_io_t;



typedef struct{
    char fuzzTag[0x100];
    char recordReproducedName[PATH_MAX +1];
    fuzz_env env;
    fuzz_noise_for_copy_io_t noise;
    union
    {
        copy_io_t entry;
    } original;
    union
    {
        copy_io_t entry;
    } now;
} _copy_io_fuzz_sample_info, copy_io_fuzz_sample_info_t;


kern_return_t Copy_copy_io_all (copy_io_ARGS,
                                copy_io_fuzz_sample_info_t *pSampleInfo, ENUM_ORDER_T order);
kern_return_t init_mutext_for_copy_io();
kern_return_t un_init_mutext_for_copy_io();
//kern_return_t trampline_copy_io(copy_io_ARGS);
kern_return_t trampline_copy_io_without_lock(copy_io_ARGS);
kern_return_t trampline_copy_io_with_lock(copy_io_ARGS);
__attribute__ ((naked)) void inlined_part_copy_io();

#endif /* copy_io_trampline_h */
