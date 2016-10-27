//twitter @flyic
//moony_li@trendmicor.com
#ifndef the_flying_circus_inline_hook_h
#define the_flying_circus_inline_hook_h

#include <mach/kern_return.h>
#include <sys/types.h>
#include <mach/mach_vm.h>
#include <libkern/libkern.h>

#include "rename_functions.h"
#include "sysproto.h"
#include "syscall.h"

typedef enum
{
    INLINE_ENUM_IS_IO_CONNECT_METHOD = 4,
    INLINE_ENUM_CREATE_MAPPING_IN_TASK=2,
    INLINE_ENUM_IPC_KMSG_GET=0,
    INLINE_ENUM_COPY_IO = 3,
    
    INLINE_ENUM_MACH_MSG_OVERWRITE_TRAP = 1,
    
    INLINE_ENUM_IPC_KMSG_SEND = 8,
    INLINE_ENUM_IS_IO_CONNECT_ASYNC_METHOD=10,
    INLINE_ENUM_KDP_PANIC_DUMP = 5,
    INLINE_ENUM_IOKIT_USER_CLIENT_TRAP = 6,
    INLINE_ENUM_IS_IO_SERVICE_OPEN_EXTENDED=7,

    INLINE_ENUM_MAX =5
} enum_inline_point_t;

typedef enum
{
    ORDER_ENTRY=0,
    ORDER_EXIT=1,
    ORDER_MAX=2
}ENUM_ORDER_T;

typedef struct
{
    char * symbol;
    mach_vm_address_t ori_func_addr;
    mach_vm_address_t trampline_func_addr;
    mach_vm_address_t inlined_func_header_addr;
    char ori_func_bytes[TRAMPOLINE_SIZE+1];
    boolean_t bSet;
    boolean_t bFuzzing;
} _inline_hook_entry, inline_hook_entry_t;

kern_return_t list_inline_info();
kern_return_t init_inline_hook();
//kern_return_t install_inline_hook(char * symbol);
kern_return_t install_inline_hook();
//kern_return_t un_install_inline_hook(char *symbol);
kern_return_t un_install_inline_hook();
kern_return_t un_init_inline_hook();
#endif
