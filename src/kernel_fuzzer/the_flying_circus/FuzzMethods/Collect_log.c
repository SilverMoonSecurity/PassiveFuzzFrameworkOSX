//@Flyic
//moony_li@trendmicro.com

#include <string.h>
#include "Collect_log.h"
#include "proc.h"
#include "str_utils.h"

#include <string.h>
//#include <ctypes.h>
//#include <stdlib.h>
#include "kernel_IOUserClient.h"
#include "kernel_info.h"
#include <mach/task.h>
#include <mach/vm_map.h>
#include "proc_utils.h"
#include "function_pointers.h"
#include "inline_hook.h"


socket_t g_comm_socket = NULL;
extern struct kernel_info g_kernel_info;
extern fuzz_sample_info_t g_fuzz_sample_info[MAX_PROCESSER_CNT][0x1];

/*
//#define KERNEL_SYMBOL_ARRAY_SIZE (20000)
//#define KERNEL_SYMBOL_SIZE (0x100)
//char g_kernel_symbol_array[KERNEL_SYMBOL_ARRAY_SIZE][KERNEL_SYMBOL_SIZE];
//static g_kern_print_log_counter=0;


typedef struct{
    uint64_t opaque[6];
} panic_hook_t;
typedef void (* panic_hook_fn_t) (panic_hook_t *);
static panic_hook_t hook_panic_moony={0};
typedef void (* panic_hook_search_t)(panic_hook_t *hook_, panic_hook_fn_t hook_fn);
static panic_hook_search_t fnAddr_panic_hook = NULL;
//void (* fnAddr_panic_hook1)(panic_hook_t *hook_, panic_hook_fn_t hook_fn) = NULL;
void panic_hook_filter_moony(panic_hook_t * hook_);
kern_return_t  set_kernel_panic_hook()
{
    //boolean_t bChanged = false;
    kern_return_t kr = KERN_FAILURE;
    uint64_t uTemp =0;
    if (!fnAddr_panic_hook)
    {
        //__asm__ volatile ("int3");
        fnAddr_panic_hook = solve_kernel_symbol(&g_kernel_info, "_panic_hook");
        //__asm__ volatile ("int3");
        //__asm__ volatile ("int3");
        //__asm__ volatile ("int3");
        //fnAddr_panic_hook = uTemp;
       //__asm__ volatile ("int3");
    }
    if (fnAddr_panic_hook)
    {
        if (is_address_readable(fnAddr_panic_hook))
        {
           // __asm__ volatile ("int3");
            fnAddr_panic_hook(&hook_panic_moony, panic_hook_filter_moony);
            //moony_modify//printf("
            printf("[DEBUG] set_kernel_panic_hook: panic_hook=0x%llx, filter=0x%llx\n", fnAddr_panic_hook, panic_hook_filter_moony);
            
            //__asm__ volatile ("int3");
            kr = KERN_SUCCESS;
        }
    }
    

_EXIT:
    return kr;
}


typedef void (*panic_unhook_search_t)(panic_hook_t *hook_);
static panic_unhook_search_t fnAddr_panic_unhook = NULL;
kern_return_t  unset_kernel_panic_hook()
{
    //boolean_t bChanged = false;
    kern_return_t kr = KERN_FAILURE;
    
    if (!fnAddr_panic_unhook)
    {
        fnAddr_panic_unhook = solve_kernel_symbol(&g_kernel_info, "_panic_unhook");
        
    }
    if (fnAddr_panic_unhook)
    {
        if (is_address_readable(fnAddr_panic_unhook))
        {
             fnAddr_panic_unhook(&hook_panic_moony);
            //moony_modify//printf("
            printf("[DEBUG] unset_kernel_panic_hook: panic_unhook=0x%llx, filter=0x%llx\n", fnAddr_panic_unhook, panic_hook_filter_moony);
             kr = KERN_SUCCESS;
        }
    }
   
_EXIT:
    return kr;
}

static uint32_t nPanicHookFilterCounter=0;
void panic_hook_filter_moony(panic_hook_t * hook_)
{
    char bufLog[0x200]={0};
    snprintf(bufLog, sizeof(bufLog), "\r\n panic_hook_filter_moony is called %d， I am hooked!", nPanicHookFilterCounter);
    ++nPanicHookFilterCounter;
    kernel_print_log(bufLog);
    //__asm__ volatile ("int3");
}


*/

kern_return_t  kernel_print_log(char *buf)
{
    boolean_t bChanged = false;
    kern_return_t kr = KERN_FAILURE;
    kprintf(buf);
    printf(buf);
    //strncpy(g_kernel_symbol_array[g_kern_print_log_counter++%KERNEL_SYMBOL_ARRAY_SIZE], buf, KERNEL_SYMBOL_SIZE);
    
    kr = KERN_SUCCESS;
_EXIT:
    return kr;
}


kern_return_t init_collect_log()
{
    kern_return_t kr = KERN_SUCCESS;
    return kr;
    //todo: Core dump by socket
    //Pay attention:
    //Please firstly set up inline hook for kdp_panic_dump() in init_inline_hook
    if (comm_init(&g_comm_socket) < 0 )
    {
        g_comm_socket = NULL;
        printf("zday comm: comm_init failed\n");
        kr = KERN_FAILURE;
        goto __COMM_FAIL;
    }
    
    if (comm_connect(g_comm_socket) < 0)
    {
        printf("zday comm: comm_connect failed\n");
        comm_deinit(g_comm_socket);
        g_comm_socket = NULL;
        kr = KERN_FAILURE;
        goto __COMM_FAIL;
    }
__COMM_FAIL:

    return kr;
}
kern_return_t un_init_collect_log()
{
    kern_return_t kr = KERN_SUCCESS;
    return kr;
    //todo: Core dump by socket
    if(g_comm_socket)
    {
        if(comm_is_connect(g_comm_socket))
            comm_closeconnect(g_comm_socket);
        comm_deinit(g_comm_socket);
        g_comm_socket = NULL;
    }
    return kr;
}

kern_return_t  transfer_fuzz_info_by_socket()
{
    kern_return_t kr = KERN_FAILURE;
    printf("jack: before call original %p\n", g_comm_socket);
    if(g_comm_socket)
    {
        if(comm_is_connect(g_comm_socket))
        {
            
            if (comm_sendfuzzinfo(g_comm_socket,
                                  &g_fuzz_sample_info[CURRENT_PROCESSER_ID][0])
                < 0)
            {
                printf("zday comm: comm_sendfuzzinfo failed");
                
            }
            else
            {
                kr = KERN_SUCCESS;
                goto _EXIT;
            }
        }
        else
        {
            printf("jack: socket not connected\n");
        }
        
    }
_EXIT:
    return kr;
}


static uint32_t nPanicDumpCallBackCounter=0;
kern_return_t  kdp_panic_dump_callback()
{
    kern_return_t kr = 0;
    char bufLog[0x200]={0};
    snprintf(bufLog, sizeof(bufLog), "\n kdp_panic_dump_callback is called :before[%d]， I am hooked!\n", nPanicDumpCallBackCounter);
    kernel_print_log(bufLog);
    nPanicDumpCallBackCounter+=1;
    //getchar();
    
    transfer_fuzz_info_by_socket();
    snprintf(bufLog, sizeof(bufLog), "\n kdp_panic_dump_callback is called :after[%d]， I am hooked!\n", nPanicDumpCallBackCounter);
    kernel_print_log(bufLog);
    
    return kr;
}

/////////////////////////Trampline function zone for kdp_pannic_dump
//For mac 10.10.x 2015-11-13

extern inline_hook_entry_t g_inline_hook_entry[];
typedef kern_return_t (* fn_kdp_panic_dump_t)
(
 );


__attribute__ ((naked)) void inlined_part_kdp_panic_dump();


uint64_t s_kdp_panic_dump_JmpBackAddr = -1;
kern_return_t trampline_kdp_panic_dump()
{
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    kern_return_t kr = 0;
    
    s_kdp_panic_dump_JmpBackAddr = g_inline_hook_entry[INLINE_ENUM_KDP_PANIC_DUMP].ori_func_addr + TRAMPOLINE_SIZE;
    kdp_panic_dump_callback();
    //Call original
_original:
    kr = ((fn_kdp_panic_dump_t )inlined_part_kdp_panic_dump)();
_done:
EXIT:
    return kr;
    
}
//Mac osx 10.11.1
/*
 (lldb) dis -n kdp_panic_dump
 kernel.development`kdp_panic_dump:
 0xffffff80158bc680 <+0>:    pushq  %rbp
 0xffffff80158bc681 <+1>:    movq   %rsp, %rbp
 0xffffff80158bc684 <+4>:    pushq  %r15
 0xffffff80158bc686 <+6>:    pushq  %r14
 0xffffff80158bc688 <+8>:    pushq  %r13
 0xffffff80158bc68a <+10>:   pushq  %r12
 0xffffff80158bc68c <+12>:   pushq  %rbx
 0xffffff80158bc68d <+13>:   subq   $0x78, %rsp
 0xffffff80158bc691 <+17>:   leaq   0x862a30(%rip), %r12      ; __stack_chk_guard
 
 */


__attribute__ ((naked)) void inlined_part_kdp_panic_dump()
{
    __asm__ volatile (
                      "  push %rbp\n"
                      "  mov %rsp, %rbp\n"
                      "  push %r15\n"
                      "  push %r14\n"
                      "  push %r13\n"
                      "  push %r12\n"
                      );
    __asm__ volatile (
                      "  jmp *%0\n"
                      //"  mov %%rax, %0"
                      :
                      :"m" (s_kdp_panic_dump_JmpBackAddr)
                      //:"%rax"
                      );
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");//10
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");
    __asm__ volatile ("int3");//20
}

