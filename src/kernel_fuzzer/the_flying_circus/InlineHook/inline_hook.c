//@Flyic
//moony_li@trendmicro.com
#include "hide_files.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/attr.h>

#include "configuration.h"
#include "proc.h"
#include "sysent.h"
#include "my_data_definitions.h"
#include "kernel_info.h"
#include "function_pointers.h"
#include "path_utils.h"
#include "inline_hook.h"
#include "is_io_connect_method_trampline.h"
#include "iokit_user_client_trap_trampline.h"
#include "is_io_connect_async_method_trampline.h"
#include "ipc_kmsg_send_trampline.h"
#include "mach_msg_overwrite_trap_trampline.h"
#include "copy_io_trampline.h"
#include "ipc_kmsg_get_trampline.h"
#include "hijacking_utils.h"
#include "Collect_log.h"
#include "communication.h"
#include "ipc_kmsg_get_trampline.h"
#include "createMappingInTask_trampline.h"

extern struct kernel_info g_kernel_info;
extern socket_t g_comm_socket;

inline_hook_entry_t g_inline_hook_entry[INLINE_ENUM_MAX] = {0};

void init_inline_item(enum_inline_point_t index,
                              char * symName,
                              mach_vm_address_t trampFuncAddr,
                              mach_vm_address_t  inlinedFuncAddr)
{
    if (index < INLINE_ENUM_MAX)
    {
        mach_vm_address_t fnAddr = 0;
        fnAddr = solve_kernel_symbol(&g_kernel_info, symName);
        g_inline_hook_entry[index].symbol = symName;
        g_inline_hook_entry[index].ori_func_addr = fnAddr;//original
        g_inline_hook_entry[index].trampline_func_addr = trampFuncAddr;//trampline
        g_inline_hook_entry[index].inlined_func_header_addr = inlinedFuncAddr;//inlined header
        g_inline_hook_entry[index].bFuzzing = false;
    }
}
kern_return_t init_inline_hook()
{
    //moony debug
    //__asm__ volatile ("int3");
    uint32_t uIndex = 0;
    kern_return_t kr = KERN_SUCCESS;
    memset((char *)g_inline_hook_entry,0, sizeof(g_inline_hook_entry));
    mach_vm_address_t fnAddr = 0;
     //Set INLINE_ENUM_CREATE_MAPPING_IN_TASK
    init_inline_item(INLINE_ENUM_CREATE_MAPPING_IN_TASK,
                     API_SYMBOL_CREATE_MAPPING_IN_TASK,
                     trampline_createMappingInTask,
                     inlined_part_createMappingInTask);
 
    //Set INLINE_ENUM_IPC_KMSG_GET
    init_inline_item(INLINE_ENUM_IPC_KMSG_GET,
                     API_SYMBOL_IPC_KMSG_GET,
                     trampline_ipc_kmsg_get,
                     inlined_part_ipc_kmsg_get);
    
    //Set API_SYMBOL_COPY_IO
    init_inline_item(INLINE_ENUM_COPY_IO,
                     API_SYMBOL_COPY_IO,
                     trampline_copy_io_without_lock,
                     inlined_part_copy_io);
    
    
    
    //Set API_SYMBOL_MACH_MSG_OVERWRITE_TRAP
    init_inline_item(INLINE_ENUM_MACH_MSG_OVERWRITE_TRAP,
                    API_SYMBOL_MACH_MSG_OVERWRITE_TRAP,
                    trampline_mach_msg_overwrite_trap,
                    inlined_part_mach_msg_overwrite_trap);
   
    
    //Set API_SYMBOL_IPC_KMSG_SEND
    init_inline_item(INLINE_ENUM_IPC_KMSG_SEND,
                    API_SYMBOL_IPC_KMSG_SEND,
                    trampline_ipc_kmsg_send,
                    inlined_part_ipc_kmsg_send);
    
    
    //Set API_SYMBOL_IS_IO_CONNECT_METHOD
    init_inline_item(INLINE_ENUM_IS_IO_CONNECT_METHOD,
                    API_SYMBOL_IS_IO_CONNECT_METHOD,
                    trampline_is_io_connect_method,
                    inlined_part_is_io_connect_method);
    
    
    //SET API_SYMBOL_IS_IO_CONNECT_ASYNC_METHOD
    init_inline_item(INLINE_ENUM_IS_IO_CONNECT_ASYNC_METHOD,
                    API_SYMBOL_IS_IO_CONNECT_ASYNC_METHOD,
                    trampline_is_io_connect_async_method,
                    inlined_part_is_io_connect_async_method);
    
    //Set API_SYMBOL_KDP_PANIC_DUMP
    init_inline_item(INLINE_ENUM_KDP_PANIC_DUMP,
                    API_SYMBOL_KDP_PANIC_DUMP,
                    trampline_kdp_panic_dump,
                    inlined_part_kdp_panic_dump);
                    

    //Set API_SYMBOL_IOKIT_USER_CLIENT_TRAP
    init_inline_item(INLINE_ENUM_IOKIT_USER_CLIENT_TRAP,
                     API_SYMBOL_IOKIT_USER_CLIENT_TRAP,
                     trampline_iokit_user_client_trap,
                     inlined_part_iokit_user_client_trap);
   
    //Set API_SYMBOL_IS_IO_SERVICE_OPEN_EXTENDED
    init_inline_item(INLINE_ENUM_IS_IO_SERVICE_OPEN_EXTENDED,
                     API_SYMBOL_IS_IO_SERVICE_OPEN_EXTENDED,
                     trampline_is_io_service_open_extended,
                     inlined_part_is_io_service_open_extended);
   
    
    
    
    //bFuzzing flags
    g_inline_hook_entry[INLINE_ENUM_CREATE_MAPPING_IN_TASK].bFuzzing = false;
    g_inline_hook_entry[INLINE_ENUM_IPC_KMSG_GET].bFuzzing = false;
    g_inline_hook_entry[INLINE_ENUM_COPY_IO].bFuzzing = false;
    g_inline_hook_entry[INLINE_ENUM_IS_IO_CONNECT_METHOD].bFuzzing = true;
    
    g_inline_hook_entry[INLINE_ENUM_IPC_KMSG_SEND].bFuzzing = false;
    g_inline_hook_entry[INLINE_ENUM_MACH_MSG_OVERWRITE_TRAP].bFuzzing = false;
    g_inline_hook_entry[INLINE_ENUM_IS_IO_CONNECT_ASYNC_METHOD].bFuzzing = false;
    g_inline_hook_entry[INLINE_ENUM_KDP_PANIC_DUMP].bFuzzing = false;
    g_inline_hook_entry[INLINE_ENUM_IOKIT_USER_CLIENT_TRAP].bFuzzing = false;
    g_inline_hook_entry[INLINE_ENUM_IS_IO_SERVICE_OPEN_EXTENDED].bFuzzing = false;
  
  
    
    //list info
    //list_inline_info();

    kr = init_mutext_for_fuzz_sample();
    kr |=init_mutext_is_io_connect_async_method_for_fuzz_sample();
	kr |=init_mutext_for_ipc_kmsg_send();
    kr |=init_mutext_for_copy_io();
    kr |=init_mutext_for_ipc_kmsg_get();
    kr |= init_mutext_for_createMappingInTask();
    return kr;
}
kern_return_t list_inline_info()
{
    kern_return_t kr = KERN_FAILURE;
    inline_hook_entry_t * pEntry = NULL;
    //moony_modify//printf("\r\n\[DEBUG] list_inline_info:[%d]\r\n", INLINE_ENUM_MAX);
    for(int i = 0; i< INLINE_ENUM_MAX; i++)
    {

        pEntry = &(g_inline_hook_entry[i]);
        //moony_modify//printf("[DEBUG] #%d inline entyr for %s, trampline=0x%llx, ori=0x%llx, inlined=0x%llx\r\n",i,pEntry->symbol,pEntry->trampline_func_addr,pEntry->ori_func_addr,pEntry->inlined_func_header_addr);
        
    }
    return kr;
}

kern_return_t find_inline_info(char * symbol, inline_hook_entry_t *pEntry)
{
    kern_return_t kr = KERN_FAILURE;
    if (!pEntry || !symbol)
    {
        return kr;
    }
    for(int i = 0; i< INLINE_ENUM_MAX ; i++)
    {
        if (0 == strcasecmp(symbol,g_inline_hook_entry[i].symbol))
        {
            *pEntry = g_inline_hook_entry[i];
            kr = KERN_SUCCESS;
            //moony_modify//printf("[DEBUG] find inline entyr for %s, trampline=0x%x, ori=0x%x, inlined=0x%x",symbol,pEntry->trampline_func_addr,pEntry->ori_func_addr,pEntry->inlined_func_header_addr);
            return kr;
        }
    }
    return kr;
}
kern_return_t
//install_inline_hook(char * symbol)
install_inline_hook()
{
    kern_return_t kr = 0;
    char * symbol = 0 ;
    char origBytes[TRAMPOLINE_SIZE+0x100] = {0};
    mach_vm_address_t tramplineAddr = 0;
    mach_vm_address_t origiAddr = 0;
    mach_vm_address_t inlinedPartAddr = 0;
    inline_hook_entry_t entry = {0};
    //moony_modify//printf("[DEBUG] install_inline_hook: start[%d]\r\n", INLINE_ENUM_MAX);
    for(int i = 0; i< INLINE_ENUM_MAX; i++)
    {
        //kr = find_inline_info(symbol, &entry);
        entry = g_inline_hook_entry[i];
        symbol = entry.symbol;
        tramplineAddr = entry.trampline_func_addr;
        origiAddr = entry.ori_func_addr;
        inlinedPartAddr = entry.inlined_func_header_addr;
        if (symbol)
        {
            //todo:bypass
            //push  rbp
            //mov rbp, rsp
            //sizeof=0x4
            kr = install_trampoline_any(origiAddr, tramplineAddr, origBytes);
            if (!kr)
            {
                memcpy(g_inline_hook_entry[i].ori_func_bytes, origBytes, TRAMPOLINE_SIZE);
                g_inline_hook_entry[i].bSet = true;
            }
            //moony_modify//printf("[DEBUG] install trampline #%d  (status:0x%x) for %s, trampline=0x%x, ori=0x%x, inlined=0x%x, oriBytes=0x%llx\r\n",i,kr,symbol,tramplineAddr,origiAddr,inlinedPartAddr,origBytes);

        }
        
    }
    //moony_modify//printf("[DEBUG] install_inline_hook: end[%d]\r\n", INLINE_ENUM_MAX);
    return kr;
}

kern_return_t un_install_inline_hook()
{
    kern_return_t kr = 0;
    char * symbol = 0 ;
    char origBytes[TRAMPOLINE_SIZE+0x100] = {0};
    mach_vm_address_t tramplineAddr = 0;
    mach_vm_address_t origiAddr = 0;
    mach_vm_address_t inlinedPartAddr = 0;
    inline_hook_entry_t entry = {0};
    //moony_modify//printf("[DEBUG] un_install_inline_hook: start [%d]\r\n", INLINE_ENUM_MAX);
    for(int i = 0; i< INLINE_ENUM_MAX; i++)
    {
        //kr = find_inline_info(symbol, &entry);
        entry = g_inline_hook_entry[i];
        symbol = entry.symbol;
        tramplineAddr = entry.trampline_func_addr;
        origiAddr = entry.ori_func_addr;
        inlinedPartAddr = entry.inlined_func_header_addr;
        char * origBytes = 0;
        if (g_inline_hook_entry[i].bSet && symbol)
        {
            kr = remove_trampoline_any(
                                       origiAddr,
                                       (origBytes=g_inline_hook_entry[i].ori_func_bytes));
            if (!kr)
                
            {
                g_inline_hook_entry[i].bSet = false;
            }
            //moony_modify//printf("[DEBUG] uninstall trampline #%d  (status:0x%x) for %s, trampline=0x%x, ori=0x%x, inlined=0x%x, oriBytes=0x%llx\r\n",i,kr,symbol,tramplineAddr,origiAddr,inlinedPartAddr,origBytes);
            
        }
    }
    //moony_modify//printf("[DEBUG] un_install_inline_hook: end [%d]\r\n", INLINE_ENUM_MAX);
    return kr;

}

kern_return_t un_init_inline_hook()
{

    un_init_mutext_for_fuzz_sample();
    un_init_mutext_is_io_connect_async_method_for_fuzz_sample();
	un_init_mutext_for_ipc_kmsg_send();
    un_init_mutext_for_copy_io();
    un_init_mutext_for_ipc_kmsg_get();
    un_init_mutext_for_createMappingInTask();
    return 0;
}


