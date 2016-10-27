//@Flyic
//moony_li@trendmicro.com
//#include "trampline_functions.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/attr.h>

#include "Collect_log.h"
#include "proc.h"
#include "sysent.h"
#include "my_data_definitions.h"
#include "kernel_info.h"
#include "function_pointers.h"
#include "path_utils.h"
#include "fuzz_method.h"
#include "inline_hook.h"
#include "record_reproduce.h"
#include "ipc_kmsg_get_trampline.h"
#include "StackTrace.h"
#include "Mutext.h"
#include "ipc_kmsg_get_noise_filter.h"
#include "StackTrace.h"
//////////////Trampline Global variable zone
extern struct kernel_info g_kernel_info;

extern stack_match_item_t stack_matcher_for_ipc_kmsg_get[];
extern uint32_t stack_matcher_size_for_ipc_kmsg_get;
lck_mtx_t *g_ipc_kmsg_get_fuzz_sample_info_mutext=NULL;
lck_grp_t *g_ipc_kmsg_get_fuzz_sample_info_mutext_group=NULL;
ipc_kmsg_get_fuzz_sample_info_t g_ipc_kmsg_get_fuzz_sample_info[MAX_FUZZ_SAMPLE_INFO_CNT] = {0};
uint64_t g_ipc_kmsg_get_fuzz_sample_info_index = 0;
uint64_t g_ipc_kmsg_get_fuzz_sample_info_counter = 0;
//////////////Trampline function zone
//For mac 10.11.2 2015-12-14

kern_return_t init_mutext_for_ipc_kmsg_get()
{
    return init_mutex(&g_ipc_kmsg_get_fuzz_sample_info_mutext, &g_ipc_kmsg_get_fuzz_sample_info_mutext_group, "g_ipc_kmsg_get_fuzz_sample_info_mutext");
}

kern_return_t un_init_mutext_for_ipc_kmsg_get()
{
	return  un_init_mutex(&g_ipc_kmsg_get_fuzz_sample_info_mutext, &g_ipc_kmsg_get_fuzz_sample_info_mutext_group);
}


extern inline_hook_entry_t g_inline_hook_entry[];
typedef kern_return_t (* fn_ipc_kmsg_get_t)
(
    ipc_kmsg_get_ARGS
 );
 

kern_return_t Prepare_ipc_kmsg_get_env(ipc_kmsg_get_ARGS, ipc_kmsg_get_fuzz_sample_info_t *pSampleInfo)
{
    kern_return_t kr = 0;

    
    //Get proc name
    pid_t pid = 0;
    proc_t pProc= proc_self();
    pid = proc_pid(pProc);
    char path [PATH_MAX+1] = {0};
    proc_name(pid, path,PATH_MAX);
    path[PATH_MAX] = '\0';
    strncpy(pSampleInfo->env.szProcName, path, PATH_MAX);
    
    //Get processer id
    pSampleInfo->env.uCpuNo = CURRENT_PROCESSER_ID_NOW;
    
    //Get counter
    pSampleInfo->env.uCounter = g_ipc_kmsg_get_fuzz_sample_info_counter;
    //Get index
    pSampleInfo->env.uIndex =  g_ipc_kmsg_get_fuzz_sample_info_index;
    if (pProc)
        proc_rele(pProc);
    
    return kr;
}


kern_return_t Copy_ipc_kmsg_get_all (ipc_kmsg_get_ARGS,
    ipc_kmsg_get_fuzz_sample_info_t *pSampleInfo, ENUM_ORDER_T order)
{

    kern_return_t  kr =0;
    char bufLog[0x200]={0};
    __asm__ volatile ("nop");
    Prepare_ipc_kmsg_get_env(ipc_kmsg_get_ARGS_VAR_LIST, pSampleInfo);
    if (!(kmsgp && *kmsgp&&(*kmsgp)->ikm_header&&(*kmsgp)->ikm_header->msgh_size))
    {
        kr = KERN_FAILURE;
        goto _EXIT;
    }
    uint64_t uMsghid = (*kmsgp)->ikm_header->msgh_id;
    uint64_t uAddr =  (uint64_t)getRoutineByMsghid(uMsghid);
    uint64_t uSendSize = (*kmsgp)->ikm_header->msgh_size;
    

    if (ORDER_ENTRY == order )
    {
        pSampleInfo->original.entry.kmsg = *kmsgp;
        pSampleInfo->original.entry.pRoutineAddr = uAddr;
        pSampleInfo->original.entry.uSendSize = uSendSize;
        pSampleInfo->original.entry.uMsghid = uMsghid;
    }
    
    if (ORDER_EXIT == order )
    {
        pSampleInfo->now.entry.kmsg = *kmsgp;
        pSampleInfo->now.entry.pRoutineAddr = uAddr;
        pSampleInfo->now.entry.uSendSize = uSendSize;
        pSampleInfo->now.entry.uMsghid = uMsghid;
    }
    //snprintf(bufLog, sizeof(bufLog), "\r\n Copy_ipc_kmsg_get_all %d", s_LogCounter++);
    //kernel_print_log(bufLog);
_EXIT:
    return kr;
}



uint64_t s_ipc_kmsg_get_JmpBackAddr = -1;
kern_return_t trampline_ipc_kmsg_get(ipc_kmsg_get_ARGS)
{
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    kern_return_t krRet = 0;
    kern_return_t krRetTemp = 0;
    boolean_t bWhiteBypass = true;
	boolean_t bFuzzBlack = false;
    boolean_t bFuzzed = false;
    boolean_t bMatchStack = false;
    //Call original first
    s_ipc_kmsg_get_JmpBackAddr = g_inline_hook_entry[INLINE_ENUM_IPC_KMSG_GET].ori_func_addr + TRAMPOLINE_SIZE;
	
    krRet = ((fn_ipc_kmsg_get_t )inlined_part_ipc_kmsg_get)(ipc_kmsg_get_ARGS_VAR_LIST);
	
	 //Begin lock
    lck_mtx_lock(g_ipc_kmsg_get_fuzz_sample_info_mutext);
    g_ipc_kmsg_get_fuzz_sample_info_counter++;
	g_ipc_kmsg_get_fuzz_sample_info_index++;
    //zero it
    memset(&(g_ipc_kmsg_get_fuzz_sample_info[g_ipc_kmsg_get_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), 0, sizeof(g_ipc_kmsg_get_fuzz_sample_info[0]));
    
    //Check in kernel mode address
    if (!(size &&
        ((((uint64_t)kmsgp) &0xffffff0000000000)== 0xffffff0000000000) &&
        (((*(uint64_t *)kmsgp)&0xffffff0000000000) == 0xffffff0000000000) &&
        ((((uint64_t)(*kmsgp)->ikm_header)&0xffffff0000000000) == 0xffffff0000000000) &&
        (*kmsgp)->ikm_header->msgh_size))
    {
     
        goto _done;
    }
    krRetTemp = Copy_ipc_kmsg_get_all(ipc_kmsg_get_ARGS_VAR_LIST, &(g_ipc_kmsg_get_fuzz_sample_info[g_ipc_kmsg_get_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), ORDER_ENTRY);
    if (krRetTemp)
    {
        goto _done;
    }
       //Check special stacks
    bMatchStack = matchFrameStack(stack_matcher_for_ipc_kmsg_get, stack_matcher_size_for_ipc_kmsg_get);
    if (!bMatchStack)
    {
        goto _original;
    }

  _WHITE_CHECK:
    //White list check
    bWhiteBypass = true;
    bWhiteBypass = should_bypass_within_ipc_kmsg_get(&g_ipc_kmsg_get_fuzz_sample_info[g_ipc_kmsg_get_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]);
    if (bWhiteBypass)
    {
        goto _original;
    }
//#endif

_BLACK_CHECK:
    //Black listing
    bFuzzBlack = false;
    bFuzzBlack  = should_fuzz_within_ipc_kmsg_get(&g_ipc_kmsg_get_fuzz_sample_info[g_ipc_kmsg_get_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]);

    if (!bFuzzBlack)
    {
        goto _original;
    }
    //Fuzz here
    uint32_t uLen = 0;
    char * pBuf = 0;
    if (_maybe(100,30,89))
    {
        if (kmsgp)
        {
        mach_msg_header_t *  ikm_header = (*kmsgp)->ikm_header;
        if (ikm_header)
        {
            size_t msgh_size = ikm_header->msgh_size;
            if (msgh_size > sizeof(mach_msg_header_t))
            {
                uLen = msgh_size - sizeof(mach_msg_header_t);
                //__asm__ volatile ("int3");
                if (uLen)
                {
                    if (uLen >= 1)
                    {
                        _flip_N_byte_if_fuzzing(pBuf = &(ikm_header[1]), uLen, INLINE_ENUM_IPC_KMSG_GET,
                                               100,10,20, 2,5);
                        bFuzzed = true;
                    }
                }//end of uLen
            }
        }
        }
        
    }
    
    //Call original
_original:
    krRetTemp = Copy_ipc_kmsg_get_all(ipc_kmsg_get_ARGS_VAR_LIST, &(g_ipc_kmsg_get_fuzz_sample_info[g_ipc_kmsg_get_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), ORDER_EXIT);
    if (krRetTemp)
    {
        goto _done;
    }
    
_done:
    if (!bFuzzed)
	{
		g_ipc_kmsg_get_fuzz_sample_info_index--;
	}
    lck_mtx_unlock(g_ipc_kmsg_get_fuzz_sample_info_mutext);

    return krRet;

}

/*
 (lldb) dis -n ipc_kmsg_get
 kernel.development`ipc_kmsg_get:
 0xffffff801f464970 <+0>:   pushq  %rbp
 0xffffff801f464971 <+1>:   movq   %rsp, %rbp
 0xffffff801f464974 <+4>:   pushq  %r15
 0xffffff801f464976 <+6>:   pushq  %r14
 0xffffff801f464978 <+8>:   pushq  %r13
 0xffffff801f46497a <+10>:  pushq  %r12
 0xffffff801f46497c <+12>:  pushq  %rbx
 0xffffff801f46497d <+13>:  subq   $0x28, %rsp

*/


__attribute__ ((naked)) void inlined_part_ipc_kmsg_get()
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
                      :"m" (s_ipc_kmsg_get_JmpBackAddr)
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
