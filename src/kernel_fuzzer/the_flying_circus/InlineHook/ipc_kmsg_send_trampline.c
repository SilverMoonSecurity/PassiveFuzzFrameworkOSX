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
#include "ipc_kmsg_send_trampline.h"
#include "StackTrace.h"
#include "Mutext.h"
#include "ipc_kmsg_send_noise_filter.h"

//////////////Trampline Global variable zone
extern struct kernel_info g_kernel_info;
lck_mtx_t *g_ipc_kmsg_send_fuzz_sample_info_mutext=NULL;
lck_grp_t *g_ipc_kmsg_send_fuzz_sample_info_mutext_group=NULL;
ipc_kmsg_send_fuzz_sample_info_t g_ipc_kmsg_send_fuzz_sample_info[MAX_FUZZ_SAMPLE_INFO_CNT] = {0};
uint64_t g_ipc_kmsg_send_fuzz_sample_info_index = 0;
uint64_t g_ipc_kmsg_send_fuzz_sample_info_counter = 0;
//////////////Trampline function zone
//For mac 10.11.2 2015-12-14

kern_return_t init_mutext_for_ipc_kmsg_send()
{
    return init_mutex(&g_ipc_kmsg_send_fuzz_sample_info_mutext, &g_ipc_kmsg_send_fuzz_sample_info_mutext_group, "g_ipc_kmsg_send_fuzz_sample_info_mutext");
}

kern_return_t un_init_mutext_for_ipc_kmsg_send()
{
	return  un_init_mutex(&g_ipc_kmsg_send_fuzz_sample_info_mutext, &g_ipc_kmsg_send_fuzz_sample_info_mutext_group);
}


extern inline_hook_entry_t g_inline_hook_entry[];
typedef kern_return_t (* fn_ipc_kmsg_send_t)
(
    IPC_KMSG_SEND_ARGS
 );
 

kern_return_t Prepare_ipc_kmsg_send_env(IPC_KMSG_SEND_ARGS, ipc_kmsg_send_fuzz_sample_info_t *pSampleInfo)
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
    pSampleInfo->env.uCounter = g_ipc_kmsg_send_fuzz_sample_info_counter;
    //Get index
    pSampleInfo->env.uIndex =  g_ipc_kmsg_send_fuzz_sample_info_index;
    if (pProc)
        proc_rele(pProc);
    
    return kr;
}


kern_return_t Copy_ipc_kmsg_send_all (IPC_KMSG_SEND_ARGS,
    ipc_kmsg_send_fuzz_sample_info_t *pSampleInfo, ENUM_ORDER_T order)
{

    kern_return_t  kr =0;
    char bufLog[0x200]={0};
    __asm__ volatile ("nop");
    Prepare_ipc_kmsg_send_env(IPC_KMSG_SEND_ARGS_VAR_LIST, pSampleInfo);
    uint64_t uMsghid = kmsg->ikm_header->msgh_id;
    uint64_t uAddr =  (uint64_t)getRoutineByMsghid(uMsghid);
    uint64_t uSendSize = kmsg->ikm_header->msgh_size;
    

    if (ORDER_ENTRY == order )
    {
        pSampleInfo->original.entry.kmsg = kmsg;
        pSampleInfo->original.entry.option = option;
        pSampleInfo->original.entry.send_timeout = send_timeout;
        pSampleInfo->original.entry.pRoutineAddr = uAddr;
        pSampleInfo->original.entry.uSendSize = uSendSize;
        pSampleInfo->original.entry.uMsghid = uMsghid;
    }
    
    if (ORDER_EXIT == order )
    {
        pSampleInfo->now.entry.kmsg = kmsg;
        pSampleInfo->now.entry.option = option;
        pSampleInfo->now.entry.send_timeout = send_timeout;
        pSampleInfo->now.entry.pRoutineAddr = uAddr;
        pSampleInfo->now.entry.uSendSize = uSendSize;
        pSampleInfo->now.entry.uMsghid = uMsghid;
    }
    //snprintf(bufLog, sizeof(bufLog), "\r\n Copy_ipc_kmsg_send_all %d", s_LogCounter++);
    //kernel_print_log(bufLog);
    return kr;
}



uint64_t s_ipc_kmsg_send_JmpBackAddr = -1;
kern_return_t trampline_ipc_kmsg_send(IPC_KMSG_SEND_ARGS)
{
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    kern_return_t kr = 0;
    boolean_t bWhiteBypass = true;
	boolean_t bFuzzBlack = false;
    boolean_t bFuzzed = false;
    s_ipc_kmsg_send_JmpBackAddr = g_inline_hook_entry[INLINE_ENUM_IPC_KMSG_SEND].ori_func_addr + TRAMPOLINE_SIZE;
	
	
	 //Begin lock
    lck_mtx_lock(g_ipc_kmsg_send_fuzz_sample_info_mutext);
    g_ipc_kmsg_send_fuzz_sample_info_counter++;
	g_ipc_kmsg_send_fuzz_sample_info_index++;
    //zero it
    memset(&(g_ipc_kmsg_send_fuzz_sample_info[g_ipc_kmsg_send_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), 0, sizeof(g_ipc_kmsg_send_fuzz_sample_info[0]));
    
    Copy_ipc_kmsg_send_all(IPC_KMSG_SEND_ARGS_VAR_LIST, &(g_ipc_kmsg_send_fuzz_sample_info[g_ipc_kmsg_send_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), ORDER_ENTRY);
    
    //Check system only from user mode
    cframe_t * pCurrFrame = 0;
    cframe_t * pFrame = 0;
	__asm__ volatile("movq %%rbp, %0" : "=m" (pCurrFrame));
    mach_vm_address_t baseRetAddr = 0;
    boolean_t bMatchFrame = false;
    boolean_t bMatchMsgId = false;
    pFrame = getBaseFrame(pCurrFrame);
    if (pFrame)
    {
        baseRetAddr = pFrame->caller;
    }
    static mach_vm_address_t hdl_mach_scall64_addr = 0;
    if (!hdl_mach_scall64_addr)
    {
       hdl_mach_scall64_addr =  solve_kernel_symbol(&g_kernel_info, "_hndl_mach_scall64");
    }
    if (hdl_mach_scall64_addr&& baseRetAddr)
        if (hdl_mach_scall64_addr<baseRetAddr && baseRetAddr<hdl_mach_scall64_addr+32/*22*/)
    {
        bMatchFrame = true;
    }
    if (!bMatchFrame)
    {
      goto _original;
    }
    
   
  _WHITE_CHECK:
    //White list check
    bWhiteBypass = true;
    bWhiteBypass = should_bypass_within_ipc_kmsg_send(&g_ipc_kmsg_send_fuzz_sample_info[g_ipc_kmsg_send_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]);
    if (bWhiteBypass)
    {
        goto _original;
    }
//#endif

_BLACK_CHECK:
    //Black listing
    bFuzzBlack = false;
    bFuzzBlack  = should_fuzz_within_ipc_kmsg_send(&g_ipc_kmsg_send_fuzz_sample_info[g_ipc_kmsg_send_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]);

    if (!bFuzzBlack)
    {
        goto _original;
    }
    //Fuzz here
    uint32_t uLen = 0;
    uint32_t uLenFuzzed = 1;
    char * pBuf = 0;
    if (maybe())
    {
        mach_msg_header_t *  ikm_header = kmsg->ikm_header;
        if (ikm_header)
        {
            size_t msgh_size = ikm_header->msgh_size;
            if (msgh_size > sizeof(mach_msg_header_t))
            {
                uLen = msgh_size - sizeof(mach_msg_header_t);
                //__asm__ volatile ("int3");
                
                if (uLen >= 1)
                {
                    flip_N_byte_if_fuzzing(pBuf = &(ikm_header[1]), uLen, INLINE_ENUM_IPC_KMSG_SEND);
                    bFuzzed = true;
                }
            }
        }
        
    }
    
    //Call original
_original:
    Copy_ipc_kmsg_send_all(IPC_KMSG_SEND_ARGS_VAR_LIST, &(g_ipc_kmsg_send_fuzz_sample_info[g_ipc_kmsg_send_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), ORDER_EXIT);
    if (!bFuzzed)
	{
		g_ipc_kmsg_send_fuzz_sample_info_index--;
	}
    lck_mtx_unlock(g_ipc_kmsg_send_fuzz_sample_info_mutext);
    kr = ((fn_ipc_kmsg_send_t )inlined_part_ipc_kmsg_send)(IPC_KMSG_SEND_ARGS_VAR_LIST);
    return kr;

}

/*
(lldb) dis -n ipc_kmsg_send
kernel.development`ipc_kmsg_send:
    0xffffff8016663de0 <+0>:    pushq  %rbp
    0xffffff8016663de1 <+1>:    movq   %rsp, %rbp
    0xffffff8016663de4 <+4>:    pushq  %r15
    0xffffff8016663de6 <+6>:    pushq  %r14
    0xffffff8016663de8 <+8>:    pushq  %r13
    0xffffff8016663dea <+10>:   pushq  %r12
    0xffffff8016663dec <+12>:   pushq  %rbx
    0xffffff8016663ded <+13>:   pushq  %rax
    0xffffff8016663dee <+14>:   movl   %esi, %r13d
    0xffffff8016663df1 <+17>:   movq   %rdi, %r14
    0xffffff8016663df4 <+20>:   movq   %gs:0x8, %rax
    0xffffff8016663dfd <+29>:   movl   0x38(%rax), %ecx

*/
 
 
__attribute__ ((naked)) void inlined_part_ipc_kmsg_send()
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
                      :"m" (s_ipc_kmsg_send_JmpBackAddr)
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
