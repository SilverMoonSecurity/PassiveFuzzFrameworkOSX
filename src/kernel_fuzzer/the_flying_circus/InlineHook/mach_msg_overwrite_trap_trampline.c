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
#include "mach_msg_overwrite_trap_trampline.h"
#include "StackTrace.h"
//////////////Trampline Global variable zone
extern struct kernel_info g_kernel_info;
mach_msg_overwrite_trap_fuzz_sample_info_t g_mach_msg_overwrite_trap_fuzz_sample_info[MAX_PROCESSER_CNT][0x1] = {0};
//////////////Trampline function zone
//For mac 10.11.2 2015-12-14




extern inline_hook_entry_t g_inline_hook_entry[];
typedef kern_return_t (* fn_mach_msg_overwrite_trap_t)
(
    MACH_MSG_OVERWRITE_TRAP_ARGS
 );
 

kern_return_t Prepare_mach_msg_overwrite_trap_env(MACH_MSG_OVERWRITE_TRAP_ARGS, mach_msg_overwrite_trap_fuzz_sample_info_t *pSampleInfo)
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
    pSampleInfo->env.uCpuNo = CURRENT_PROCESSER_ID;
    
    
    if (pProc)
        proc_rele(pProc);
    
    return kr;
}


kern_return_t Copy_mach_msg_overwrite_trap_all (MACH_MSG_OVERWRITE_TRAP_ARGS,
    mach_msg_overwrite_trap_fuzz_sample_info_t *pSampleInfo, ENUM_ORDER_T order)
{

    kern_return_t  kr =0;
    char bufLog[0x200]={0};
    __asm__ volatile ("nop");
    Prepare_mach_msg_overwrite_trap_env(MACH_MSG_OVERWRITE_TRAP_ARGS_VAR_LIST, pSampleInfo);
    if (ORDER_ENTRY == order )
    {
        pSampleInfo->original.entry = *((mach_msg_overwrite_trap_t*)args);
    }
    if (ORDER_EXIT == order )
    {
        pSampleInfo->original.entry = *((mach_msg_overwrite_trap_t*)args);
    }
    //snprintf(bufLog, sizeof(bufLog), "\r\n Copy_mach_msg_overwrite_trap_all %d", s_LogCounter++);
    //kernel_print_log(bufLog);
    return kr;
}

uint64_t s_mach_msg_overwrite_trap_JmpBackAddr = -1;
kern_return_t trampline_mach_msg_overwrite_trap(MACH_MSG_OVERWRITE_TRAP_ARGS)
{
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    kern_return_t kr = 0;
    
    s_mach_msg_overwrite_trap_JmpBackAddr = g_inline_hook_entry[INLINE_ENUM_MACH_MSG_OVERWRITE_TRAP].ori_func_addr + TRAMPOLINE_SIZE;
    //zero it
    memset(&(g_mach_msg_overwrite_trap_fuzz_sample_info[CURRENT_PROCESSER_ID][0]), 0, sizeof(g_mach_msg_overwrite_trap_fuzz_sample_info[0]));
    
    Copy_mach_msg_overwrite_trap_all(MACH_MSG_OVERWRITE_TRAP_ARGS_VAR_LIST, &(g_mach_msg_overwrite_trap_fuzz_sample_info[CURRENT_PROCESSER_ID][0]), ORDER_ENTRY);
    
    //Check system only from user mode
    cframe_t * pCurrFrame = 0;
    cframe_t * pFrame = 0;
	__asm__ volatile("movq %%rbp, %0" : "=m" (pCurrFrame));
    mach_vm_address_t baseRetAddr = 0;
    boolean_t bMatch = false;
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
        bMatch = true;
    }
    if (!bMatch)
    {
      goto _original;
    }
    
    //Fuzz here
  
    //Call original
_original:
    kr = ((fn_mach_msg_overwrite_trap_t )inlined_part_mach_msg_overwrite_trap)(MACH_MSG_OVERWRITE_TRAP_ARGS_VAR_LIST);
_done:
   Copy_mach_msg_overwrite_trap_all(MACH_MSG_OVERWRITE_TRAP_ARGS_VAR_LIST, &(g_mach_msg_overwrite_trap_fuzz_sample_info[CURRENT_PROCESSER_ID][0]), ORDER_EXIT);
EXIT:
    return kr;

}

/*
 (lldb) dis -n mach_msg_overwrite_trap
 kernel.development`mach_msg_overwrite_trap:
 0xffffff801667a400 <+0>:   pushq  %rbp
 0xffffff801667a401 <+1>:   movq   %rsp, %rbp
 0xffffff801667a404 <+4>:   pushq  %r15
 0xffffff801667a406 <+6>:   pushq  %r14
 0xffffff801667a408 <+8>:   pushq  %r13
 0xffffff801667a40a <+10>:  pushq  %r12
 0xffffff801667a40c <+12>:  pushq  %rbx
 0xffffff801667a40d <+13>:  subq   $0x38, %rsp

*/


__attribute__ ((naked)) void inlined_part_mach_msg_overwrite_trap()
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
                      :"m" (s_mach_msg_overwrite_trap_JmpBackAddr)
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
