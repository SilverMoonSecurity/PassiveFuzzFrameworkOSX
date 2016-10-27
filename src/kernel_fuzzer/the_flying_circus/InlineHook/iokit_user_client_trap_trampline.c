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
#include "iokit_user_client_trap_trampline.h"

//////////////Trampline Global variable zone

user_client_trap_fuzz_sample_info_t g_user_client_tramp_fuzz_sample_info[MAX_PROCESSER_CNT][0x1] = {0};

//////////////Trampline function zone
//For mac 10.10.x 2015-09-22


extern inline_hook_entry_t g_inline_hook_entry[];
typedef kern_return_t (* fn_iokit_user_client_trap_t)
(
 struct iokit_user_client_trap_args *args
 );




kern_return_t Prepare_iokit_user_client_trap_env(struct iokit_user_client_trap_args *args, user_client_trap_fuzz_sample_info_t *pSampleInfo)
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

uint32_t s_LogCounter=0;
kern_return_t Copy_iokit_user_client_trap_all (iokit_user_client_trap_args *args,
    user_client_trap_fuzz_sample_info_t *pSampleInfo, ENUM_ORDER_T order)
{

    kern_return_t  kr =0;
    char bufLog[0x200]={0};
    __asm__ volatile ("nop");
    Prepare_iokit_user_client_trap_env(args, pSampleInfo);
    if (ORDER_ENTRY == order )
    {
        pSampleInfo->original.entry = *(iokit_user_client_trap_t *)args;
    }
    
    if (ORDER_EXIT == order )
    {
        pSampleInfo->now.entry = *(iokit_user_client_trap_t *)args;
    }
    //snprintf(bufLog, sizeof(bufLog), "\r\n Copy_iokit_user_client_trap_all %d", s_LogCounter++);
    //kernel_print_log(bufLog);
    return kr;
}

uint64_t s_iokit_user_client_trap_JmpBackAddr = -1;
kern_return_t trampline_iokit_user_client_trap(iokit_user_client_trap_args *args)
{
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    kern_return_t kr = 0;
    
    s_iokit_user_client_trap_JmpBackAddr = g_inline_hook_entry[INLINE_ENUM_IOKIT_USER_CLIENT_TRAP].ori_func_addr + TRAMPOLINE_SIZE +1;
    //zero it
    memset(&(g_user_client_tramp_fuzz_sample_info[CURRENT_PROCESSER_ID][0]), 0, sizeof(g_user_client_tramp_fuzz_sample_info[0]));
    //Pay attention: assemble code is NOT aligned with 12
    
    Copy_iokit_user_client_trap_all(args, &(g_user_client_tramp_fuzz_sample_info[CURRENT_PROCESSER_ID][0]), ORDER_ENTRY);
    //Fuzz here
    
    uint32_t uLen = 0;
    if (maybe())
    {
        uLen = sizeof(args->p1);
        //flip_N_byte(args->p1, uLen, uLen/FLIP_N_DEVIDED);
        flip_N_byte_if_fuzzing(args->p1, uLen, INLINE_ENUM_IOKIT_USER_CLIENT_TRAP);
        uLen = sizeof(args->p2);
            flip_N_byte_if_fuzzing(args->p2, uLen, INLINE_ENUM_IOKIT_USER_CLIENT_TRAP);
        uLen = sizeof(args->p3);
        flip_N_byte_if_fuzzing(args->p3, uLen,INLINE_ENUM_IOKIT_USER_CLIENT_TRAP);
        uLen = sizeof(args->p4);
        flip_N_byte_if_fuzzing(args->p4, uLen, INLINE_ENUM_IOKIT_USER_CLIENT_TRAP);
        uLen = sizeof(args->p5);
        flip_N_byte_if_fuzzing(args->p5, uLen, INLINE_ENUM_IOKIT_USER_CLIENT_TRAP);
        uLen = sizeof(args->p6);
        flip_N_byte_if_fuzzing(args->p6, uLen, INLINE_ENUM_IOKIT_USER_CLIENT_TRAP);
    }
    
    //Call original
_original:
    kr = ((fn_iokit_user_client_trap_t )inlined_part_iokit_user_client_trap)(args);
_done:
   Copy_iokit_user_client_trap_all(args, &(g_user_client_tramp_fuzz_sample_info[CURRENT_PROCESSER_ID][0]), ORDER_EXIT);
EXIT:
    return kr;

}

/*
(lldb) dis -n iokit_user_client_trap
kernel.development`iokit_user_client_trap:
    0xffffff801a6e4880 <+0>:   pushq  %rbp
    0xffffff801a6e4881 <+1>:   movq   %rsp, %rbp
    0xffffff801a6e4884 <+4>:   pushq  %r15
    0xffffff801a6e4886 <+6>:   pushq  %r14
    0xffffff801a6e4888 <+8>:   pushq  %rbx
    0xffffff801a6e4889 <+9>:   subq   $0x18, %rsp
    0xffffff801a6e488d <+13>:  movq   %rdi, %r14
    0xffffff801a6e4890 <+16>:  movq   (%r14), %rdi
    0xffffff801a6e4893 <+19>:  movq   %gs:0x8, %rax
    0xffffff801a6e489c <+28>:  movq   0x378(%rax), %rax
    0xffffff801a6e48a3 <+35>:  movq   0x278(%rax), %rsi

*/
 
 
__attribute__ ((naked)) void inlined_part_iokit_user_client_trap()
{
    __asm__ volatile (
                      "  push %rbp\n"
                      "  mov %rsp, %rbp\n"
                      "  push %r15\n"
                      "  push %r14\n"
                      "  push %rbx\n"
                      "  sub $0x18, %rsp"
                      );
    __asm__ volatile (
                      "  jmp *%0\n"
                      //"  mov %%rax, %0"
                      :
                      :"m" (s_iokit_user_client_trap_JmpBackAddr)
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
