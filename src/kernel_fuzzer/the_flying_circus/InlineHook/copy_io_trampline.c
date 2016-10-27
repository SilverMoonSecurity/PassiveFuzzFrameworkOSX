//
//  copy_io_trampline.c
//  the_flying_circus
//
//  Created by jack on 1/27/16.
//  Copyright © 2016 reverser. All rights reserved.
//

#include "copy_io_trampline.h"

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
#include "StackTrace.h"
#include "Mutext.h"
#include "copyio_noise_filter.h"
#include "StackTrace.h"


//////////////Trampline Global variable zone
extern struct kernel_info g_kernel_info;
extern stack_match_item_t stack_matcher_for_copyio[];
extern uint32_t stack_matcher_size_for_copyio;
lck_mtx_t *g_copy_io_mutext=NULL;
lck_grp_t *g_copy_io_mutext_group=NULL;
copy_io_fuzz_sample_info_t g_copy_io_fuzz_sample_info[MAX_FUZZ_SAMPLE_INFO_CNT] = {0};
uint64_t g_copy_io_fuzz_sample_info_index = 0;
uint64_t g_copy_io_fuzz_sample_info_counter = 0;
//////////////Trampline function zone



void print_memory(unsigned char * p, size_t len)
{
    printf("print_memory: pointer: %p,  len: %x", p, len);
    
    size_t final_len = len;
    
    if(len > 0x50)
    {
        final_len = 0x50;
    }
    
    char str[17] = {0};
    
    
    int i = 0;
    for(; i<final_len; ++i)
    {
        
        if(i%0x10 == 0)
        {
            if(i != 0)
            {
                printf("=> %s", str);
                uint64_t* u = (uint64_t*)str;
                *u = 0;
                *(u+1) = 0;
            }
            
            printf("\n");
        }
        printf("0x%02x ", p[i]);
        
        if(p[i]>=0x20 && p[i]<=0x7e)
        {
            str[i%0x10] = p[i];
            
        }
        else
        {
            str[i%0x10] = '.';
        }
        
    }
    
    if( i % 0x10 != 0)
    {
        printf("=> %s", str);
    }
    
    if( final_len % 0x10 == 0 && final_len != 0)
    {
        printf("=> %s", str);
    }
    
    /*if(final_len < 0x10)
    {
        printf("=> %s", str);
    }*/
    
    printf("\n");
    printf("print_memory: end\n");
    
}



kern_return_t init_mutext_for_copy_io()
{
    return init_mutex(&g_copy_io_mutext, &g_copy_io_mutext_group, "g_copy_io_mutext");
}

kern_return_t un_init_mutext_for_copy_io()
{
    return  un_init_mutex(&g_copy_io_mutext, &g_copy_io_mutext_group);
}


extern inline_hook_entry_t g_inline_hook_entry[];
typedef kern_return_t (* fn_copy_io_t)
(
 copy_io_ARGS
 );


kern_return_t Prepare_copy_io_env(copy_io_ARGS, copy_io_fuzz_sample_info_t *pSampleInfo)
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
    pSampleInfo->env.uCounter = g_copy_io_fuzz_sample_info_counter;
    //Get index
    pSampleInfo->env.uIndex =  g_copy_io_fuzz_sample_info_index;
    if (pProc)
        proc_rele(pProc);
    
    return kr;
}


kern_return_t Copy_copy_io_all (copy_io_ARGS,
                                      copy_io_fuzz_sample_info_t *pSampleInfo, ENUM_ORDER_T order)
{
    
    kern_return_t  kr =0;
    char bufLog[0x200]={0};
    __asm__ volatile ("nop");
    
    
    Prepare_copy_io_env(copy_io_ARGS_List, pSampleInfo);
    
    
    if (ORDER_ENTRY == order )
    {
        pSampleInfo->original.entry.copy_type = copy_type;
        pSampleInfo->original.entry.user_addr = user_addr;
        pSampleInfo->original.entry.kernel_addr = kernel_addr;
        pSampleInfo->original.entry.nbytes = nbytes;
        if(copy_type == 0)
        {
            pSampleInfo->original.entry.lencopied = 0;
        }
        else
        {
            pSampleInfo->original.entry.lencopied = *lencopied;
        }
        pSampleInfo->original.entry.use_kernel_map = user_kernel_map;
    }
    
    if (ORDER_EXIT == order )
    {
        pSampleInfo->now.entry.copy_type = copy_type;
        pSampleInfo->now.entry.user_addr = user_addr;
        pSampleInfo->now.entry.kernel_addr = kernel_addr;
        pSampleInfo->now.entry.nbytes = nbytes;
        if(copy_type == 0)
        {
            pSampleInfo->original.entry.lencopied = 0;
        }
        else
        {
            pSampleInfo->now.entry.lencopied = *lencopied;
        }
        pSampleInfo->now.entry.use_kernel_map = user_kernel_map;
    }

    return kr;
}


uint64_t s_copy_io_JmpBackAddr = -1;
kern_return_t trampline_copy_io_with_lock(copy_io_ARGS)
{
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    
    kern_return_t kr = 0;
    
   // __asm__ volatile ("int3");
    
    //lock
    //lck_mtx_lock(g_copy_io_mutext);
    
    s_copy_io_JmpBackAddr = g_inline_hook_entry[INLINE_ENUM_COPY_IO].ori_func_addr + TRAMPOLINE_SIZE;
    
    //unlock
    //lck_mtx_unlock(g_copy_io_mutext);
    
    
    //call target function
    kr = ((fn_copy_io_t )inlined_part_copy_io)(copy_io_ARGS_List);
    if(kr )
    {//target call fail
        goto _exit;
    }
    if(!(user_addr<0x8000000000000000
         && kernel_addr
         && ((uint64_t)kernel_addr & 0xffffff0000000000)==0xffffff0000000000
         && nbytes
         ))
    {
        goto _exit;
    }

    
    //lock
    lck_mtx_lock(g_copy_io_mutext);
    
    boolean_t bMatchStack = false;
    boolean_t bWhiteBypass = true;
    boolean_t bFuzzBlack = false;
    boolean_t bFuzzed = false;
    g_copy_io_fuzz_sample_info_counter++;
    g_copy_io_fuzz_sample_info_index++;
    //zero it
    memset(&(g_copy_io_fuzz_sample_info[g_copy_io_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), 0, sizeof(g_copy_io_fuzz_sample_info[0]));
    
    //Copy_copy_io_all(copy_io_ARGS_List, &(g_copy_io_fuzz_sample_info[g_copy_io_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), ORDER_ENTRY);

    //Check special stacks
    bMatchStack = matchFrameStack(stack_matcher_for_copyio, stack_matcher_size_for_copyio);
    if (!bMatchStack)
    {
        goto _original;
    }
    //Check info leak here
    is_info_leak_within_copyio(copy_io_ARGS_List);
    

#if 1
    if (!(copy_type == 0))
        //Check copyin
    {
        goto _original;
    }
_WHITE_CHECK:
    //White list check
    bWhiteBypass = true;
    bWhiteBypass = should_bypass_within_copy_io(&g_copy_io_fuzz_sample_info[g_copy_io_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]);
    if (bWhiteBypass)
    {
        goto _original;
    }
    //#endif
    
_BLACK_CHECK:
    //Black listing
    bFuzzBlack = false;
    bFuzzBlack  = should_fuzz_within_copy_io(&g_copy_io_fuzz_sample_info[g_copy_io_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]);
    
    if (!bFuzzBlack)
    {
        goto _original;
    }
    
    //print_memory(kernel_addr, nbytes);
    
    //Fuzz here
   if (_maybe(100000,9,17))
    {
        uint32_t uLen = nbytes;
        char * pBuf = kernel_addr;
        if (uLen>=1 )
        {
            //__asm__ volatile ("int3");
            _flip_N_byte_if_fuzzing(pBuf, uLen, INLINE_ENUM_COPY_IO,
                                    1000,3,17,1,7);
            bFuzzed = true;
        }
    
    }
#endif 
    //Call original
_original:
    Copy_copy_io_all(copy_io_ARGS_List, &(g_copy_io_fuzz_sample_info[g_copy_io_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), ORDER_EXIT);
    if (!bFuzzed)
    {
        g_copy_io_fuzz_sample_info_index--;
    }
    
_unlock_exit:
    
    //unlock
    lck_mtx_unlock(g_copy_io_mutext);
    
_exit:
    
    
    return kr;
    
}

///////////////trampline_copy_io_without_lock
kern_return_t trampline_copy_io_without_lock(copy_io_ARGS)
{
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    
    kern_return_t kr = 0;
    //copy_io_fuzz_sample_info_t nowArgStruct={0};
    s_copy_io_JmpBackAddr = g_inline_hook_entry[INLINE_ENUM_COPY_IO].ori_func_addr + TRAMPOLINE_SIZE;
    //call target function
    kr = ((fn_copy_io_t )inlined_part_copy_io)(copy_io_ARGS_List);
    if(kr )
    {//target call fail
        goto _exit;
    }
    //Check user and kernel address valid
    if(!( user_addr<0x8000000000000000
         && kernel_addr
         && ((uint64_t)kernel_addr & 0xffffff0000000000)==0xffffff0000000000
         && nbytes
         )
       )
    {
        goto _exit;
    }
   
    boolean_t bMatchStack = false;
    boolean_t bWhiteBypass = true;
    boolean_t bFuzzBlack = false;
    boolean_t bFuzzed = false;

    //Check special stacks
    bMatchStack = matchFrameStack(stack_matcher_for_copyio, stack_matcher_size_for_copyio);
    if (!bMatchStack)
    {
        goto _original;
    }

    //Check info leak first
    is_info_leak_within_copyio(copy_io_ARGS_List);
    
    //copy_in check for fuzzing user data of copyin
    if (!(copy_type == 0 ))
    {
        goto _exit;
    }
    //Copy_copy_io_all(copy_io_ARGS_List, &(nowArgStruct), ORDER_EXIT);
_WHITE_CHECK:
    //White list check
    bWhiteBypass = true;
    bWhiteBypass = _should_bypass_within_copy_io(copy_io_ARGS_List);
    if (bWhiteBypass)
    {
        goto _original;
    }
    //#endif
    
_BLACK_CHECK:
    //Black listing
    //bFuzzBlack = false;
    //bFuzzBlack  = _should_fuzz_within_copy_io(copy_io_ARGS_List);
    
    //if (!bFuzzBlack)
    //{
    //    goto _original;
    //}

    //Fuzz here
    if (_maybe(1234567,11,29))
    {
        uint32_t uLen = nbytes;
        char * pBuf = kernel_addr;
        if (uLen>=1 )
        {
            //__asm__ volatile ("int3");
            _flip_N_byte_if_fuzzing(pBuf, uLen, INLINE_ENUM_COPY_IO,
                                    1000,3,27,1,3);
            bFuzzed = true;
        }
        
    }
    
    //Call original
_original:
_exit:
    
    return kr;
    
}


/*
 (lldb) dis -n copyio
 kernel.development`copyio:
 0xffffff800a7906d0 <+0>:   pushq  %rbp
 0xffffff800a7906d1 <+1>:   movq   %rsp, %rbp
 0xffffff800a7906d4 <+4>:   pushq  %r15
 0xffffff800a7906d6 <+6>:   pushq  %r14
 0xffffff800a7906d8 <+8>:   pushq  %r13
 0xffffff800a7906da <+10>:  pushq  %r12
 0xffffff800a7906dc <+12>:  pushq  %rbx
 
 */

__attribute__ ((naked)) void inlined_part_copy_io()
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
                      :"m" (s_copy_io_JmpBackAddr)
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







