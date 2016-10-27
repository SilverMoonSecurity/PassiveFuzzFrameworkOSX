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
#include "createMappingInTask_trampline.h"
#include "StackTrace.h"
#include "Mutext.h"
#include "createMappingInTask_noise_filter.h"
#include "kernel_IOUserClient.h"
#include "StackTrace.h"

//////////////Trampline Global variable zone
extern stack_match_item_t stack_matcher_for_createMappingInTask[];
extern uint32_t stack_matcher_size_for_createMappingInTask;
extern struct kernel_info g_kernel_info;
lck_mtx_t *g_createMappingInTask_fuzz_sample_info_mutext=NULL;
lck_grp_t *g_createMappingInTask_fuzz_sample_info_mutext_group=NULL;
createMappingInTask_fuzz_sample_info_t g_createMappingInTask_fuzz_sample_info[MAX_FUZZ_SAMPLE_INFO_CNT] = {0};
uint64_t g_createMappingInTask_fuzz_sample_info_index = 0;
uint64_t g_createMappingInTask_fuzz_sample_info_counter = 0;
//////////////Trampline function zone
//For mac 10.11.2 2015-12-14

kern_return_t init_mutext_for_createMappingInTask()
{
    return init_mutex(&g_createMappingInTask_fuzz_sample_info_mutext, &g_createMappingInTask_fuzz_sample_info_mutext_group, "g_createMappingInTask_fuzz_sample_info_mutext");
}

kern_return_t un_init_mutext_for_createMappingInTask()
{
	return  un_init_mutex(&g_createMappingInTask_fuzz_sample_info_mutext, &g_createMappingInTask_fuzz_sample_info_mutext_group);
}


extern inline_hook_entry_t g_inline_hook_entry[];
typedef uint64_t * (* fn_createMappingInTask_t)
(
    createMappingInTask_ARGS
 );
 

kern_return_t Prepare_createMappingInTask_env(createMappingInTask_ARGS, createMappingInTask_fuzz_sample_info_t *pSampleInfo)
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
    pSampleInfo->env.uCounter = g_createMappingInTask_fuzz_sample_info_counter;
    //Get index
    pSampleInfo->env.uIndex =  g_createMappingInTask_fuzz_sample_info_index;
    if (pProc)
        proc_rele(pProc);
    
    return kr;
}


kern_return_t Copy_createMappingInTask_all (createMappingInTask_ARGS,
    createMappingInTask_fuzz_sample_info_t *pSampleInfo, ENUM_ORDER_T order)
{

    kern_return_t  kr =0;
    char bufLog[0x200]={0};
    __asm__ volatile ("nop");
    Prepare_createMappingInTask_env(createMappingInTask_ARGS_VAR_LIST, pSampleInfo);
   

    if (ORDER_ENTRY == order )
    {
        pSampleInfo->original.entry.atAddress = atAddress;
        pSampleInfo->original.entry.intoTask = intoTask;
        pSampleInfo->original.entry.length = length;
        pSampleInfo->original.entry.offset = offset;
        pSampleInfo->original.entry.options = options;
    }
    
    if (ORDER_EXIT == order )
    {
        pSampleInfo->now.entry.atAddress = atAddress;
        pSampleInfo->now.entry.intoTask = intoTask;
        pSampleInfo->now.entry.length = length;
        pSampleInfo->now.entry.offset = offset;
        pSampleInfo->now.entry.options = options;
    }
 
    return kr;
}



uint64_t s_createMappingInTask_JmpBackAddr = -1;
uint64_t trampline_createMappingInTask(createMappingInTask_ARGS)
{
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    mach_vm_address_t *krResult = 0;
    boolean_t bWhiteBypass = true;
	boolean_t bFuzzBlack = false;
    boolean_t bFuzzed = false;
    boolean_t bMatchStack = false;
    s_createMappingInTask_JmpBackAddr = g_inline_hook_entry[INLINE_ENUM_CREATE_MAPPING_IN_TASK].ori_func_addr + TRAMPOLINE_SIZE;
    //__asm__ volatile ("int3");
    krResult = ((fn_createMappingInTask_t )inlined_part_createMappingInTask)(createMappingInTask_ARGS_VAR_LIST);
    
    //Begin lock
    lck_mtx_lock(g_createMappingInTask_fuzz_sample_info_mutext);
    g_createMappingInTask_fuzz_sample_info_counter++;
	g_createMappingInTask_fuzz_sample_info_index++;
    //zero it
    memset(&(g_createMappingInTask_fuzz_sample_info[g_createMappingInTask_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), 0, sizeof(g_createMappingInTask_fuzz_sample_info[0]));
    
    Copy_createMappingInTask_all(createMappingInTask_ARGS_VAR_LIST, &(g_createMappingInTask_fuzz_sample_info[g_createMappingInTask_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), ORDER_ENTRY);
    
    //Check special stacks
    bMatchStack = matchFrameStack(stack_matcher_for_createMappingInTask, stack_matcher_size_for_createMappingInTask);
    if (!bMatchStack)
    {
        goto _original;
    }
    
  _WHITE_CHECK:
    //White list check
    bWhiteBypass = true;
    bWhiteBypass = should_bypass_within_createMappingInTask(&g_createMappingInTask_fuzz_sample_info[g_createMappingInTask_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]);
    if (bWhiteBypass)
    {
        goto _original;
    }
//#endif

_BLACK_CHECK:
    //Black listing
    bFuzzBlack = false;
    bFuzzBlack  = should_fuzz_within_createMappingInTask(&g_createMappingInTask_fuzz_sample_info[g_createMappingInTask_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]);

    if (!bFuzzBlack)
    {
        goto _original;
    }
    //Fuzz here
    uint32_t uLen = 0;
    uint32_t uLenFuzzed = 1;
    char * pBuf = 0;
    
    mach_vm_address_t *mapAddr = 0;
    mach_vm_address_t virtualAddrMap = 0;
    uint64_t uLengthMap = 0;
    mapAddr = krResult;
    if (_maybe(1000,100,900) && (((uint64_t)mapAddr)&0xffffff0000000000==0xffffff0000000000))
    {
        virtualAddrMap = getVirtualAddressFromIOMapMemory(mapAddr);
        uLengthMap = getLengthFromIOMapMemory(mapAddr);
        if (is_address_range_readable(virtualAddrMap, uLengthMap) &&
        is_address_range_writeable(virtualAddrMap, uLengthMap))
        {
            if (uLengthMap && (
                uLengthMap<1024*4
                || uLengthMap<1024*4*1 && uLengthMap<1024*4*2
                //|| uLengthMap<1024*4*5&&uLengthMap<1024*4*10
                               )
                )
            {
                //Kernel mode address
                if ((0xf000000000000000 & virtualAddrMap) == 0xf000000000000000)
                {
                    uLen = uLengthMap;
                    if (uLen>1024)
                    {
                        //Fuzz the first 1024 bytes at most
                        uLen = 1024;
                    }
                    _flip_N_byte_if_fuzzing(virtualAddrMap, uLen,
                                       INLINE_ENUM_CREATE_MAPPING_IN_TASK,
                                            100,5,20,3,7);
                }
 
            }
        }

    }
 
    
    //Call original
_original:
    Copy_createMappingInTask_all(createMappingInTask_ARGS_VAR_LIST, &(g_createMappingInTask_fuzz_sample_info[g_createMappingInTask_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), ORDER_EXIT);
    if (!bFuzzed)
	{
		g_createMappingInTask_fuzz_sample_info_index--;
	}
    lck_mtx_unlock(g_createMappingInTask_fuzz_sample_info_mutext);

    return krResult;

}

/*
(lldb) dis -n IOMemoryDescriptor::createMappingInTask
kernel.development`IOMemoryDescriptor::createMappingInTask:
    0xffffff8017ea1410 <+0>:   pushq  %rbp
    0xffffff8017ea1411 <+1>:   movq   %rsp, %rbp
    0xffffff8017ea1414 <+4>:   pushq  %r15
    0xffffff8017ea1416 <+6>:   pushq  %r14
    0xffffff8017ea1418 <+8>:   pushq  %r13
    0xffffff8017ea141a <+10>:  pushq  %r12
    0xffffff8017ea141c <+12>:  pushq  %rbx

*/
 
 
__attribute__ ((naked)) uint64_t *inlined_part_createMappingInTask()
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
                      :"m" (s_createMappingInTask_JmpBackAddr)
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
