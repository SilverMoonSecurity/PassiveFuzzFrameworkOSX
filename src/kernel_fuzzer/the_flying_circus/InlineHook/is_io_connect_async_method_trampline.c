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
#include "is_io_connect_async_method_trampline.h"
#include "Mutext.h"
//////////////Trampline Global variable zone
uint64_t g_is_io_connect_async_method_counter = 0;
lck_mtx_t *g_is_io_connect_async_method_fuzz_sample_info_mutext=NULL;
lck_grp_t *g_is_io_connect_async_method_fuzz_sample_info_mutext_group=NULL;
is_io_connect_async_method_fuzz_sample_info_t g_is_io_connect_async_method_fuzz_sample_info[MAX_PROCESSER_CNT][0x1] = {0};

kern_return_t init_mutext_is_io_connect_async_method_for_fuzz_sample()
{
	return init_mutex(&g_is_io_connect_async_method_fuzz_sample_info_mutext, 
	&g_is_io_connect_async_method_fuzz_sample_info_mutext_group,
	"g_is_io_connect_async_method_fuzz_sample_info_mutext");
}

kern_return_t un_init_mutext_is_io_connect_async_method_for_fuzz_sample()
{
   	return un_init_mutex(&g_is_io_connect_async_method_fuzz_sample_info_mutext, 
	&g_is_io_connect_async_method_fuzz_sample_info_mutext_group);
}

//////////////Trampline function zone
//For mac 10.11.1.x 2015-09-22


extern inline_hook_entry_t g_inline_hook_entry[];
typedef kern_return_t (* fn_is_io_connect_async_method_t)
(
IS_IO_CONNECT_ASYNC_METHOD_ARGS
 );


kern_return_t Copy_is_io_connnect_async_method_args (IS_IO_CONNECT_ASYNC_METHOD_ARGS, is_io_connect_async_method_t *pEntry)
{
    kern_return_t kr = 0;
    pEntry->connection = connection;
    pEntry->selector = selector;
    //inband_input
    pEntry->inband_inputCnt = inband_inputCnt;
    
    //__asm__ volatile ("int3");
    unsigned  int uInband_input_len = sizeof(io_struct_inband_t);
    if (inband_inputCnt < uInband_input_len)
    {
        uInband_input_len = inband_inputCnt;
    }
	if (inband_input && uInband_input_len)
	{
		memcpy(pEntry->inband_input, inband_input, uInband_input_len);
	}
    //pEntry->inband_input_addr_of_stack = &inband_input;
    pEntry->inband_input_addr_of_global = (pEntry->inband_input);
    pEntry->inband_input_addr_of_stack = inband_input;
    
    //scalar_input
    pEntry->scalar_inputCnt = scalar_inputCnt;
    unsigned  int uScalar_input_len = sizeof(io_scalar_inband64_t);
    if (scalar_inputCnt*sizeof(uint64_t) < uScalar_input_len)
    {
        uScalar_input_len = scalar_inputCnt*sizeof(uint64_t);
    }
	if (scalar_input && uScalar_input_len)
	{
		memcpy(pEntry->scalar_input, scalar_input, uScalar_input_len);
	}
    pEntry->scalar_input_addr_of_global = (pEntry->scalar_input);
    pEntry->scalar_input_addr_of_stack = scalar_input;
    
    //ool_input
    pEntry->ool_input_size = ool_input_size;
    pEntry->ool_input = ool_input;
    pEntry->ool_input_addr_of_global = (pEntry->ool_input);
    pEntry->ool_input_addr_of_stack = ool_input;
  
    return kr;
}

kern_return_t Prepare_is_io_connect_async_method_env(IS_IO_CONNECT_ASYNC_METHOD_ARGS, is_io_connect_async_method_fuzz_sample_info_t *pSampleInfo)
{
     kern_return_t kr = 0;
    proc_t pProc = 0;
    //Set Counter
    pSampleInfo->env.uCounter = g_is_io_connect_async_method_counter;
    //Get Connection info
    pSampleInfo->env.connection = connection;
    //Get Class Name
    k_is_io_object_get_class(connection, pSampleInfo->env.szClassName);
    
    //Get service info
    /*
    k_is_io_connect_get_service(pSampleInfo->original.entry.connection,
                                &(pSampleInfo->env.service));
    get_serivce_name_of_connection(pSampleInfo->original.entry.connection,
                                   pSampleInfo->env.szServiceClassName);
     /**/
    
    //Get proc name
    pid_t pid = 0;
    pid = proc_pid(pProc = proc_self());
    char path [PATH_MAX+1] = {0};
    proc_name(pid, path,PATH_MAX);
    path[PATH_MAX] = '\0';
    strncpy(pSampleInfo->env.szProcName, path, PATH_MAX);
    
    //Get processer id
    pSampleInfo->env.uCpuNo = CURRENT_PROCESSER_ID_NOW;
    
   
    if (pProc)
    {
        proc_rele(pProc);
    }
    
    return kr;
}


kern_return_t Copy_is_io_connect_async_method_all (IS_IO_CONNECT_ASYNC_METHOD_ARGS,
    is_io_connect_async_method_fuzz_sample_info_t *pSampleInfo, ENUM_ORDER_T order)
{

    kern_return_t  kr =0;

    char bufLog[0x200]={0};
    __asm__ volatile ("nop");
    Prepare_is_io_connect_async_method_env(IS_IO_CONNECT_ASYNC_METHOD_ARGS_VAR_LIST, pSampleInfo);
	Copy_is_io_connnect_async_method_args(IS_IO_CONNECT_ASYNC_METHOD_ARGS_VAR_LIST, pSampleInfo);
    if (ORDER_ENTRY == order )
    {
        //pSampleInfo->original.entry = *(is_io_connect_async_method_t *)args;
    }
    
    if (ORDER_EXIT == order )
    {
        //pSampleInfo->now.entry = *(is_io_connect_async_method_t *)args;
    }
    //snprintf(bufLog, sizeof(bufLog), "\r\n Copy_is_io_connect_async_method_all %d", s_LogCounter++);
    //kernel_print_log(bufLog);
    return kr;
}

uint64_t g_current_cr4=0;
uint64_t s_is_io_connect_async_method_JmpBackAddr = -1;
kern_return_t trampline_is_io_connect_async_method(IS_IO_CONNECT_ASYNC_METHOD_ARGS)
{
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
	kern_return_t kr = 0;
	boolean_t bWhiteBypass = true;
	boolean_t bFuzzBlack = false;
	boolean_t bMaybe = false;
	boolean_t bFuzzedInband = false;
	boolean_t bFuzzedScalar = false;
	boolean_t bFuzzedOOl = false;
	uint32_t uLen = 1;
	

    
	//Begin Lock
    lck_mtx_lock(g_is_io_connect_async_method_fuzz_sample_info_mutext);
    s_is_io_connect_async_method_JmpBackAddr = g_inline_hook_entry[INLINE_ENUM_IS_IO_CONNECT_ASYNC_METHOD].ori_func_addr + TRAMPOLINE_SIZE ;
    //zero it
    memset(&(g_is_io_connect_async_method_fuzz_sample_info[CURRENT_PROCESSER_ID][0]), 0, sizeof(g_is_io_connect_async_method_fuzz_sample_info[0]));
     
     //record original sample info
    strcpy(g_is_io_connect_async_method_fuzz_sample_info[CURRENT_PROCESSER_ID][0].fuzzTag, "_is_io_connect_method_flyic_moony_fuzz");
    strncpy(g_is_io_connect_async_method_fuzz_sample_info[CURRENT_PROCESSER_ID][0].recordReproducedName, RECORD_PRODUCE_FILE_FOR_IS_IO_CONNECT_METHOD , PATH_MAX);
 
    Copy_is_io_connect_async_method_all(IS_IO_CONNECT_ASYNC_METHOD_ARGS_VAR_LIST, &(g_is_io_connect_async_method_fuzz_sample_info[CURRENT_PROCESSER_ID][0]), ORDER_ENTRY);
    
    //goto _original;
    //Fuzz here
    #if 1
	bWhiteBypass = true;
    bFuzzBlack = false;
    bMaybe = false;
    bFuzzedInband = false;
    bFuzzedScalar = false;
    bFuzzedOOl = false;
    g_is_io_connect_async_method_counter++;


    bFuzzBlack = true;//
_WHITE_CHECK:
    //White list check
    bWhiteBypass = true;
    bWhiteBypass = should_bypass_within_is_io_connect_method(&g_is_io_connect_async_method_fuzz_sample_info[CURRENT_PROCESSER_ID][0]);
    if (bWhiteBypass)
    {
        //memset(&(g_is_io_connect_async_method_fuzz_sample_info[CURRENT_PROCESSER_ID][0]), 0, sizeof(g_is_io_connect_async_method_fuzz_sample_info));
        //__asm__ volatile ("int3");
        goto _original;
    }
//#endif

_BLACK_CHECK:
    //Black listing
    bFuzzBlack = false;
    bFuzzBlack  = should_fuzz_within_is_io_connect_method(&g_is_io_connect_async_method_fuzz_sample_info[CURRENT_PROCESSER_ID][0]);


    if (!bFuzzBlack)
    {
        //memset(&(g_is_io_connect_async_method_fuzz_sample_info[CURRENT_PROCESSER_ID][0]), 0, sizeof(g_is_io_connect_async_method_fuzz_sample_info));
        //__asm__ volatile ("int3");
        goto _original;
    }


_FUZZ_INPUT:
    //Fuzz buf
    if (bMaybe = maybe() )
    {
        uLen = 1;

        if (bFuzzBlack)
        {
            //Fuzz Inband input
            uint64_t uInband_input_len = sizeof(io_struct_inband_t);
            if (inband_inputCnt < uInband_input_len)
            {
                uInband_input_len = inband_inputCnt;
            }
            if (uInband_input_len && inband_input)
            {
                //moony_modify//printf("[DEBUG] trampline_is_io_connect_method fuzzing inband_input(0x%llx)\r\n",inband_input);
                //flip_byte(inband_input, uInband_input_len);
                //flip_bit(inband_input, uInband_input_len);
                //__asm__ volatile ("int3");
      

                flip_N_byte_if_fuzzing(inband_input, uInband_input_len, INLINE_ENUM_IS_IO_CONNECT_ASYNC_METHOD);
                
                {
                    bFuzzedInband = true;
                }
                
            }
            
            //Fuzz Scalar input
            uint64_t uScalar_input_len = scalar_inputCnt* sizeof(uint64_t);
            if (sizeof(io_scalar_inband64_t)< uScalar_input_len)
            {
                uScalar_input_len = sizeof(io_scalar_inband64_t);
            }
            if (uScalar_input_len && scalar_input)
            {
                //moony_modify//printf("[DEBUG] trampline_is_io_connect_method fuzzing scalar_input(0x%llx)\r\n",scalar_input);
          
                flip_N_byte_if_fuzzing(scalar_input, uScalar_input_len, INLINE_ENUM_IS_IO_CONNECT_ASYNC_METHOD);
                
                {
                    bFuzzedScalar = true;
                }


            }

            
            if (bFuzzedScalar && bFuzzedInband)
            {

            }
            
        }// end of fuzz black

        
    }
    //end of maybe()
    
    
    //Call original

_done:
   #endif
_original:
	Copy_is_io_connect_async_method_all(IS_IO_CONNECT_ASYNC_METHOD_ARGS_VAR_LIST, &(g_is_io_connect_async_method_fuzz_sample_info[CURRENT_PROCESSER_ID][0]), ORDER_EXIT);
	//End mutex
	lck_mtx_unlock(g_is_io_connect_async_method_fuzz_sample_info_mutext);
    kr = ((fn_is_io_connect_async_method_t )inlined_part_is_io_connect_async_method)(IS_IO_CONNECT_ASYNC_METHOD_ARGS_VAR_LIST);
EXIT:
    return kr;

}

/*
(lldb) dis -n is_io_connect_async_method
kernel.development`is_io_connect_async_method:
    0xffffff8004abb980 <+0>:   pushq  %rbp
    0xffffff8004abb981 <+1>:   movq   %rsp, %rbp
    0xffffff8004abb984 <+4>:   pushq  %r15
    0xffffff8004abb986 <+6>:   pushq  %r14
    0xffffff8004abb988 <+8>:   pushq  %r13
    0xffffff8004abb98a <+10>:  pushq  %r12
    0xffffff8004abb98c <+12>:  pushq  %rbx

*/
 
 
__attribute__ ((naked)) void inlined_part_is_io_connect_async_method(IS_IO_CONNECT_ASYNC_METHOD_ARGS)
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
                      :"m" (s_is_io_connect_async_method_JmpBackAddr)
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


