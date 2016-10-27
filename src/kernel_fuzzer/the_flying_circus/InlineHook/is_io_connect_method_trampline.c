//@Flyic
//moony_li@trendmicro.com
#include "is_io_connect_method_trampline.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/attr.h>


#include "proc.h"
#include "sysent.h"
#include "my_data_definitions.h"
#include "kernel_info.h"
#include "function_pointers.h"
#include "path_utils.h"
#include "fuzz_method.h"
#include "inline_hook.h"
#include "record_reproduce.h"
#include "Mutext.h"
#include "is_io_connect_method_noise_filter.h"
#include "is_io_connect_method_info_leak_check.h"

extern inline_hook_entry_t g_inline_hook_entry[];
uint64_t g_is_io_connect_method_counter = 0;
lck_mtx_t *g_fuzz_sample_info_mutext=NULL;
lck_grp_t *g_fuzz_sample_info_mutext_group=NULL;
fuzz_sample_info_t g_fuzz_sample_info[MAX_FUZZ_SAMPLE_INFO_CNT] = {0};
uint64_t g_fuzz_sample_info_index = 0;

service_open_connection_table_t g_service_open_connection_table[MAX_PROCESSER_CNT]={0};
kern_return_t init_mutext_for_fuzz_sample()
{
    return init_mutex(&g_fuzz_sample_info_mutext, &g_fuzz_sample_info_mutext_group, "g_fuzz_sample_info_mutext");
}

kern_return_t un_init_mutext_for_fuzz_sample()
{
	return  un_init_mutex(&g_fuzz_sample_info_mutext, &g_fuzz_sample_info_mutext_group);
}

//////////////Trampline Global variable zone


//////////////Trampline function zone
//For mac 10.10.x 2015-08-27




///*NDR_record_t ndr,\*/

typedef kern_return_t (* fn_is_io_service_open_extended_t)
(
 IS_IO_SERVICE_OPEN_EXTENDED_ARGS
 );


/*
 #define IS_IO_SERVICE_OPEN_EXTENDED_ARGS   \
 io_object_t _service,\
 task_t owningTask,\
 uint32_t connect_type,\
 NDR_record_t ndr,\
 io_buf_ptr_t properties,\
 mach_msg_type_number_t propertiesCnt,\
 kern_return_t *result,\
 io_object_t *connection
 */
kern_return_t Copy_is_io_service_open_extended (IS_IO_SERVICE_OPEN_EXTENDED_ARGS)
{
    kern_return_t  kr =0;
    __asm__ volatile ("nop");
    uint32_t index =0;
    service_open_connection_entry_t *pTable= NULL;
    index = g_service_open_connection_table[CURRENT_PROCESSER_ID].uCurrentIndex;
    //__asm__ volatile ("int3");
    pTable = g_service_open_connection_table[CURRENT_PROCESSER_ID].table;
    pTable[index].connection = 0;//(is_address_readable(connection))? *connection:NULL;
    pTable[index].nType = connect_type;
    pTable[index].service = _service;
    if (connection && is_address_readable(connection))
    {
        pTable[index].connection = *connection;
        k_is_io_object_get_class(*connection, pTable[index].szConnectionClassName );
    }
    k_is_io_object_get_class(_service, pTable[index].szServiceClassName);
    g_service_open_connection_table[CURRENT_PROCESSER_ID].uCurrentIndex=(index+1)%SERVICE_CONNECTION_TABLE_MAX;
    return kr;
}

uint64_t s_is_io_service_open_extended_JmpBackAddr = -1;
kern_return_t trampline_is_io_service_open_extended (IS_IO_SERVICE_OPEN_EXTENDED_ARGS)
{
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    kern_return_t kr = 0;
    
    s_is_io_service_open_extended_JmpBackAddr = g_inline_hook_entry[INLINE_ENUM_IS_IO_SERVICE_OPEN_EXTENDED].ori_func_addr + TRAMPOLINE_SIZE;

_original:
    kr = ((fn_is_io_service_open_extended_t )inlined_part_is_io_service_open_extended)(IS_IO_SERVICE_OPEN_EXTENDED_VAR_LIST_FIXED);
_original_done:
   Copy_is_io_service_open_extended(IS_IO_SERVICE_OPEN_EXTENDED_VAR_LIST_FIXED);
EXIT:
    return kr;

}

/*
 kernel.development`is_io_service_open_extended:
 0xffffff800e0e12a0 <+0>:   pushq  %rbp
 0xffffff800e0e12a1 <+1>:   movq   %rsp, %rbp
 0xffffff800e0e12a4 <+4>:   pushq  %r15
 0xffffff800e0e12a6 <+6>:   pushq  %r14
 0xffffff800e0e12a8 <+8>:   pushq  %r13
 0xffffff800e0e12aa <+10>:  pushq  %r12
 0xffffff800e0e12ac <+12>:  pushq  %rbx
 0xffffff800e0e12ad <+13>:  subq   $0x38, %rsp
 0xffffff800e0e12b1 <+17>:  movl   %r9d, %r12d
 0xffffff800e0e12b4 <+20>:  movq   %r8, %r14
 0xffffff800e0e12b7 <+23>:  movq   %rcx, %r13
 0xffffff800e0e12ba <+26>:  movq   %rdi, %rbx
 */
__attribute__ ((naked)) void inlined_part_is_io_service_open_extended()
{
    __asm__ volatile (
                      "  push %rbp\n"
                      "  mov %rsp, %rbp\n"
                      "  push %r15\n"
                      "  push %r14\n"
                      "  push %r13\n"
                      "  push %r12\n"
                      //"  push %rbx\n"
                      //"  sub $0x108, %rsp"
                      );
    __asm__ volatile (
                      "  jmp *%0\n"
                      //"  mov %%rax, %0"
                      :
                      :"m" (s_is_io_service_open_extended_JmpBackAddr)
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

//////////////Trampline function zone  for trampline_is_io_connect_method//////////////////////
//For mac 10.10.x 2015-06-17



static uint32_t s_LogCounter =0;
kern_return_t Copy_is_io_connnect_method_all (IS_IO_CONNECT_METHOD_ARGS, is_io_connect_method_t *pEntry, fuzz_sample_info_t *pSampleInfo, ENUM_ORDER_T order, boolean_t bWhiteBypass , boolean_t bFuzzBlack)
{
    
    kern_return_t kr = 0;
    Copy_is_io_connnect_method_args(IS_IO_CONNECT_METHOD_ARGS_VAR_LIST, pEntry);
    Prepare_is_io_connnect_method_env(IS_IO_CONNECT_METHOD_ARGS_VAR_LIST, pSampleInfo);
    
    strncpy(pEntry->szClassName, pSampleInfo->env.szClassName, PATH_MAX);
    strncpy(pEntry->szProcName, pSampleInfo->env.szProcName, PATH_MAX);
    if (!bWhiteBypass && bFuzzBlack)
    {
        char bufLog[0x300]={""};
        snprintf(bufLog, sizeof(bufLog), "\r\n moony_Copy_is_io_connnect_method_all:[%d], proc=[%s], class=[%s], sel=[0x%llx]",
                 s_LogCounter++,
                 pSampleInfo->env.szProcName,
                 pSampleInfo->env.szClassName,
                 pSampleInfo->original.entry.selector);

    }
    return kr;
}


kern_return_t Prepare_is_io_connnect_method_env(IS_IO_CONNECT_METHOD_ARGS, fuzz_sample_info_t *pSampleInfo)
{
     kern_return_t kr = 0;
    proc_t pProc = 0;
    //Get proc
    pSampleInfo->env.proc = current_proc();
    //Get thread
    pSampleInfo->env.thread = current_thread();
    //Set Counter
    pSampleInfo->env.uCounter = g_is_io_connect_method_counter;
    //Set Index
    pSampleInfo->env.uIndex = g_fuzz_sample_info_index;
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
kern_return_t Copy_is_io_connnect_method_args (IS_IO_CONNECT_METHOD_ARGS, is_io_connect_method_t *pEntry)
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
    /*
    //inband_output
    //pEntry->inband_outputCnt = inband_outputCnt;//Differs 
    unsigned  int uInband_ouput_len = sizeof(io_struct_inband_t);
    if (!inband_outputCnt)
	{
		uInband_ouput_len=0;
		
	}
	else if(*inband_outputCnt < uInband_ouput_len)
    {
        uInband_ouput_len = *inband_outputCnt;
    }
	pEntry->inband_outputCnt = uInband_ouput_len;
    memcpy(pEntry->inband_output, inband_output, uInband_ouput_len);
    //pEntry->inband_output_addr_of_stack = &inband_output;
    pEntry->inband_output_addr_of_global = (pEntry->inband_output);
    pEntry->inband_output_addr_of_stack = (inband_output);
    
    //scalar_output
    //pEntry->scalar_outputCnt = scalar_outputCnt;  //Differs
    unsigned  int uScalar_ouput_len = sizeof(io_scalar_inband64_t);
    if (!scalar_outputCnt)
	{
		uScalar_ouput_len=0;
	}
	else if((*scalar_outputCnt)*sizeof(scalar_output[0]) < uScalar_ouput_len)
    {
        uScalar_ouput_len = (*scalar_outputCnt)*sizeof(scalar_output[0]);
    }
	pEntry->scalar_outputCnt = uScalar_ouput_len;
    memcpy(pEntry->scalar_output, scalar_output, uScalar_ouput_len);
    pEntry->scalar_output_addr_of_global = (pEntry->scalar_output);
    pEntry->scalar_output_addr_of_stack = (scalar_output);
    
    //ool_output
    //pEntry->ool_output_size = ool_output_size; //Differs
	unsigned int uOol_output_len = 0;
	if (ool_output_size)
	{
		uOol_output_len = *ool_output_size;
	}
	pEntry->ool_output_size = uOol_output_len;
    pEntry->ool_output = ool_output;
    pEntry->ool_output_addr_of_global = (pEntry->ool_output);
    pEntry->ool_output_addr_of_stack = (ool_output);
    */
    
    return kr;
}

kern_return_t Check_Fuzz_Changed_is_io_connnect_method (fuzz_sample_info_t *pSampleInfo)
{
    if(pSampleInfo->original.entry.connection != pSampleInfo->now.entry.connection)
    {
        pSampleInfo->changed.bConnection = true;
    }
    if(pSampleInfo->original.entry.selector != pSampleInfo->now.entry.selector)
    {
        pSampleInfo->changed.bSelector = true;
    }
  
    //inband intput
    if (pSampleInfo->original.entry.inband_inputCnt != pSampleInfo->now.entry.inband_inputCnt)
    {
        pSampleInfo->changed.bInband_inputCnt = true;
    }
	
	unsigned uInband_input_len = sizeof(io_struct_inband_t);
	if (pSampleInfo->original.entry.inband_inputCnt < uInband_input_len)
	{
		uInband_input_len = pSampleInfo->original.entry.inband_inputCnt;
	}
	
    if (memcmp(
               pSampleInfo->original.entry.inband_input,
               pSampleInfo->now.entry.inband_input,
               uInband_input_len))
    {
        pSampleInfo->changed.bInband_input = true;
    }
	

    //Scalar input
    if (pSampleInfo->original.entry.scalar_inputCnt != pSampleInfo->now.entry.scalar_inputCnt)
    {
        pSampleInfo->changed.bScalar_inputCnt = true;
    }
	unsigned uScalar_input_len = sizeof(io_scalar_inband64_t);
	if (pSampleInfo->original.entry.scalar_inputCnt*sizeof(uint64_t) < uScalar_input_len)
	{
		uScalar_input_len = pSampleInfo->original.entry.scalar_inputCnt*sizeof(uint64_t);
	}
    if (memcmp(
               pSampleInfo->original.entry.scalar_input,
               pSampleInfo->now.entry.scalar_input,
               uScalar_input_len))
    {
        pSampleInfo->changed.bScalar_input = true;
    }
    
    /*
    
    //ool input
    if (pSampleInfo->original.entry.ool_input_size != pSampleInfo->now.entry.ool_input_size)
    {
        pSampleInfo->changed.bOol_input_size = true;
    }
    if (memcmp( pSampleInfo->original.entry.ool_input ,
               pSampleInfo->now.entry.ool_input,
			   pSampleInfo->original.entry.ool_input_size))
    {
        pSampleInfo->changed.bOol_input = true;
    }
    
#if 0
    //inband output
    if (pSampleInfo->original.entry.inband_outputCnt != pSampleInfo->now.entry.inband_outputCnt)
    {
        pSampleInfo->changed.bInband_outputCnt = true;
    }
    if (memcmp(
               pSampleInfo->original.entry.inband_output,
               pSampleInfo->now.entry.inband_output,
               sizeof(pSampleInfo->original.entry.inband_output)))
    {
        pSampleInfo->changed.bInband_output = true;
    }
    
    //Scalar output
    if (pSampleInfo->original.entry.scalar_outputCnt != pSampleInfo->now.entry.scalar_outputCnt)
    {
        pSampleInfo->changed.bScalar_outputCnt = true;
    }
    if ( pSampleInfo->original.entry.scalar_output !=
               pSampleInfo->now.entry.scalar_output)
    {
        pSampleInfo->changed.bScalar_output = true;
    }
   
    
    
    //ool output
    if (pSampleInfo->original.entry.ool_output_size != pSampleInfo->now.entry.ool_output_size)
    {
        pSampleInfo->changed.bOol_output_size = true;
    }
    if (pSampleInfo->original.entry.ool_output !=
        pSampleInfo->now.entry.ool_output)
    {
        pSampleInfo->changed.bOol_output = true;
    }
 #endif    
     */
    
}


/*
kern_return_t kr = 0;
boolean_t bWhiteBypass = true;
boolean_t bFuzzBlack = false;
boolean_t bMaybe = false;
boolean_t bFuzzedInband = false;
boolean_t bFuzzedScalar = false;
boolean_t bFuzzedOOl = false;
uint32_t uLen = 1;
*/

static bool s_b_is_io_connect_method_called_first = false;
static uint64_t s_is_io_connect_method_JmpBackAddr = -1;
//uint64_t g_is_io_connect_method_counter = 0;
/* Routine io_user_client_method */
//__attribute__ ((naked))
kern_return_t trampline_is_io_connect_method (IS_IO_CONNECT_METHOD_ARGS)
//kern_return_t flyic_customized_is_io_connect_method

{
     __asm__ volatile ("nop");
     __asm__ volatile ("nop");
     __asm__ volatile ("nop");
     __asm__ volatile ("nop");
   /////***************************************/////////
    //todo: + inline code size by instruction size instead of TRAMPOLINE_SIZE
    //uJmpBackAddr = g_inline_hook_entry[INLINE_ENUM_IS_IO_CONNECT_METHOD].ori_func_addr + TRAMPOLINE_SIZE;
    //uJmpBackAddr = g_inline_hook_entry[INLINE_ENUM_IS_IO_CONNECT_METHOD].ori_func_addr + 0x14;
    //todo: s_is_io_connect_method_JmpBackAddr should not as local variable
    //uint64_t s_is_io_connect_method_JmpBackAddr = -1;
    
    kern_return_t kr = 0;
    boolean_t bWhiteBypass = true;
    boolean_t bFuzzBlack = false;
    boolean_t bMaybe = false;
    boolean_t bFuzzedInband = false;
    boolean_t bFuzzedScalar = false;
    boolean_t bFuzzedOOl = false;
    uint32_t uLen = 1;
    
    //fuzz_sample_info_t sample_info;
    s_is_io_connect_method_JmpBackAddr = g_inline_hook_entry[INLINE_ENUM_IS_IO_CONNECT_METHOD].ori_func_addr + TRAMPOLINE_SIZE;
    
    ////moony_modify//printf("[DEBUG] #0x%llx: trampline_is_io_connect_method(select(%d))\r\n",s_is_io_connect_method_counter++, selector);
    
    //Begin lock
    lck_mtx_lock(g_fuzz_sample_info_mutext);
    bWhiteBypass = true;
    bFuzzBlack = false;
    bMaybe = false;
    bFuzzedInband = false;
    bFuzzedScalar = false;
    bFuzzedOOl = false;
    if (!s_b_is_io_connect_method_called_first)
    {
        s_b_is_io_connect_method_called_first = true;
        memset(g_fuzz_sample_info, 0, sizeof(g_fuzz_sample_info));
    }
    g_is_io_connect_method_counter++;
    g_fuzz_sample_info_index++;
    //zero it
    memset(&(g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), 0, sizeof(g_fuzz_sample_info[0]));
    //record original sample info
    //strcpy(g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT].fuzzTag, "_is_io_connect_method_flyic_moony_fuzz");
    //strncpy(g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT].recordReproducedName, RECORD_PRODUCE_FILE_FOR_IS_IO_CONNECT_METHOD , PATH_MAX);
    Copy_is_io_connnect_method_all(IS_IO_CONNECT_METHOD_ARGS_VAR_LIST,&(g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT].original.entry), &(g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), ORDER_ENTRY, 0, 0);
    
    
    //moony debug
    //__asm__ volatile ("int3");
    bFuzzBlack = true;//
    //goto _FUZZ_INPUT;
    //goto _FUZZ_DONE;
    ////moony_modify//printf("[DEBUG] Alway go here!\r\n");
//#if 1
_WHITE_CHECK:
    //White list check
    bWhiteBypass = true;
    bWhiteBypass = should_bypass_within_is_io_connect_method(&g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]);
    if (bWhiteBypass)
    {
        //memset(&(g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), 0, sizeof(g_fuzz_sample_info));
        //__asm__ volatile ("int3");
        goto _original;
    }
//#endif

_BLACK_CHECK:
    //Black listing
    bFuzzBlack = false;
    bFuzzBlack  = should_fuzz_within_is_io_connect_method(&g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]);


    if (!bFuzzBlack)
    {
        //memset(&(g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), 0, sizeof(g_fuzz_sample_info));
        //__asm__ volatile ("int3");
        goto _original;
    }


	//__asm__ volatile ("int3");
    //Fuzz here
    ////moony_modify//printf("[DEBUG] Actually I should fuzz here\r\n");
    //goto _original;
    //goto _FUZZ_DONE;
/*
    //Fuzz selector
    if (maybe())
    {
        //moony_modify//printf("[DEBUG] trampline_is_io_connect_method fuzzing selector(0x%llx)\r\n",selector);
        flip_around_int(&selector, 2*selector);
    }
    //Fuzz Cnt
    if (maybe())
    {
        //moony_modify//printf("[DEBUG] trampline_is_io_connect_method fuzzing inband_inputCnt(0x%llx)\r\n",
               inband_inputCnt);
        flip_around_int(&inband_inputCnt, 2*inband_inputCnt);
    }
*/
_FUZZ_INPUT:
    //Fuzz buf
    if (bMaybe = _maybe(9,1,7))
    {


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
                
                _flip_N_byte_if_fuzzing(inband_input, uInband_input_len, INLINE_ENUM_IS_IO_CONNECT_METHOD,100,10,35,1,50);
                    bFuzzedInband = true;
                
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
                {
                    _flip_N_byte_if_fuzzing(scalar_input, uScalar_input_len,INLINE_ENUM_IS_IO_CONNECT_METHOD,100,10,35,1,70);
                    bFuzzedScalar = true;
                }
                
            }


            //Fuzz ool input
            /*
            uint64_t uOol_input_len = ool_input_size;
            if (uOol_input_len && ool_input)
            {
                //moony_modify//printf("[DEBUG] trampline_is_io_connect_method fuzzing ool_input(0x%llx)\r\n",ool_input);
                //_flip_N_byte_if_fuzzing(scalar_input, uScalar_input_len,INLINE_ENUM_IS_IO_CONNECT_METHOD,100,10,25,1,7);
                bFuzzedOOl = true;
                //ool_input seems in user mode
               
            }
            */
            
        }// end of fuzz black

        
    }
    //end of maybe()
    /*
    //Fuzz size
    if (bMaybe = _maybe(9999,1,13))
    {
        
            //Fuzz Inband input size
            inband_inputCnt = rand_num()%sizeof(io_struct_inband_t);
            bFuzzedInband = true;
    }
            
    if (bMaybe = _maybe(9999,1,13))
    {            //Fuzz Scalar input size
            scalar_inputCnt = rand_num()%16;
            bFuzzedScalar = true;
    }
    if (bMaybe = _maybe(9999,1,13))
    {
            //Fuzz ool input size
            ool_input_size = 4096+rand_num()%(4096);
            bFuzzedOOl = true;
    }
    if (bMaybe = _maybe(9999,1,13))
    {
        ool_input = rand_num();
        bFuzzedOOl = true;
    }
    //end of maybe()
    */
_FUZZ_DONE:
    
_CHECK_CHANGE:
    //Record the changed info
_original:
    //Copy_is_io_connnect_method_all(IS_IO_CONNECT_METHOD_ARGS_VAR_LIST,&(g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT].now.entry), &(g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]), ORDER_EXIT,
                                   //bWhiteBypass, bFuzzBlack);
    //Check_Fuzz_Changed_is_io_connnect_method(&(g_fuzz_sample_info[g_fuzz_sample_info_index%MAX_FUZZ_SAMPLE_INFO_CNT]));
    if (!(bFuzzedScalar || bFuzzedInband || bFuzzedOOl ))
    //None is fuzzed
    {
        g_fuzz_sample_info_index--;
    }
    lck_mtx_unlock(g_fuzz_sample_info_mutext);
    kr = ((fn_is_io_connect_method_t )inlined_part_is_io_connect_method)(
                                               //io_connect_t
                                               connection,
                                          //uint32_t
                                               selector,
                                          //io_scalar_inband64_t
                                               scalar_input,
                                          //mach_msg_type_number_t
                                               scalar_inputCnt,
                                          //io_struct_inband_t
                                               inband_input,
                                          //mach_msg_type_number_t
                                               inband_inputCnt,
                                          //mach_vm_address_t
                                               ool_input,
                                          //mach_vm_size_t
                                               ool_input_size,
                                          //io_struct_inband_t
                                               inband_output,
                                          //mach_msg_type_number_t *
                                               inband_outputCnt,
                                          //io_scalar_inband64_t
                                               scalar_output,
                                          //mach_msg_type_number_t *
                                               scalar_outputCnt,
                                          //mach_vm_address_t
                                               ool_output,
                                          //mach_vm_size_t *
                                               ool_output_size);

    lck_mtx_lock(g_fuzz_sample_info_mutext);
    is_info_leak_within_is_io_connect_method(IS_IO_CONNECT_METHOD_ARGS_VAR_LIST);
    lck_mtx_unlock(g_fuzz_sample_info_mutext);
    return kr;
}

/*
 kernel.development`is_io_connect_method:
 0xffffff800e0e2250 <+0>:   pushq  %rbp
 0xffffff800e0e2251 <+1>:   movq   %rsp, %rbp
 0xffffff800e0e2254 <+4>:   pushq  %r15
 0xffffff800e0e2256 <+6>:   pushq  %r14
 0xffffff800e0e2258 <+8>:   pushq  %r13
 0xffffff800e0e225a <+10>:  pushq  %r12
 0xffffff800e0e225c <+12>:  pushq  %rbx
 0xffffff800e0e225d <+13>:  subq   $0x108, %rsp
 0xffffff800e0e2264 <+20>:  movq   %r8, %r13
 0xffffff800e0e2267 <+23>:  movl   %ecx, %r14d
 0xffffff800e0e226a <+26>:  movq   %rdx, %r15
 0xffffff800e0e226d <+29>:  movq   %rdi, %rbx
 */
__attribute__ ((naked)) void inlined_part_is_io_connect_method()
{
    __asm__ volatile (
                      "  push %rbp\n"
                      "  mov %rsp, %rbp\n"
                      "  push %r15\n"
                      "  push %r14\n"
                      "  push %r13\n"
                      "  push %r12\n"
                      //"  push %rbx\n"
                      //"  sub $0x108, %rsp"
                      );
    __asm__ volatile (
                      "  jmp *%0\n"
                      //"  mov %%rax, %0"
                      :
                      :"m" (s_is_io_connect_method_JmpBackAddr)
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
