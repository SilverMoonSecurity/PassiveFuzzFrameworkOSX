//
//  copyio_noise_filter.c
//  the_flying_circus
//
//  Created by jack on 1/27/16.
//  Copyright © 2016 reverser. All rights reserved.
//



#include <string.h>
#include "noise_filter.h"
#include "proc.h"
#include "str_utils.h"
#include "configuration.h"
#include "noise_filter.h"
#include "copyio_noise_filter.h"
#include "Mach_msg.h"
#include "kernel_info.h"
#include "StackTrace.h"
#include "process.h"
#include <sys/kauth.h>

extern copy_io_fuzz_sample_info_t g_copy_io_fuzz_sample_info[MAX_FUZZ_SAMPLE_INFO_CNT] ;
extern uint64_t g_copy_io_fuzz_sample_info_index ;
extern struct kernel_info g_kernel_info;

/*
 shim_io_connect_method_scalarI_scalarO       __text FFFFFF8000C9B8B0 00000846 000001B8 00000000 R . . . B T .
 shim_io_connect_method_scalarI_structureO    __text FFFFFF8000C9D5C0 000005D5 00000138 00000000 R . . . B T .
 shim_io_connect_method_scalarI_structureI    __text FFFFFF8000C9E490 000005D8 00000138 00000000 R . . . B T .
 shim_io_connect_method_structureI_structureO __text FFFFFF8000C9F270 00000319 000000C8 00000000 R . . . B T .
 */
stack_match_item_t stack_matcher_for_copyio[]=
{
//If any item in list match, then match
    //{routineName, cache}, routineAddress, offSetFrom, offsetTo, levelLow, levelHigh
#if 0
    {{"_shim_io_connect_method_scalarI_scalarO",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 0xC120-0xB8B0, STACK_ALL_LEVEL_RANGE},
    {{"_shim_io_connect_method_scalarI_structureO",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 0xDB94-0xD5C0, STACK_ALL_LEVEL_RANGE},
    {{"_shim_io_connect_method_scalarI_structureI",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 0xEA97-0xE490, STACK_ALL_LEVEL_RANGE},
    {{"_shim_io_connect_method_structureI_structureO",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 0xF588-0xF270, STACK_ALL_LEVEL_RANGE},
    
    {{"_is_io_connect_method",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 0xb2a9-0xaf10,STACK_ALL_LEVEL_RANGE},
    //{{"_hndl_mach_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 22+0xf,STACK_ALL_LEVEL_RANGE},
    //{{"_ipc_kmsg_get",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 0xC74-0x720,STACK_ALL_LEVEL_RANGE},
    //{{"_return_from_trap",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 200,STACK_ALL_LEVEL_RANGE},
    //{{"_ipc_kmsg_get",STACK_ANY_INTEGER},STACK_ANY_INTEGER, 266-0xf ,266+0x2f,STACK_ALL_LEVEL_RANGE},//Get Kmsg body part only
    /*(lldb) bt
     * thread #5: tid = 0x08cd, 0xffffff8017864a7a kernel.development`ipc_kmsg_get [inlined] copyinmsg(user_addr=123145302914032, kernel_addr=<unavailable>, nbytes=0) at copyio.c:322, name = '0xffffff802486e5d8', queue = '0x0', stop reason = breakpoint 1.2
     * frame #0: 0xffffff8017864a7a kernel.development`ipc_kmsg_get [inlined] copyinmsg(user_addr=123145302914032, kernel_addr=<unavailable>, nbytes=0) at copyio.c:322 [opt]
     frame #1: 0xffffff8017864a7a kernel.development`ipc_kmsg_get(msg_addr=123145302914032, size=32, kmsgp=0xffffff888183be88) + 266 at ipc_kmsg.c:1209 [opt]
     frame #2: 0xffffff801787b3e8 kernel.development`mach_msg_overwrite_trap(args=<unavailable>) + 120 at mach_msg.c:458 [opt]
     frame #3: 0xffffff7f998291ec the_flying_circus`trampline_mach_msg_overwrite_trap(args=0xffffff888183bf28) + 332 at mach_msg_overwrite_trap_trampline.c:131
     frame #4: 0xffffff8017983850 kernel.development`mach_call_munger64(state=0xffffff8024883760) + 480 at bsd_i386.c:560 [opt]
     frame #5: 0xffffff80179b9516 kernel.development`hndl_mach_scall64 + 22
 */
#endif
    {{"_hndl_unix_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER, 0x0 ,42+0x10,STACK_ALL_LEVEL_RANGE},
    //{{"_hndl_mach_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 42+0xf,STACK_ALL_LEVEL_RANGE},
    //{{"_hndl_mdep_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 42+0xf,STACK_ALL_LEVEL_RANGE},
    //{{"_hndl_diag_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 42+0xf,STACK_ALL_LEVEL_RANGE},
};

uint32_t stack_matcher_size_for_copyio = sizeof(stack_matcher_for_copyio)/sizeof(stack_match_item_t);
detail_control_entry_for_copy_io_t g_white_list_copy_io[] =
{
    //{"*", 0, ANY_LEAVING_INTEGER},//bypass root process
    {"terminal", PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    {"finder", PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    {"watch", PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    {"sandbox", PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    {"WindowServer",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    {"Kernel",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
};



detail_control_entry_for_copy_io_t g_black_list_copy_io[] =
{
   
    
    {"*",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
    {"webkit",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
    {"safari",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
    {"chrome",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
    {"google",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
    //{"IOHID",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
    {"plant",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
    {"help",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
    {"apple",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
    {"d",PROCESS_UID_ANY_INTEGER,ANY_LEAVING_INTEGER} ,
    {"Web",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
    {"bird",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
    {"grim",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER} ,
   
};


////////////////////////////////////////////////////////////////////////////////////////
boolean_t _should_bypass_within_copy_io(copy_io_ARGS)
{
    copy_io_fuzz_sample_info_t nowArgStruct={0};
    Copy_copy_io_all(copy_io_ARGS_List, &nowArgStruct, ORDER_EXIT);
    return should_bypass_within_copy_io(&nowArgStruct);
}
//White Listing
boolean_t should_bypass_within_copy_io(copy_io_fuzz_sample_info_t * pEntry)
{
    boolean_t bBypass = false;
    boolean_t bMatched = false;
    if (!pEntry)
    {
        bBypass = true;
        //moony_modify//printf("[DEBUG] should_bypass_within_ipc_kmsg_send, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
    
    bMatched = match_detail_control_entry_list_for_copy_io(WHITE_LISTING_STATE, pEntry,
                                                                 g_white_list_copy_io,
                                                                 sizeof(g_white_list_copy_io)/sizeof(detail_control_entry_for_copy_io_t));
    
    
_EXIT:
    if (bMatched)
    {
        //__asm__ volatile ("int3");
        //moony_modify//printf("[DEBUG]  allowed for [%s], PID[%x], className=[%s], object=0x%llx\r\n",path,pid,szClassName,object);
        bBypass = true;
    }
    return bBypass;
}


///////////////////////////////////////////////////
//Black listing
boolean_t _should_fuzz_within_copy_io(copy_io_ARGS)
{
    copy_io_fuzz_sample_info_t nowArgStruct={0};
    Copy_copy_io_all(copy_io_ARGS_List, &nowArgStruct, ORDER_EXIT);
    return should_fuzz_within_copy_io(&nowArgStruct);
}
boolean_t should_fuzz_within_copy_io(copy_io_fuzz_sample_info_t * pEntry)
{
    boolean_t bMatched = false;
    if (!pEntry)
    {
        bMatched = true;
        //moony_modify//printf("[DEBUG] should_bypass_within_ipc_kmsg_send, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
    
    bMatched = match_detail_control_entry_list_for_copy_io(BLACK_LISTING_STATE, pEntry,
                                                                 g_black_list_copy_io,
                                                                 sizeof(g_black_list_copy_io)/sizeof(detail_control_entry_for_copy_io_t
                                                                    )
                                                           );
    
    if (bMatched)
    {
        //moony_modify//printf("[DEBUG] should_bypass_within_ipc_kmsg_send, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
_EXIT:
    
    return bMatched;
}


boolean_t match_detail_control_entry_list_for_copy_io(FILTER_STATE state, copy_io_fuzz_sample_info_t * pSampleInfo, pdetail_control_entry_for_copy_io_t listing_head, unsigned int uLen)
{
    boolean_t bMatched = false;
    if ( !listing_head || uLen ==0)
    {
        bMatched = true;
        goto _EXIT;
    }
    if (!pSampleInfo)
    {
        goto _EXIT;
    }
    for(int i = 0; i<uLen;i++)
    {
        bMatched = match_detail_control_handler_for_copy_io(state, pSampleInfo, &(listing_head[i]));
        if (bMatched)
        {
            break;
        }
    }
    
_EXIT:
    
    return bMatched;
}

boolean_t match_detail_control_handler_for_copy_io(FILTER_STATE state, copy_io_fuzz_sample_info_t*pSampleInfo, pdetail_control_entry_for_copy_io_t pCtlEntry)
{
    boolean_t bMatched = false;
    boolean_t bMatchedProc = false;
    boolean_t bMatchedUid = false;
    uint64_t uid = 0;

    

    if (!pSampleInfo)
    {
        goto _EXIT;
    }
    if (!pCtlEntry)
    {
        bMatched = true;
        goto _EXIT;
    }
    
    //printf("jack: compare proc name: %s ==== %s\n", pSampleInfo->env.szProcName, pCtlEntry->procName);
    //Cmp proc name
    bMatchedProc = match_str(pSampleInfo->env.szProcName, pCtlEntry->procName);
    if (!bMatchedProc)
    {
        //bMatched = false;
        goto _DONE;
    }
    
    //Cmp uid
    uid = kauth_getuid();
    bMatchedUid = match_int(uid, pCtlEntry->uid);
    if (!bMatchedUid)
    {
        goto _DONE;
    }
    
_DONE:
    
_EXIT:
    if (bMatchedProc&& bMatchedUid)
    {
        
        //__asm__ volatile ("int3");
        //moony_modify//printf("[DEBUG]  allowed for [%s], PID[%x], className=[%s], object=0x%llx\r\n",path,pid,szClassName,object);
        bMatched = true;
        switch (state) {
            case WHITE_LISTING_STATE:
                pSampleInfo->noise.white.entry.bMatched = true;
                pSampleInfo->noise.white.entry.matchedRule = *pCtlEntry;
                break;
            case BLACK_LISTING_STATE:
                pSampleInfo->noise.black.entry.bMatched = true;
                pSampleInfo->noise.black.entry.matchedRule = *pCtlEntry;
                break;
            default:
                break;
        }
        
    }
    return bMatched;
}


