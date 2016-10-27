//@Flyic
//moony_li@trendmicro.com

#include <string.h>
#include "noise_filter.h"
#include "proc.h"
#include "str_utils.h"
#include "configuration.h"
#include "noise_filter.h"
#include "createMappingInTask_noise_filter.h"
#include "Mach_msg.h"
#include "kernel_info.h"
#include "StackTrace.h"
#include "configuration.h"
#include "process.h"


extern createMappingInTask_fuzz_sample_info_t g_createMappingInTask_fuzz_sample_info[MAX_FUZZ_SAMPLE_INFO_CNT] ;
extern uint64_t g_createMappingInTask_fuzz_sample_info_index ;
extern struct kernel_info g_kernel_info;


stack_match_item_t stack_matcher_for_createMappingInTask[]=
{
    //If any item in list match, then match
    {{"_shim_io_connect_method_scalarI_scalarO",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 0xC120-0xB8B0, STACK_ALL_LEVEL_RANGE},
    {{"_shim_io_connect_method_scalarI_structureO",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 0xDB94-0xD5C0, STACK_ALL_LEVEL_RANGE},
    {{"_shim_io_connect_method_scalarI_structureI",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 0xEA97-0xE490, STACK_ALL_LEVEL_RANGE},
    {{"_shim_io_connect_method_structureI_structureO",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 0xF588-0xF270, STACK_ALL_LEVEL_RANGE},
    
    {{"_is_io_connect_method",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 0xb2a9-0xaf10,STACK_ALL_LEVEL_RANGE},
    {{"_hndl_unix_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER, 0x0 ,42+0x10,STACK_ALL_LEVEL_RANGE},
    {{"_hndl_mach_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 42+0xf,STACK_ALL_LEVEL_RANGE},
    {{"_hndl_mdep_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 42+0xf,STACK_ALL_LEVEL_RANGE},
    {{"_hndl_diag_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 42+0xf,STACK_ALL_LEVEL_RANGE},
  
};

uint32_t stack_matcher_size_for_createMappingInTask = sizeof(stack_matcher_for_createMappingInTask)/sizeof(stack_match_item_t);


detail_control_entry_for_createMappingInTask_t g_whitle_listing_detail_control_forcreateMappingInTask[] =
{
    //{"*",0,ANY_LEAVING_INTEGER},
    //{"d",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    {"WindowServer",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    {"Sandbox",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    {"Finder",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    {"kernel",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    {"watch",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    //{"dock",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},
    {"launchd",PROCESS_UID_ANY_INTEGER, ANY_LEAVING_INTEGER},

};

detail_control_entry_for_createMappingInTask_t g_black_listing_detail_control_forcreateMappingInTask[] =
{
    {"*",      PROCESS_UID_ANY_INTEGER,ANY_LEAVING_INTEGER}, 
    {"chrome", PROCESS_UID_ANY_INTEGER,ANY_LEAVING_INTEGER},
    {"audio",  PROCESS_UID_ANY_INTEGER,ANY_LEAVING_INTEGER},
    {"safari", PROCESS_UID_ANY_INTEGER,ANY_LEAVING_INTEGER},
    {"webkit", PROCESS_UID_ANY_INTEGER,ANY_LEAVING_INTEGER},
    {"player", PROCESS_UID_ANY_INTEGER,ANY_LEAVING_INTEGER},

};


////////////////////////////////////////////////////////////////////////////////////////
//White Listing
boolean_t should_bypass_within_createMappingInTask(createMappingInTask_fuzz_sample_info_t * pEntry)
{
    boolean_t bBypass = false;
    boolean_t bMatched = false;
    if (!pEntry)
    {
        bBypass = true;
        //moony_modify//printf("[DEBUG] should_bypass_within_createMappingInTask, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
 
    bMatched = match_detail_control_entry_list_for_createMappingInTask(WHITE_LISTING_STATE, pEntry,
        g_whitle_listing_detail_control_forcreateMappingInTask,
            sizeof(g_whitle_listing_detail_control_forcreateMappingInTask)/sizeof(detail_control_entry_for_createMappingInTask_t));
    
  
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
boolean_t should_fuzz_within_createMappingInTask(createMappingInTask_fuzz_sample_info_t * pEntry)
{
    boolean_t bMatched = false;
    if (!pEntry)
    {
        bMatched = true;
        //moony_modify//printf("[DEBUG] should_bypass_within_createMappingInTask, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
    
    bMatched = match_detail_control_entry_list_for_createMappingInTask(BLACK_LISTING_STATE, pEntry,
                                               g_black_listing_detail_control_forcreateMappingInTask,
                                               sizeof(g_black_listing_detail_control_forcreateMappingInTask)/sizeof(detail_control_entry_for_createMappingInTask_t));
    
    if (bMatched)
    {
        //moony_modify//printf("[DEBUG] should_bypass_within_createMappingInTask, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
_EXIT:

    return bMatched;
}





boolean_t match_detail_control_entry_list_for_createMappingInTask(FILTER_STATE state, createMappingInTask_fuzz_sample_info_t * pSampleInfo, pdetail_control_entry_for_createMappingInTask_t listing_head, unsigned int uLen)
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
        bMatched = match_detail_control_handler_for_createMappingInTask(state, pSampleInfo, &(listing_head[i]));
        if (bMatched)
        {
            break;
        }
    }
    
_EXIT:
    
    return bMatched;
}



boolean_t match_detail_control_handler_for_createMappingInTask(FILTER_STATE state, createMappingInTask_fuzz_sample_info_t *pSampleInfo, pdetail_control_entry_for_createMappingInTask_t pCtlEntry)
{
    boolean_t bMatched = false;
    boolean_t bMatchedProc = false;
    boolean_t bMatchedMsgID = false;
    boolean_t bMatchedRoutineName = false;
    boolean_t bMatchedRoutineAddr = false;
    boolean_t bMatchedOffSet = false;
    boolean_t bMatchedUid = false;
    uint64_t uid;
	uint64_t msg_id =0;
    if (!pSampleInfo)
    {
        goto _EXIT;
    }
    if (!pCtlEntry)
    {
        bMatched = true;
        goto _EXIT;
    }
    
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

