//@Flyic
//moony_li@trendmicro.com

#include <string.h>
#include "noise_filter.h"
#include "proc.h"
#include "str_utils.h"
#include "configuration.h"
#include "noise_filter.h"
#include "ipc_kmsg_get_noise_filter.h"
#include "Mach_msg.h"
#include "kernel_info.h"
#include "StackTrace.h"
#include "process.h"

extern ipc_kmsg_get_fuzz_sample_info_t g_ipc_kmsg_get_fuzz_sample_info[MAX_FUZZ_SAMPLE_INFO_CNT] ;
extern uint64_t g_ipc_kmsg_get_fuzz_sample_info_index ;
extern struct kernel_info g_kernel_info;

//#include <IOkit/IOUserClient.h>
//is_iokit_subsystem	0xAF0, 0x0B47,
/*
 __const:FFFFFF8000E05CD0                 public is_iokit_subsystem_0
 __const:FFFFFF8000E05CD0 ; const is_iokit_subsystem is_iokit_subsystem_0
 __const:FFFFFF8000E05CD0 is_iokit_subsystem_0 dq offset iokit_server_routine; server
 __const:FFFFFF8000E05CD0                                         ; DATA XREF: iokit_server_routine:loc_FFFFFF8000482F82o
 __const:FFFFFF8000E05CD0                                         ; iokit_server+80o ...
 __const:FFFFFF8000E05CD0                 dd 0AF0h                ; start
 __const:FFFFFF8000E05CD0                 dd 0B47h                ; end
 __const:FFFFFF8000E05CD0                 dd 10C8h                ; maxsize
 */


detail_control_entry_for_ipc_kmsg_get_t g_whitle_listing_detail_control_foripc_kmsg_get[] =
{
    //procName,uid, msg_id_from, msg_id_to, routineName, addr, addr_offset_from, addr_offset_to
	//"*",0,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"vmware",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "kernel",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "WindowServer",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"launchd",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "watch",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "finder",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "sandbox",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"dock",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"d",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"d",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"server",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"store",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"spot",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
	"*",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"_ipc_kmsg_destroy",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
	"*",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"__Xio_service_add_interest_notification_64",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
	"*",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"__Xio_service_get_matching_services_bin",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
	"*",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"__Xio_service_get_matching_service_bin",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "*",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"__Xio_service_match_property_table_bin",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "*",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"__Xio_service_add_notification_bin_64",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
	"*",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"__Xio_connect_method",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
	"*",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"__Xio_registry_entry_get_property_bin",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,//tocheck-37

   
};

detail_control_entry_for_ipc_kmsg_get_t g_black_listing_detail_control_foripc_kmsg_get[] =
{
	//"webkit",PROCESS_UID_ANY_INTEGER, KMSG_IOKIT_RANGE,"__Xio_connect_method",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,

    "ioreg",PROCESS_UID_ANY_INTEGER, KMSG_IOKIT_SUBSYSTEM_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,

    //"*",PROCESS_UID_ANY_INTEGER, 0,0xAF0,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "*",PROCESS_UID_ANY_INTEGER, KMSG_IOKIT_SUBSYSTEM_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "vm",PROCESS_UID_ANY_INTEGER, KMSG_IOKIT_SUBSYSTEM_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "d",PROCESS_UID_ANY_INTEGER, KMSG_IOKIT_SUBSYSTEM_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"chrome", PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"safari", PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"webkit",PROCESS_UID_ANY_INTEGER, KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"Content",PROCESS_UID_ANY_INTEGER, KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,

#if 0
    //"*",PROCESS_UID_ANY_INTEGER, KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    ////////////////////////////subsystem fuzzing
    "*",PROCESS_UID_ANY_INTEGER, KMSG_MACH_HOST_SUBSYSTEM_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "*",PROCESS_UID_ANY_INTEGER, KMSG_HOST_PRIV_SUBSYSTEM_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "*",PROCESS_UID_ANY_INTEGER, KMSG_HOST_SECURITY_SUBSYSTEM_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"*",PROCESS_UID_ANY_INTEGER, KMSG_MACH_VM_SUBSYSTEM_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "*",PROCESS_UID_ANY_INTEGER,  KMSG_MACH_PORT_SUBSYSTEM_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"*",PROCESS_UID_ANY_INTEGER,  KMSG_THREAD_ACT_SUBSYSTEM_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
#endif
    
#if 0
#define KMSG_IOKIT_SUBSYSTEM_RANGE  0xAF0, 0x0B47
#define KMSG_MACH_VM_SUBSYSTEM_RANGE  0x12C0, 0x12D4
#define KMSG_MACH_PORT_SUBSYSTEM_RANGE  0xC80, 0x0CA4
#define KMSG_MACH_HOST_SUBSYSTEM_RANGE  0xC8, 0xE4
#define KMSG_HOST_PRIV_SUBSYSTEM_RANGE  0x190, 0x1AA
#define KMSG_HOST_SECURITY_SUBSYSTEM_RANGE  0x258, 0x25A
#define KMSG_CLOCK_SUBSYSTEM_RANGE  0x3E8, 0x3EB
#define KMSG_CLOCK_PRIV_SUBSYSTEM_RANGE  0x4B0, 0x4B2
#define KMSG_PROCESSOR_SUBSYSTEM_RANGE  0xBB8, 0xBBE
#define KMSG_PROCESSOR_SET_SUBSYSTEM_RANGE  0xFA0, 0xFAA
#define KMSG_LOCK_SET_SUBSYSTEM_RANGE  0x96A28, 0x96A2E
#define KMSG_TASK_SUBSYSTEM_RANGE  0x0D48, 0x0D72
#define KMSG_THREAD_ACT_SUBSYSTEM_RANGE  0x0E10, 0x0E2C
#define KMSG_VM32_MAP_SUBSYSTEM_RANGE  0x0ED8, 0x0EF7
#define KMSG_UNDREPLY_SUBSYSTEM_RANGE  0x1838, 0x183A
#define KMSG_DEFAULT_PAGER_OBJECT_SUBSYSTEM_RANGE  0x8E3, 0x8EE
#define KMSG_MACH_VOUCHER_SUBSYSTEM_RANGE  0x1518, 0x151D
#define KMSG_MACH_VOUCHER_SUBSYSTEM_RANGE  0x8E3, 0x8EE
#define KMSG_MACH_VOUCHER_ATTR_CONTROL_SUBSYSTEM_RANGE  0x15E0, 0x15E2
    ///NOT IN MIG_E below
#define KMSG_CATCH_EXC_SUBSYSTEM_RANGE  0x961, 0x964
#define KMSG_CATCH_MACH_EXC_SUBSYSTEM_RANGE  0x965, 0x968
#define KMSG_DP_MEMORY_OBJECT_SUBSYSTEM_RANGE  0x898, 0x8A2
#define KMSG_MEMORY_OBJECT_CONTROL_SUBSYSTEM_RANGE  0x7D0, 0x7DC
#define KMSG_UPL_SUBSYSTEM_RANGE  0x802, 0x806
#endif
    //"*",0xAF0, 0x0B47,
};




stack_match_item_t stack_matcher_for_ipc_kmsg_get[]=
{
    //If any item in list match, then match

    //routineName,reserved, routineAddres,offSetFrom, offSetTo, levelLow, levelHigh
    {{"_hndl_mach_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 32,STACK_ALL_LEVEL_RANGE},
    {{"_hndl_unix_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER, 0x0 ,42+0x10,STACK_ALL_LEVEL_RANGE},
    {{"_hndl_mdep_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 42+0xf,STACK_ALL_LEVEL_RANGE},
    {{"_hndl_diag_scall64",STACK_ANY_INTEGER},STACK_ANY_INTEGER,0, 42+0xf,STACK_ALL_LEVEL_RANGE},

};

uint32_t stack_matcher_size_for_ipc_kmsg_get = sizeof(stack_matcher_for_ipc_kmsg_get)/sizeof(stack_match_item_t);


////////////////////////////////////////////////////////////////////////////////////////
//White Listing
boolean_t should_bypass_within_ipc_kmsg_get(ipc_kmsg_get_fuzz_sample_info_t * pEntry)
{
    boolean_t bBypass = false;
    boolean_t bMatched = false;
    if (!pEntry)
    {
        bBypass = true;
        //moony_modify//printf("[DEBUG] should_bypass_within_ipc_kmsg_get, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
 
    bMatched = match_detail_control_entry_list_for_ipc_kmsg_get(WHITE_LISTING_STATE, pEntry,
        g_whitle_listing_detail_control_foripc_kmsg_get,
            sizeof(g_whitle_listing_detail_control_foripc_kmsg_get)/sizeof(detail_control_entry_for_ipc_kmsg_get_t));
    
  
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
boolean_t should_fuzz_within_ipc_kmsg_get(ipc_kmsg_get_fuzz_sample_info_t * pEntry)
{
    boolean_t bMatched = false;
    if (!pEntry)
    {
        bMatched = true;
        //moony_modify//printf("[DEBUG] should_bypass_within_ipc_kmsg_get, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
    
    bMatched = match_detail_control_entry_list_for_ipc_kmsg_get(BLACK_LISTING_STATE, pEntry,
                                               g_black_listing_detail_control_foripc_kmsg_get,
                                               sizeof(g_black_listing_detail_control_foripc_kmsg_get)/sizeof(detail_control_entry_for_ipc_kmsg_get_t));
    
    if (bMatched)
    {
        //moony_modify//printf("[DEBUG] should_bypass_within_ipc_kmsg_get, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
_EXIT:

    return bMatched;
}





boolean_t match_detail_control_entry_list_for_ipc_kmsg_get(FILTER_STATE state, ipc_kmsg_get_fuzz_sample_info_t * pSampleInfo, pdetail_control_entry_for_ipc_kmsg_get_t listing_head, unsigned int uLen)
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
        bMatched = match_detail_control_handler_for_ipc_kmsg_get(state, pSampleInfo, &(listing_head[i]));
        if (bMatched)
        {
            break;
        }
    }
    
_EXIT:
    
    return bMatched;
}



boolean_t match_detail_control_handler_for_ipc_kmsg_get(FILTER_STATE state, ipc_kmsg_get_fuzz_sample_info_t *pSampleInfo, pdetail_control_entry_for_ipc_kmsg_get_t pCtlEntry)
{
    boolean_t bMatched = false;
    boolean_t bMatchedProc = false;
    boolean_t bMatchedMsgID = false;
    boolean_t bMatchedRoutineName = false;
    boolean_t bMatchedRoutineAddr = false;
    boolean_t bMatchedOffSet = false;
    uint64_t uid =0;
    boolean_t bMatchedUid = false;
    
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
    //Cmp uid
    uid = kauth_getuid();
    bMatchedUid = match_int(uid, pCtlEntry->uid);
    if (!bMatchedUid)
    {
        goto _DONE;
    }
    
    //Cmp proc name
    bMatchedProc = match_str(pSampleInfo->env.szProcName, pCtlEntry->procName);
    if (!bMatchedProc)
    {
        //bMatched = false;
        goto _DONE;
    }
    
	//Cmp msg id range
    msg_id = pSampleInfo->original.entry.kmsg->ikm_header->msgh_id;
    bMatchedMsgID = match_int_range(msg_id,pCtlEntry->msg_id_from, pCtlEntry->msg_id_to);
    if (!bMatchedMsgID)
    {
        goto _DONE;
    }
    
    //Cmp routine name
    uint64_t routineAddr = 0;
    if (pCtlEntry->routineName[0] == '*')
    {
        bMatchedRoutineName = true;
    }
    else
    {
        if(!pCtlEntry->u.uTemp || KMSG_LEAVING == pCtlEntry->u.uTemp)
        {
            pCtlEntry->u.uTemp = solve_kernel_symbol(&g_kernel_info, pCtlEntry->routineName);
        }
        routineAddr  = getRoutineByMsghid(msg_id);
        if (routineAddr == pCtlEntry->u.uTemp)
        {
            bMatchedRoutineName = true;
        }
    }
    if (!bMatchedRoutineName)
    {
        goto _DONE;
    }
    
    //Cmp offset range
    if (is_int_range_bypass(pCtlEntry->addr_offset_from, pCtlEntry->addr_offset_to))
    {
        bMatchedOffSet = true;
    }
    else
    {
        routineAddr  = getRoutineByMsghid(msg_id);
        //(unsigned char*)(g_kernel_info.running_text_addr);
        bMatchedOffSet = match_int_range(
                                         routineAddr-(g_kernel_info.running_text_addr),
                                         pCtlEntry->addr_offset_from,
                                         pCtlEntry->addr_offset_to);
                                         
    }
    
_DONE:

_EXIT:
    if (bMatchedProc && bMatchedMsgID&&bMatchedRoutineName&& bMatchedOffSet&&bMatchedUid)
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

