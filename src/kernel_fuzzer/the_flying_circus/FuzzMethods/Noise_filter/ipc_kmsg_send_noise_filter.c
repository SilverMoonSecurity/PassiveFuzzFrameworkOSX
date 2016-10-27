//@Flyic
//moony_li@trendmicro.com

#include <string.h>
#include "noise_filter.h"
#include "proc.h"
#include "str_utils.h"
#include "configuration.h"
#include "noise_filter.h"
#include "ipc_kmsg_send_noise_filter.h"
#include "Mach_msg.h"
#include "kernel_info.h"
#include "process.h"
extern ipc_kmsg_send_fuzz_sample_info_t g_ipc_kmsg_send_fuzz_sample_info[MAX_FUZZ_SAMPLE_INFO_CNT] ;
extern uint64_t g_ipc_kmsg_send_fuzz_sample_info_index ;
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

detail_control_entry_for_ipc_kmsg_send_t g_whitle_listing_detail_control_foripc_kmsg_send[] =
{
    //procName,uid,msg_id_from, msg_id_to, routineName, addr, addr_offset_from, addr_offset_to
	"*",0,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"vmware",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
	"*",PROCESS_UID_ANY_INTEGER,KMSG_ANY_RANGE,"_ipc_kmsg_destroy",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"*",PROCESS_UID_ANY_INTEGER,0xB44,0xB44,//ipc_kmsg_destroy
    //"*",PROCESS_UID_ANY_INTEGER,0xB2e,0xB2e,//ipc_kmsg_destroy
};

detail_control_entry_for_ipc_kmsg_send_t g_black_listing_detail_control_foripc_kmsg_send[] =
{
	//"webkit",PROCESS_UID_ANY_INTEGER, KMSG_IOKIT_RANGE,"__Xio_connect_method",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
	
    //"*",PROCESS_UID_ANY_INTEGER, 0,0xAF0,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "*",PROCESS_UID_ANY_INTEGER, KMSG_IOKIT_SUBSYSTEM_RANGE,"*",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    "chrome",PROCESS_UID_ANY_INTEGER, KMSG_IOKIT_SUBSYSTEM_RANGE,"__Xio_connect_method",KMSG_ADDR_OFFSET_ANY_RANGE,KMSG_LEAVING,
    //"*",0xAF0, 0x0B47,
};


////////////////////////////////////////////////////////////////////////////////////////
//White Listing
boolean_t should_bypass_within_ipc_kmsg_send(ipc_kmsg_send_fuzz_sample_info_t * pEntry)
{
    boolean_t bBypass = false;
    boolean_t bMatched = false;
    if (!pEntry)
    {
        bBypass = true;
        //moony_modify//printf("[DEBUG] should_bypass_within_ipc_kmsg_send, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
 
    bMatched = match_detail_control_entry_list_for_ipc_kmsg_send(WHITE_LISTING_STATE, pEntry,
        g_whitle_listing_detail_control_foripc_kmsg_send,
            sizeof(g_whitle_listing_detail_control_foripc_kmsg_send)/sizeof(detail_control_entry_for_ipc_kmsg_send_t));
    
  
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
boolean_t should_fuzz_within_ipc_kmsg_send(ipc_kmsg_send_fuzz_sample_info_t * pEntry)
{
    boolean_t bMatched = false;
    if (!pEntry)
    {
        bMatched = true;
        //moony_modify//printf("[DEBUG] should_bypass_within_ipc_kmsg_send, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
    
    bMatched = match_detail_control_entry_list_for_ipc_kmsg_send(BLACK_LISTING_STATE, pEntry,
                                               g_black_listing_detail_control_foripc_kmsg_send,
                                               sizeof(g_black_listing_detail_control_foripc_kmsg_send)/sizeof(detail_control_entry_for_ipc_kmsg_send_t));
    
    if (bMatched)
    {
        //moony_modify//printf("[DEBUG] should_bypass_within_ipc_kmsg_send, strange pEntry, it is NULL!\r\n");
        goto _EXIT;
    }
_EXIT:

    return bMatched;
}





boolean_t match_detail_control_entry_list_for_ipc_kmsg_send(FILTER_STATE state, ipc_kmsg_send_fuzz_sample_info_t * pSampleInfo, pdetail_control_entry_for_ipc_kmsg_send_t listing_head, unsigned int uLen)
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
        bMatched = match_detail_control_handler_for_ipc_kmsg_send(state, pSampleInfo, &(listing_head[i]));
        if (bMatched)
        {
            break;
        }
    }
    
_EXIT:
    
    return bMatched;
}



boolean_t match_detail_control_handler_for_ipc_kmsg_send(FILTER_STATE state, ipc_kmsg_send_fuzz_sample_info_t *pSampleInfo, pdetail_control_entry_for_ipc_kmsg_send_t pCtlEntry)
{
    boolean_t bMatched = false;
    boolean_t bMatchedProc = false;
    boolean_t bMatchedMsgID = false;
    boolean_t bMatchedRoutineName = false;
    boolean_t bMatchedRoutineAddr = false;
    boolean_t bMatchedOffSet = false;
    boolean_t bMatchedUid = false;
    uint64_t uid = 0;
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
                                         routineAddr- (g_kernel_info.running_text_addr),
                                         pCtlEntry->addr_offset_from,
                                         pCtlEntry->addr_offset_to);
                                         
    }
_DONE:

_EXIT:
    if (bMatchedProc && bMatchedMsgID&&bMatchedRoutineName&& bMatchedOffSet &&bMatchedUid)
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

