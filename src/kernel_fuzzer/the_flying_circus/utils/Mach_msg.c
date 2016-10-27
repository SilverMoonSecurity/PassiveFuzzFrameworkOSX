//moony_li@trendmicro.com
//@flyic


#include <string.h>
//#include <ctypes.h>
//#include <stdlib.h>
#include <sys/malloc.h>
#include "Mach_msg.h"


extern struct kernel_info g_kernel_info;
static uint64_t s_mig_table_max_displ = 0x10;
static mig_hash_t *s_mig_buckets = NULL;
boolean_t lookupMig_bucketsByMsghid(mach_msg_id_t id, mig_hash_t *pRet)
{
    mig_hash_t *ptr = NULL;
    mach_msg_id_t key = id;
    mach_msg_id_t i = id;
    uint32_t max_iter = 0;
    boolean_t bRet = FALSE;
    uint64_t uTempMigBuckets = 0;
    /*
    if (!s_mig_table_max_displ)
    {
        s_mig_table_max_displ= solve_kernel_symbol(&g_kernel_info, "_mig_table_max_displ");
    }
    */
    if (!s_mig_buckets)
    {
        s_mig_buckets = solve_kernel_symbol(&g_kernel_info, "_mig_buckets");
    }
    if (!(s_mig_table_max_displ && s_mig_buckets && pRet))
    {
        bRet = FALSE;
        goto _EXIT;
    }
    {
        uTempMigBuckets = s_mig_buckets;
        //s_mig_table_max_displ+=0xffffff8000000000;
        s_mig_buckets= (void *)((uint64_t)s_mig_buckets | 0xffffff8000000000);
    }
    max_iter = s_mig_table_max_displ;
    mach_msg_id_t uTemp =0;
    mach_msg_id_t uTempModeded =0;
    uint32_t uLeft =0;
    do
    {
        uTemp = i++;
        uTempModeded = uTemp % 0x407;
        ptr = &s_mig_buckets[uTempModeded];
        uLeft = 0;
        if ( key != ptr->num/*mig_buckets[uTempModeded].num*/ )
        {
            uLeft = 0;
            if ( ptr->num )
                uLeft = --max_iter != 0;
        }
    }
    while ( uLeft );
    if (ptr&&ptr->routine && key == ptr->num )
    {
        
        pRet->num = ptr->num;
        pRet->routine = ptr->routine;
        pRet->size = ptr->size;
        //*pRet = *ptr;
        bRet = TRUE;
        //__asm__ volatile ("int3");
        //((void (__fastcall *)(mach_msg_header_t *, mach_msg_header_t *))ptr->routine);
    }
_EXIT:
    return bRet;
}


uint64_t getRoutineByMsghid(mach_msg_id_t id)
{
    uint64_t uRet =0;
    mig_hash_t migHash = {0};
    if (lookupMig_bucketsByMsghid(id, &migHash))
    {
        uRet = (uint64_t) migHash.routine;
        //uRet = uRet | 0xffffff8000000000;
    }
    return uRet;
}