//@Flyic
//moony_li@trendmicro.com

#include <string.h>
#include "record_reproduce.h"
#include "proc.h"
#include "str_utils.h"
//#include "stdio.h"
static enum_record_reproduce_type s_record_type = LOG_REPRODUCE_DIFF;
static uint64_t s_sample_info_counter = 0;
extern struct kernel_info g_kernel_info;

void list_buf(char * buffer, uint64_t size)
{
    uint64_t uLen = size;
    uint64_t index = uLen -1;

    for(; index >= 0; index--)
    {
        if (buffer[index])
        {
            break;
        }
        if (!index)
        {
            break;
        }
    }


    //print non 0
    for(uint64_t i = 0; i< (index<size?index:size); )
    {
        char * p = 0;
        p = ((char *)buffer) + i;
#if 0
        //moony_modify//printf("[DEBUG][#0x0%llx]%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\r\n",
               i,
               p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
               p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
               p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23],
               p[24],p[25],p[26],p[27],p[28],p[29],p[30],p[31]
               );
        i+=32;
#endif
#if 0
        if (i%128 == 0 )
        {
            //moony_modify//printf("\r\n[DEBUG][#0x0%llx]", i);
        }
        //moony_modify//printf("0x%x ", *p);
        i++;
    
#endif
    
#if 0
    //moony_modify//printf("[DEBUG][#0x0%llx]%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\r\n",
           i,
           p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7],
           p[8],p[9],p[10],p[11],p[12],p[13],p[14],p[15],
           p[16],p[17],p[18],p[19],p[20],p[21],p[22],p[23],
           p[24],p[25],p[26],p[27],p[28],p[29],p[30],p[31],
           p[32],p[33],p[34],p[35],p[36],p[37],p[38],p[39],
           p[40],p[41],p[42],p[43],p[44],p[45],p[46],p[47],
           p[48],p[49],p[50],p[51],p[52],p[53],p[54],p[55],
           p[56],p[57],p[58],p[59],p[60],p[61],p[62],p[63]
           );
    i+=64;
#endif
    }
    //print 0 zone
    //moony_modify//printf("\r\n[DEBUG][#0x0%llx---#0x0%llx]{0}", index, uLen-1);
    //moony_modify//printf("\r\n[DEBUG]\r\n");
}

void list_is_io_connect_method_t(is_io_connect_method_t *pEntry)
{
    if (!pEntry)
    {
        return;
    }
    uint64_t uLen = sizeof(pEntry->inband_input);
    //moony_modify//printf("[DEBUG]\tconnection=0x%llx\r\n", pEntry->connection);
    ////moony_modify//printf("[DEBUG]\tszClassName=0x%llx\r\n", pEntry->szClassName);
    //moony_modify//printf("[DEBUG]\tselector=0x%llx\r\n", pEntry->selector);
    //moony_modify//printf("[DEBUG]\tinband_inputCnt=0x%llx\r\n", pEntry->inband_inputCnt);
    //moony_modify//printf("[DEBUG]\tinband_input_addr_of_global=0x%llx\r\n", pEntry->inband_input_addr_of_global);
    //moony_modify//printf("[DEBUG]\tinband_input_addr_of_stack=0x%llx\r\n", pEntry->inband_input_addr_of_stack);
    //moony_modify//printf("[DEBUG]\tinband_input[0x%llx]=\r\n", uLen);
    list_buf(pEntry->inband_input, sizeof(pEntry->inband_input));
}


kern_return_t  record_sample_info_is_io_connect_method(fuzz_sample_info_t * pEntry)
{
    boolean_t bChanged = false;
    kern_return_t kr = KERN_FAILURE;
    if (!pEntry)
    {
        goto _EXIT;
    }
    uint64_t uIndex = s_sample_info_counter++;
    //moony_modify//printf("\r\n\r\n[DEBUG] ========>>>>>>>>record_sample_info_is_io_connect_method() s_sample_info_counter =0x%llx <=\r\n",uIndex);
    //moony_modify//printf("[DEBUG] %s\r\n", pEntry->recordReproducedName);
    //moony_modify//printf("[DEBUG]\tbypassed[%d]\tProc[%s]\r\n",pEntry->noise.eProc.bBypassByProcName,pEntry->noise.eProc.path);
    //moony_modify//printf("[DEBUG]\tbypassed[%d]\tClassName[%s]\r\n",pEntry->noise.eClass.bBypassByClassName,pEntry->noise.eClass.szClassName);
    
    //moony_modify//printf("[DEBUG] listing original entry:\r\n");
    list_is_io_connect_method_t(&(pEntry->original));
    //fflush(stdout);
    switch (s_record_type) {
        case LOG_REPRODUCE_DIFF:
            if (pEntry->changed.bConnection)
            {
                //moony_modify//printf("[DEBUG] connection differs!");
                bChanged = true;
            }
            if (pEntry->changed.bSelector)
            {
                //moony_modify//printf("[DEBUG] selector differs!");
                bChanged = true;
            }
            if (pEntry->changed.bInband_inputCnt)
            {
                //moony_modify//printf("[DEBUG] inband_inputCnt differs!");
                bChanged = true;
            }
            if (pEntry->changed.bInband_input)
            {
                //moony_modify//printf("[DEBUG] inband_input differs!");
                bChanged = true;
            }
            if (bChanged)
            {
                //moony_modify//printf("[DEBUG] After change, listing now entry:\r\n");
                list_is_io_connect_method_t(&(pEntry->now));
            }
            break;
            
        default:
            break;
    }
    //moony_modify//printf("[DEBUG] ............record_sample_info_is_io_connect_method() => s_sample_info_counter =0x%llx \r\n",uIndex);
_EXIT:
    return kr;
}