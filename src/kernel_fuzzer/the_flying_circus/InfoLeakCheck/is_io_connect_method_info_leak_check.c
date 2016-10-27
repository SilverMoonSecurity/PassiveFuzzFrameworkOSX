//@Flyic
//moony_li@trendmicro.com

#include <string.h>
#include "proc.h"
#include "str_utils.h"
#include "configuration.h"
#include "noise_filter.h"
#include "is_io_connect_method_trampline.h"
#include "kernel_IOUserClient.h"



///////////////////////////////////////////////////

boolean_t is_info_leak_within_is_io_connect_method(IS_IO_CONNECT_METHOD_ARGS)
{
    boolean_t bFound = false;
    boolean_t bScalarFound = false;
    boolean_t bInBandFound = false;
    boolean_t bOolFound = false;
    do {
    /*inband_output,\
     inband_outputCnt,\
     scalar_output,\
     scalar_outputCnt,\
     ool_output,\
     ool_output_size
    */
    //check scalar_output
    size_t uScalarOutCnt = 0;
    if (scalar_output && scalar_outputCnt && *scalar_outputCnt)
    {
        uScalarOutCnt=*scalar_outputCnt;
        for(size_t i =0;i<uScalarOutCnt;i++)
        {
            if (is_address_possible_txt(scalar_output[i]))
            {
                bScalarFound = true;
                __asm__ volatile ("int3");
                break;
            }
        }

    }
    //Check inband_output
    if(inband_output && inband_outputCnt && *inband_outputCnt && *inband_outputCnt>=sizeof(uint64_t))
    {
        size_t uInbandOutCnt = *inband_outputCnt;
        if ( selector ==16 &&(20== uInbandOutCnt) && 0x7fffffff7fffffff == (*(uint64_t*)
                                                         (
                                                                    ((char*)inband_output
                                                                    )  +8
                                                         )
                                                        )
            )
        {//bypass1
            break;
        }
        //Check byte by byte
        for(size_t i =0;i<=(uInbandOutCnt-sizeof(uint64_t));i++)
        {
            if (is_address_possible_txt((*(
                                           (uint64_t*)(
                                                       ((char*)inband_output
                                                        )  +i
                                                       )
                                           )
                                         )
                                        )
                )
            {
                bInBandFound = true;
                __asm__ volatile ("int3");
                break;
            }
        }

    }
#if 0
    //Check ool
    if(ool_output && ool_output_size && *ool_output_size && *ool_output_size>=sizeof(uint64_t))
    {
        size_t uOolCnt = *ool_output_size;
        for(size_t i =0;i<=(uOolCnt-sizeof(uint64_t));i++)
        {
            if (is_address_possible_txt((*(
                                           (uint64_t*)(
                                                       ((char*)ool_output
                                                        )  +i
                                                       )
                                           )
                                         )
                                        )
                )
            {
                bOolFound = true;
                __asm__ volatile ("int3");
                break;
            }
        }
       
    }
#endif
        
    }while(0);
_EXIT:
    return bFound;
}




