//@Flyic
//moony_li@trendmicro.com

#include <string.h>
#include "proc.h"
#include "str_utils.h"
#include "configuration.h"
#include "noise_filter.h"
#include "is_io_connect_method_trampline.h"
#include "kernel_IOUserClient.h"
#include "copy_io_trampline.h"

///////////////////////////////////////////////////

boolean_t is_info_leak_within_copyio(copy_io_ARGS)
{
    boolean_t bFound = false;
    //Disable because high FA
    return bFound;
    
    do
    {
    if(/*COPYOUT*/1 != copy_type)
    {
        break;
    }

    //Check
    size_t uCopyCnt = 0;
    //if(kernel_addr && user_addr && nbytes && lencopied &&((uCopyCnt = *lencopied)>=sizeof(uint64_t)))
    if( user_addr<0x8000000000000000
             && kernel_addr
             && ((uint64_t)kernel_addr & 0xffffff0000000000)==0xffffff0000000000
             && nbytes
            &&((uCopyCnt = nbytes)>=sizeof(uint64_t))
        )
    {
        
        for(size_t i =0;i<=(uCopyCnt-sizeof(uint64_t));i++)
        {
            if (is_address_possible_txt((*(
                                           (uint64_t*)(
                                                       ((char*)kernel_addr
                                                        )  +i
                                                       )
                                           )
                                         )
                                        )
                )
            {
                bFound = true;
                __asm__ volatile ("int3");
                break;
            }
        }
       
    }

        
    }while(0);
_EXIT:
    return bFound;
}




