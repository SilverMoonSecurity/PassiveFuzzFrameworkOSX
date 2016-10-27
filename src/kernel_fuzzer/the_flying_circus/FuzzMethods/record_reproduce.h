//twitter @flyic
//moony_li@trendmicor.com
#ifndef the_flying_circus_record_reproduce_h
#define the_flying_circus_record_reproduce_h


#include "is_io_connect_method_trampline.h"


typedef enum
{
    LOG_REPRODUCE_ALL = 0,
    LOG_REPRODUCE_DIFF,
    LOG_REPRODUCE_MAX_LEN
} enum_record_reproduce_type;

kern_return_t  record_sample_info_is_io_connect_method(fuzz_sample_info_t * pEntry);

void list_is_io_connect_method_t(is_io_connect_method_t *pEntry);
#endif
