//twitter @flyic
//moony_li@trendmicor.com
#ifndef createMappingInTask_noise_filter_h
#define createMappingInTask_noise_filter_h


//#include "trampline_functions.h"
#include "createMappingInTask_trampline.h"
//extern struct createMappingInTask_fuzz_sample_info_t;


boolean_t should_bypass_within_createMappingInTask(createMappingInTask_fuzz_sample_info_t * pEntry);
boolean_t should_fuzz_within_createMappingInTask(createMappingInTask_fuzz_sample_info_t * pEntry);

#endif
