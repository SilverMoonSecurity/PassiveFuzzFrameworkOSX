//twitter @flyic
//moony_li@trendmicor.com
#ifndef the_flying_circus_noise_filter_h
#define the_flying_circus_noise_filter_h


#include "is_io_connect_method_trampline.h"
//extern struct fuzz_sample_info_t;

#define ANY_LEAVING_INTEGER 0
#define ANY_MATCH_INTEGER 0xefffffffefffffff

typedef struct
{
    char procName[PATH_MAX];
    //char routineName[PATH_MAX];
    uint64_t uid;
    struct
    {
        uint64_t uTemp;
    }u;
    
} detail_control_entry_common_t, *pdetail_control_entry_commont_t;


typedef enum
{
    UNKNOWN_STATE=0,
    WHITE_LISTING_STATE,
    BLACK_LISTING_STATE,
    MAX_STATE
} FILTER_STATE;
//boolean_t should_bypass_within_is_io_connect_method(fuzz_sample_info_t * pEntry);
boolean_t match_int(uint64_t uTarget, uint64_t uPattern);
boolean_t is_int_range_bypass(uint64_t uFrom, uint64_t uTo);
boolean_t match_int_range(uint64_t uTarget, uint64_t uFrom, uint64_t uTo);
boolean_t match_str(char longName[PATH_MAX], char entryName[PATH_MAX] );

boolean_t should_match_by_class_name(
                                      io_object_t object,
                                      char listing_class_name[][PATH_MAX],
                                      unsigned int uLen);
boolean_t should_match_by_proc_name(
                                     char listing_proc_name[][PATH_MAX],
                                     unsigned int uLen);									  
#endif
