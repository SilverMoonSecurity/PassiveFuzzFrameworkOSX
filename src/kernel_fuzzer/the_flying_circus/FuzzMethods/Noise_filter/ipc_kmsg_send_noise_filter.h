//twitter @flyic
//moony_li@trendmicor.com
#ifndef ipc_kmsg_send_noise_filter_h
#define ipc_kmsg_send_noise_filter_h


//#include "trampline_functions.h"
#include "ipc_kmsg_send_trampline.h"
//extern struct ipc_kmsg_send_fuzz_sample_info_t;


boolean_t should_bypass_within_ipc_kmsg_send(ipc_kmsg_send_fuzz_sample_info_t * pEntry);
boolean_t should_fuzz_within_ipc_kmsg_send(ipc_kmsg_send_fuzz_sample_info_t * pEntry);

#endif
