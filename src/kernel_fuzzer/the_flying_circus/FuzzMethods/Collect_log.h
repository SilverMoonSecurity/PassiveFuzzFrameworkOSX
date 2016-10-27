//twitter @flyic
//moony_li@trendmicor.com
#ifndef the_flying_circus_collect_log_h
#define the_flying_circus_collect_log_h


#include "is_io_connect_method_trampline.h"


kern_return_t  kernel_print_log(char *buf);
kern_return_t  unset_kernel_panic_hook();
kern_return_t  set_kernel_panic_hook();
kern_return_t trampline_kdp_panic_dump();
__attribute__ ((naked)) void inlined_part_kdp_panic_dump();
#endif
