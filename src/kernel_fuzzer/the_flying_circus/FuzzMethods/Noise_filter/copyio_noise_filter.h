//
//  copyio_noise_filter.h
//  the_flying_circus
//
//  Created by jack on 1/27/16.
//  Copyright © 2016 reverser. All rights reserved.
//

#ifndef copyio_noise_filter_h
#define copyio_noise_filter_h


//#include "trampline_functions.h"
#include "copy_io_trampline.h"



boolean_t should_bypass_within_copy_io(copy_io_fuzz_sample_info_t * pEntry);
boolean_t should_fuzz_within_copy_io(copy_io_fuzz_sample_info_t * pEntry);




#endif /* copyio_noise_filter_h */
