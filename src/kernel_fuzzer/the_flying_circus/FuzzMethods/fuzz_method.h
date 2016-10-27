//twitter @flyic
//moony_li@trendmicor.com
#ifndef the_flying_circus_fuzz_method_h
#define the_flying_circus_fuzz_method_h

#include <mach/kern_return.h>
#include <sys/types.h>
#include <mach/mach_vm.h>
#include <libkern/libkern.h>

#include "rename_functions.h"
#include "sysproto.h"
#include "syscall.h"

float rand_rate(size_t uRandLimit, size_t uRandMin, size_t uRandMax);
boolean_t  maybe();
boolean_t _maybe(size_t uLimit, size_t uMin, size_t uMax);
void flip_bit(void* buf, size_t len);
void flip_byte(void* buf, size_t len);

void flip_N_byte(void* buf, size_t len);
void flip_around_int(unsigned int *puInt, size_t nOffSet);
boolean_t flip_if_fuzzing(uint32_t uEnumInlinePointIndex);
void flip_N_byte_if_fuzzing(void* buf, size_t len, uint32_t uEnumInlinePointIndex);
#endif
