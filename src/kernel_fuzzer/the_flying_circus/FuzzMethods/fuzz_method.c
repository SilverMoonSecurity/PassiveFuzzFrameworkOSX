//@Flyic
//moony_li@trendmicro.com
#include "hide_files.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/random.h>
#include <sys/time.h>
#include <IOKit/IOLib.h>
//#include <IOKit/IOTimerEventSource.h>

#include "configuration.h"
#include "proc.h"
#include "sysent.h"
#include "my_data_definitions.h"
#include "kernel_info.h"
#include "function_pointers.h"
#include "path_utils.h"
#include "inline_hook.h"
#include "fuzz_method.h"

extern inline_hook_entry_t g_inline_hook_entry[INLINE_ENUM_MAX];
size_t get_min(size_t a, size_t b)
{
    return a<b?a:b;
}
size_t get_max(size_t a, size_t b)
{
    return a>b?a:b;
}
uint32_t rand_num()
{
    uint64_t uTime = 0;
    static int seeded_num = 0;
    clock_get_uptime(&uTime);
    //if (!seeded_num)
    {
        //srand(uTime);
        seeded_num = 1;
    }
    return random();
}

float rand_rate(size_t uRandLimit, size_t uRandMin, size_t uRandMax)
{
    size_t uTemp = (uRandMax==uRandMin?0:rand_num()%(uRandMax-uRandMin));
    return ((float)(uRandMin+uTemp)/(float)(uRandLimit));
}

boolean_t singleMaybe(size_t uLimit, size_t uValue)
{
    boolean_t bRet = false;
    size_t uTemp = rand_num()%uLimit;
    if (uTemp<=uValue)
    {
        bRet = true;
    }
    return bRet;
}

boolean_t _maybe(size_t uLimit, size_t uMin, size_t uMax)
{
    return singleMaybe(uLimit, uLimit*rand_rate(uLimit,uMin,uMax));
}
boolean_t maybe()
{
    return _maybe(FUZZ_METHOD_RAND_MAYBE_LIMIT, FUZZ_METHOD_RAND_MAYBE_MIN, FUZZ_METHOD_RAND_MAYBE_MAX);
}

void flip_bit(void* buf, size_t len){
    if (!len)
        return;
    //if (maybe())
    {
    size_t offset = rand_num() % len;
    ((uint8_t*)buf)[offset] ^= (0x01 << (rand_num() % 8));
    ////moony_modify//printf("\r\nmoony: lip_bit: offset=%d, buf[offset]=%x", offset, ((uint8_t*)buf)[offset]);
    }
}

void flip_byte(void* buf, size_t len){
    if (!len)
        return;
    //if (maybe())
    {
    size_t offset = rand_num() % len;
    ((uint8_t*)buf)[offset] = (rand_num()%0xff);
    ////moony_modify//printf("\r\nmoony: lip_bit: offset=%d, buf[offset]=%x", offset, ((uint8_t*)buf)[offset]);
    }
}

void _flip_N_byte(void* buf, size_t len,
                  size_t uRandLimit,
                  size_t uRandMin,
                  size_t uRandMax,
                  size_t uMinBytes,
                  size_t uMaxBytes)
{
    if (!(len&&buf))
        return;
    size_t uTryFuzzedBytes = 0; size_t uRealFuzzedBytes = 0;
    uTryFuzzedBytes = len*rand_rate(uRandLimit,uRandMin,uRandMax);
    size_t uMaxLegal = get_min(len, uMaxBytes);//keep it legal
    size_t uMinLegal = get_min(len,uMinBytes);
    uRealFuzzedBytes = uMinLegal;
    if (uTryFuzzedBytes >= uMinLegal && uTryFuzzedBytes >= uMaxLegal )
    {
        uRealFuzzedBytes = uTryFuzzedBytes;
    }
   
    for(size_t i=0;i< uRealFuzzedBytes; i++)
    {
        flip_byte(buf, len);
    }
}
void flip_N_byte(void* buf, size_t len)
{
    _flip_N_byte( buf, len,FLIP_N_RAND_LIMIT,FLIP_N_RAND_MIN, FLIP_N_RAND_MAX, FLIP_MIN_BYTES, FLIP_MAX_BYTES);
}

void flip_around_int(unsigned int *puInt, size_t nOffSet)
{
    if (!puInt)
        return ;
    nOffSet +=FUZZ_METHOD_FIXED_OFFSET;//todo: moony_li:magic number here
    *puInt = *puInt + rand_num()%(2*nOffSet) - nOffSet;
}

boolean_t flip_if_fuzzing(uint32_t uEnumInlinePointIndex)
{
    boolean_t bRet = false;
    if(uEnumInlinePointIndex<INLINE_ENUM_MAX)
    {
        if (g_inline_hook_entry[uEnumInlinePointIndex].bFuzzing)
        {
            bRet = true;
        }
    }
    return bRet;
}

void _flip_N_byte_if_fuzzing(void* buf, size_t len,  uint32_t uEnumInlinePointIndex, size_t uRandLimit, size_t uRandMin, size_t uRandMax, size_t uMinBytes, size_t uMaxBytes)
{
    if (flip_if_fuzzing(uEnumInlinePointIndex))
    {
        _flip_N_byte(buf, len, uRandLimit, uRandMin,uRandMax,uMinBytes,uMaxBytes);
    }
}

void flip_N_byte_if_fuzzing(void* buf, size_t len,  uint32_t uEnumInlinePointIndex)
{
    if (flip_if_fuzzing(uEnumInlinePointIndex))
    {
        flip_N_byte(buf, len);
    }
}