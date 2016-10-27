
#ifndef the_flying_circus_stack_trace_utils_h
#define the_flying_circus_stack_trace_utils_h
#include <stdint.h>
#include <sys/syslimits.h>
#include <sys/types.h>
#include <IOKit/IOTypes.h>
#include "noise_filter.h"
#define MAX_FRAME_NUMBER (64)
#define STACK_ANY_INTEGER  ANY_MATCH_INTEGER
#define STACK_ANY_INTEGER_RANGE  0,ANY_MATCH_INTEGER
#define STACK_ALL_LEVEL_RANGE  0,MAX_FRAME_NUMBER 


typedef struct _cframe_t {
    struct _cframe_t	*prev;
    uint64_t		caller;
    uint64_t		args[0];
} cframe_t;

typedef struct _frame_info_t {
    cframe_t cframe;
    uint32_t uLevel;//Top=0, Top-1=1 ...
} frame_info_t;


typedef struct _symbole_routine_t {
    char rountineName[PATH_MAX];
    uint64_t		uCache;
} symbole_routine_t;


typedef struct _stack_match_item_t {
    symbole_routine_t symbolRoutine;
    uint64_t          addressRoutine;
    uint64_t   uOffSetFrom;
    uint64_t   uOffSetTo;
    uint64_t   uLevelLow;
    uint64_t   uLevelHigh;
} stack_match_item_t;

cframe_t *getBaseFrame();

boolean_t matchFrameStack(
                          stack_match_item_t *stack_match_item_list,
                          uint64_t stack_match_item_list_size);
#endif
