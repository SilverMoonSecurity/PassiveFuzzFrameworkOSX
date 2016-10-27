//twitter @flyic
//moony_li@trendmicor.com
#ifndef createMappingInTask_trampline_h
#define createMappingInTask_trampline_h

#include <mach/kern_return.h>
#include <sys/types.h>
#include <mach/mach_vm.h>
#include <libkern/libkern.h>
#include <IOKit/IOTypes.h>
#include <Device/device_types.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/attr.h>
#include "noise_filter.h"
#include "rename_functions.h"
#include "sysproto.h"
#include "syscall.h"
#include "configuration.h"
#include "Mach_msg.h"

//ffffff80008a1410 T __ZN18IOMemoryDescriptor19createMappingInTaskEP4taskyjyy
/*
IOMemoryMap * IOMemoryDescriptor::createMappingInTask(
	task_t			intoTask,
	mach_vm_address_t	atAddress,
	IOOptionBits		options,
	mach_vm_size_t		offset,
	mach_vm_size_t		length)
*/



#define createMappingInTask_ARGS \
    uint64_t         this_IOMemoryDescriptor,\
	task_t			intoTask,\
	mach_vm_address_t	atAddress,\
	IOOptionBits		options,\
	mach_vm_size_t		offset,\
	mach_vm_size_t		length
	
	
#define createMappingInTask_ARGS_VAR_LIST   \
    this_IOMemoryDescriptor,\
	intoTask,\
	atAddress,\
	options,\
	offset,\
	length
	
	
#define createMappingInTask_ARGS_IN_STRUCT \
    uint64_t         this_IOMemoryDescriptor;\
	task_t			intoTask;\
	mach_vm_address_t	atAddress;\
	IOOptionBits		options;\
	mach_vm_size_t		offset;\
	mach_vm_size_t		length
	
#define createMappingInTask_ARGS_FOR_ANALYSIS_IN_STRUCT


typedef struct
{
    createMappingInTask_ARGS_IN_STRUCT;
}createMappingInTask_t;



typedef detail_control_entry_common_t detail_control_entry_for_createMappingInTask_t, *pdetail_control_entry_for_createMappingInTask_t;


typedef struct
{
    boolean_t bMatched;
    detail_control_entry_for_createMappingInTask_t matchedRule;
}
filter_info_entry_for_createMappingInTask, filter_info_entry_for_createMappingInTask_t;


typedef struct
{
    filter_info_entry_for_createMappingInTask_t entry;
}
white_filter_info_for_createMappingInTask, white_filter_info_for_createMappingInTask_t;

typedef struct
{
    filter_info_entry_for_createMappingInTask_t entry;
}
black_filter_info_for_createMappingInTask, black_filter_info_for_createMappingInTask_t;

typedef struct
{
    //noise_bypass_by_class_name_t eClass;
    //noise_bypass_by_proc_t eProc;
    white_filter_info_for_createMappingInTask_t white;
    black_filter_info_for_createMappingInTask_t black;
}
fuzz_noise_for_createMappingInTask, fuzz_noise_for_createMappingInTask_t;




typedef struct{
    char fuzzTag[0x100];
    char recordReproducedName[PATH_MAX +1];
    fuzz_env env;
    fuzz_noise_for_createMappingInTask_t noise;
    union
    {
        createMappingInTask_t entry;
    } original;
    union
    {
        createMappingInTask_t entry;
    } now;
} _createMappingInTask_fuzz_sample_info, createMappingInTask_fuzz_sample_info_t;



kern_return_t init_mutext_for_createMappingInTask();
kern_return_t un_init_mutext_for_createMappingInTask();
uint64_t trampline_createMappingInTask(createMappingInTask_ARGS);
__attribute__ ((naked)) uint64_t *inlined_part_createMappingInTask();

#endif
