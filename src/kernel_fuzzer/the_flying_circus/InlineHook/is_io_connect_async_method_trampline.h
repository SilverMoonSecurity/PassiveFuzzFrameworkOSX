//twitter @flyic
//moony_li@trendmicor.com
#ifndef is_io_connect_async_method_trampline_h
#define is_io_connect_async_method_trampline_h

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


/*
	io_connect_t connection,
	mach_port_t wake_port,
	io_async_ref64_t reference,
	mach_msg_type_number_t referenceCnt,
	uint32_t selector,
	io_scalar_inband64_t scalar_input,
	mach_msg_type_number_t scalar_inputCnt,
	io_struct_inband_t inband_input,
	mach_msg_type_number_t inband_inputCnt,
	mach_vm_address_t ool_input,
	mach_vm_size_t ool_input_size,
	io_struct_inband_t inband_output,
	mach_msg_type_number_t *inband_outputCnt,
	io_scalar_inband64_t scalar_output,
	mach_msg_type_number_t *scalar_outputCnt,
	mach_vm_address_t ool_output,
	mach_vm_size_t * ool_output_size
    */
#define IS_IO_CONNECT_ASYNC_METHOD_ARGS \
    io_connect_t connection,\
    mach_port_t wake_port,\
    io_async_ref64_t reference,\
    mach_msg_type_number_t refernceCnt,\
    uint32_t selector,\
    io_scalar_inband64_t scalar_input,\
    mach_msg_type_number_t scalar_inputCnt,\
    io_struct_inband_t inband_input,\
    mach_msg_type_number_t inband_inputCnt,\
    mach_vm_address_t ool_input,\
    mach_vm_size_t ool_input_size,\
    io_struct_inband_t inband_output,\
    mach_msg_type_number_t *inband_outputCnt,\
    io_scalar_inband64_t scalar_output,\
	mach_msg_type_number_t *scalar_outputCnt,\
    mach_vm_address_t ool_output,\
	mach_vm_size_t * ool_output_size
	
	
	#define IS_IO_CONNECT_ASYNC_METHOD_ARGS_VAR_LIST   \
	connection,\
    wake_port,\
    reference,\
    refernceCnt,\
    selector,\
    scalar_input,\
    scalar_inputCnt,\
    inband_input,\
    inband_inputCnt,\
    ool_input,\
    ool_input_size,\
    inband_output,\
    inband_outputCnt,\
    scalar_output,\
	scalar_outputCnt,\
    ool_output,\
	ool_output_size
	
#define IS_IO_CONNECT_ASYNC_METHOD_ARGS_IN_STRUCT \
    io_connect_t connection;\
    mach_port_t wake_port;\
    io_async_ref64_t reference;\
    mach_msg_type_number_t refernceCnt;\
    uint32_t selector;\
    io_scalar_inband64_t scalar_input;\
    mach_msg_type_number_t scalar_inputCnt;\
    io_struct_inband_t inband_input;\
    mach_msg_type_number_t inband_inputCnt;\
    mach_vm_address_t ool_input;\
    mach_vm_size_t ool_input_size;\
    io_struct_inband_t inband_output;\
    mach_msg_type_number_t *inband_outputCnt;\
    io_scalar_inband64_t scalar_output;\
	mach_msg_type_number_t *scalar_outputCnt;\
    mach_vm_address_t ool_output;\
	mach_vm_size_t * ool_output_size;
	
#define IS_IO_CONNECT_ASYNC_METHOD_ARGS_FOR_ANALYSIS_IN_STRUCT \
	uint64_t scalar_input_addr_of_global;\
    uint64_t scalar_input_addr_of_stack;\
    uint64_t inband_input_addr_of_global;\
    uint64_t inband_input_addr_of_stack;\
    uint64_t ool_input_addr_of_global;\
    uint64_t ool_input_addr_of_stack;\
    uint64_t inband_output_addr_of_global;\
    uint64_t inband_output_addr_of_stack;\
    uint64_t scalar_output_addr_of_global;\
    uint64_t scalar_output_addr_of_stack;\
    uint64_t ool_output_addr_of_global;\
    uint64_t ool_output_addr_of_stack;\
	
typedef struct
{
    //is_io_connect_async_method_args_t args;
    //io_object_t  object;
    //char szClassName[PATH_MAX +1]; //For analysis
	IS_IO_CONNECT_ASYNC_METHOD_ARGS_IN_STRUCT
	IS_IO_CONNECT_ASYNC_METHOD_ARGS_FOR_ANALYSIS_IN_STRUCT
} is_io_connect_async_method, is_io_connect_async_method_t;

typedef struct{

	IS_IO_CONNECT_ASYNC_METHOD_ARGS_IN_STRUCT
    
} is_io_connect_async_method_args, is_io_connect_async_method_args_t;


typedef struct{
    char fuzzTag[0x100];
    char recordReproducedName[PATH_MAX +1];
    fuzz_env env;
    fuzz_noise_t noise;
    union
    {
        is_io_connect_async_method_t entry;
    } original;
    union
    {
        is_io_connect_async_method_t entry;
    } now;
} _is_io_connect_async_method_fuzz_sample_info, is_io_connect_async_method_fuzz_sample_info_t;




kern_return_t trampline_is_io_connect_async_method(IS_IO_CONNECT_ASYNC_METHOD_ARGS);
__attribute__ ((naked)) void inlined_part_is_io_connect_async_method();

#endif
