//twitter @flyic
//moony_li@trendmicor.com
#ifndef the_flying_circus_is_io_connect_method_trampline_functions_h
#define the_flying_circus_is_io_connect_method_trampline_functions_h

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

//extern union fuzz_noise_t;
//extern struct noise_bypass_by_class_name_t ;
//extern struct noise_bypass_by_proc_t uProc;


#define IS_IO_CONNECT_METHOD_ARGS   \
io_connect_t connection, \
uint32_t selector,  \
io_scalar_inband64_t scalar_input, \
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
mach_vm_size_t *ool_output_size

#define IS_IO_CONNECT_METHOD_ARGS_VAR_LIST   \
connection, \
selector,  \
scalar_input, \
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

typedef struct
{
    boolean_t bBypassByProcName;
    boolean_t bLastMatch;
    char path[PATH_MAX+1];
}
noise_bypass_by_proc, noise_bypass_by_proc_t;

typedef struct
{
    boolean_t bBypassByClassName;
    boolean_t bLastMatch;
    char szClassName[PATH_MAX+1];
}
noise_bypass_by_class_name, noise_bypass_by_class_name_t;





typedef struct
{
    io_object_t connection;
    char szClassName[PATH_MAX +1]; //For analysis
    
    uint32_t selector;
    char szProcName[PATH_MAX +1];
    //mach_msg_type_number_t inband_inputCnt;
	//uint64_t inband_input_addr_of_global;//For analysis
    //io_struct_inband_t inband_input;
    //uint64_t inband_input_addr_of_stack;//For analysis
    
    /////////Input
    io_scalar_inband64_t scalar_input;
    uint64_t scalar_input_addr_of_global;//For analysis
    uint64_t scalar_input_addr_of_stack;//For analysis
    mach_msg_type_number_t scalar_inputCnt;
    
    io_struct_inband_t inband_input;
    uint64_t inband_input_addr_of_global;//For analysis
    uint64_t inband_input_addr_of_stack;//For analysis
    mach_msg_type_number_t inband_inputCnt;
    
    mach_vm_address_t ool_input;
    uint64_t ool_input_addr_of_global;//For analysis
    uint64_t ool_input_addr_of_stack;//For analysis
    mach_vm_size_t ool_input_size;
    ////////Output
    io_struct_inband_t inband_output;
    uint64_t inband_output_addr_of_global;//For analysis
    uint64_t inband_output_addr_of_stack;//For analysis
    mach_msg_type_number_t *inband_outputCnt;
    
    io_scalar_inband64_t scalar_output;
    uint64_t scalar_output_addr_of_global;//For analysis
    uint64_t scalar_output_addr_of_stack;//For analysis
    mach_msg_type_number_t *scalar_outputCnt;
    
    mach_vm_address_t ool_output;
    uint64_t ool_output_addr_of_global;//For analysis
    uint64_t ool_output_addr_of_stack;//For analysis
    mach_vm_size_t *ool_output_size
}
is_io_connect_method, is_io_connect_method_t;


typedef struct
{
    uint32_t bConnection;
    uint32_t bSelector;
    
    uint32_t bScalar_inputCnt;
    uint32_t bScalar_input;
    uint32_t bInband_inputCnt;
    uint32_t bInband_input;
    uint32_t bOol_input_size;
    uint32_t bOol_input;

    uint32_t bScalar_outputCnt;
    uint32_t bScalar_output;
    uint32_t bInband_outputCnt;
    uint32_t bInband_output;
    uint32_t bOol_output_size;
    uint32_t bOol_output;
}
is_io_connect_method_changed, is_io_connect_method_changed_t;

typedef union
{
    noise_bypass_by_class_name_t uClass;
    noise_bypass_by_proc_t uProc;
}
fuzz_noise_entry, fuzz_noise_entry_t;


typedef struct
{
    char procName[PATH_MAX];
    uint64_t uid;
    char driverBundleName[PATH_MAX];
    char driverClassName[PATH_MAX];
    uint64_t selFunctionNO;

} detail_control_entry_t, *pdetail_control_entry_t;

typedef struct
{
    boolean_t bMatched;
    detail_control_entry_t matchedRule;
}
filter_info_entry, filter_info_entry_t;


typedef struct
{
    filter_info_entry_t entry;
}
white_filter_info, white_filter_info_t;

typedef struct
{
    filter_info_entry_t entry;
}
black_filter_info, black_filter_info_t;

typedef struct
{
    //noise_bypass_by_class_name_t eClass;
    //noise_bypass_by_proc_t eProc;
    white_filter_info_t white;
    black_filter_info_t black;
}
fuzz_noise, fuzz_noise_t;


typedef struct
{
    io_object_t service;
    char szServiceClassName[PATH_MAX+1];
    uint32_t nType;
    io_connect_t connection;
    char szConnectionClassName[PATH_MAX+1]
}
service_open_connection_entry, service_open_connection_entry_t;

typedef struct
{
    service_open_connection_entry_t table[SERVICE_CONNECTION_TABLE_MAX];
    uint32_t uCurrentIndex;
    uint32_t uMax;
}service_open_connection_table, service_open_connection_table_t;

typedef struct
{
    io_connect_t connection;
    char szClassName[PATH_MAX+1];
    io_object_t service;
    char szServiceClassName[PATH_MAX+1];
    char szProcName[PATH_MAX+1];
    pid_t uCpuNo;
    thread_t thread;
    proc_t proc;
    uint64_t uCounter;
    uint64_t uIndex;
}
fuzz_env, fuzz_env_t;

typedef struct{
    //char fuzzTag[0x100];
    //char recordReproducedName[PATH_MAX +1];
    fuzz_env env;
    fuzz_noise_t noise;
    union
    {
        is_io_connect_method_t entry;
    } original;
    union
    {
        is_io_connect_method_t entry;
    } now;
    is_io_connect_method_changed_t changed;
} _fuzz_sample_info, fuzz_sample_info_t;




typedef kern_return_t (* fn_is_io_connect_method_t)
(
 struct OSObject * connection,
	//io_connect_t connection,
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
	mach_vm_size_t *ool_output_size
 );
///////////////////////////
//kern_return_t install_inline_hook(char * symbol);
//kern_return_t un_install_inline_hook(char *symbol);
//*
//__attribute__ ((naked))
kern_return_t trampline_is_io_connect_method
(
    struct OSObject * connection,
	//io_connect_t connection,
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
	mach_vm_size_t *ool_output_size
 );


/**/
__attribute__ ((naked)) void inlined_part_is_io_connect_method();

////////////////////////////////////////////////////////////////////////

__attribute__ ((naked)) void inlined_part_is_io_service_open_extended();
//*
//args order in source code of Apple
#define IS_IO_SERVICE_OPEN_EXTENDED_ARGS   \
io_object_t _service,\
task_t owningTask,\
uint32_t connect_type,\
NDR_record_t ndr,\
io_buf_ptr_t properties,\
mach_msg_type_number_t propertiesCnt,\
kern_return_t *result,\
io_object_t *connection


#define IS_IO_SERVICE_OPEN_EXTENDED_VAR_LIST   \
_service,\
owningTask,\
connect_type,\
ndr,\
properties,\
propertiesCnt,\
result,\
connection

#define IS_IO_SERVICE_OPEN_EXTENDED_VAR_LIST_FIXED   \
_service,\
owningTask,\
connect_type,\
*((NDR_record_t *)&ndr),\
properties,\
propertiesCnt,\
result,\
connection
/**/

/*
//Args order in lldb debug of kernel
#define IS_IO_SERVICE_OPEN_EXTENDED_ARGS   \
io_object_t _service,\
task_t owningTask,\
uint32_t connect_type,\
io_buf_ptr_t properties,\
mach_msg_type_number_t propertiesCnt,\
kern_return_t *result,\
io_object_t *connection,\
NDR_record_t ndr


#define IS_IO_SERVICE_OPEN_EXTENDED_VAR_LIST   \
_service,\
owningTask,\
connect_type,\
properties,\
propertiesCnt,\
result,\
connection,\
ndr

#define IS_IO_SERVICE_OPEN_EXTENDED_VAR_LIST_FIXED   \
_service,\
owningTask,\
connect_type,\
properties,\
propertiesCnt,\
result,\
connection,\
*((NDR_record_t *)&ndr)

 */

kern_return_t trampline_is_io_service_open_extended (IS_IO_SERVICE_OPEN_EXTENDED_ARGS);
#endif
