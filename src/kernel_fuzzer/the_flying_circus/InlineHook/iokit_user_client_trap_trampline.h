//twitter @flyic
//moony_li@trendmicor.com
#ifndef iokit_user_client_trap_trampline_h
#define iokit_user_client_trap_trampline_h

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

typedef struct{
/*
	PAD_ARG_(void *, userClientRef);
	PAD_ARG_(uint32_t, index);
	PAD_ARG_(void *, p1);
	PAD_ARG_(void *, p2);
	PAD_ARG_(void *, p3);
	PAD_ARG_(void *, p4);
	PAD_ARG_(void *, p5);
    	PAD_ARG_8
	PAD_ARG_(void *, p6);
    */
    void * userClientRef;
	uint32_t  index;
	void *  p1;
	void *  p2;
	void *  p3;
	void *  p4;
	void *  p5;
	void * p6;
} iokit_user_client_trap_args, iokit_user_client_trap_args_t;


typedef struct
{
    iokit_user_client_trap_args_t args;
    io_object_t  object;
    char szClassName[PATH_MAX +1]; //For analysis
} iokit_user_client_trap, iokit_user_client_trap_t;



typedef struct{
    char fuzzTag[0x100];
    char recordReproducedName[PATH_MAX +1];
    fuzz_env env;
    fuzz_noise_t noise;
    union
    {
        iokit_user_client_trap_t entry;
    } original;
    union
    {
        iokit_user_client_trap_t entry;
    } now;
} _user_client_trap_fuzz_sample_info, user_client_trap_fuzz_sample_info_t;




kern_return_t trampline_iokit_user_client_trap(iokit_user_client_trap_args *args);
__attribute__ ((naked)) void inlined_part_iokit_user_client_trap();

#endif
