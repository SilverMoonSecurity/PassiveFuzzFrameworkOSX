//
//  Mutext.h
//  flyic
//
//  Created by flyic on 1/14/16.
//  Copyright © 2016 reverser. All rights reserved.
//

#ifndef Mutext_h
#define Mutext_h
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
//#include <stdio.h>
kern_return_t init_mutex(
	lck_mtx_t **pp_mutex,
	lck_grp_t **pp_mutex_group,
	char *szMutexName);
	
kern_return_t un_init_mutex(
	lck_mtx_t **pp_mutex,
	lck_grp_t **pp_mutex_group);
#endif /* Mutext_h */
