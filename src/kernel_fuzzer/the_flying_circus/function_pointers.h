/*
 *   _____   _                          ___     _      _  _     _              __ _
 *  |_   _| | |_      ___      o O O   | __|   | |    | || |   (_)    _ _     / _` |
 *    | |   | ' \    / -_)    o        | _|    | |     \_, |   | |   | ' \    \__, |
 *   _|_|_  |_||_|   \___|   TS__[O]  _|_|_   _|_|_   _|__/   _|_|_  |_||_|   |___/
 * _|"""""|_|"""""|_|"""""| {======|_| """ |_|"""""|_| """"|_|"""""|_|"""""|_|"""""|
 * "`-0-0-'"`-0-0-'"`-0-0-'./o--000'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'
 *            ___      _
 *    o O O  / __|    (_)      _ _    __     _  _     ___
 *   o      | (__     | |     | '_|  / _|   | +| |   (_-<
 *  TS__[O]  \___|   _|_|_   _|_|_   \__|_   \_,_|   /__/_
 *  {======|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|
 * ./o--000'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'
 *
 * And now for something completely different...
 *
 * A Mountain Lion rootkit for Phrack #69!
 *
 * Copyright (c) fG!, 2012, 2013 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * function_pointers.h
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef the_flying_circus_function_pointers_h
#define the_flying_circus_function_pointers_h

#include "proc.h"

extern void (*_proc_list_lock)(void);
extern void (*_proc_list_unlock)(void);
extern void (*_vm_map_deallocate)(register vm_map_t	map);
extern void (*_vm_map_reference)(register vm_map_t map);
extern void (*_psignal)(proc_t p, int signum);
extern void (*_proc_fdlock)(proc_t p);
extern void (*_proc_fdunlock)(proc_t p);
extern void (*_lck_mtx_lock)(lck_mtx_t *lck);
extern void (*_lck_mtx_unlock)(lck_mtx_t *lck);
extern void (*_vnode_lock)(vnode_t vp);
extern void (*_vnode_unlock)(vnode_t vp);
extern void (*_kernel_debug)(uint32_t debugid, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, __unused uintptr_t arg5);
extern int (*_fp_getfvp)(proc_t p, int fd, struct fileproc **resultfp, struct vnode **resultvp);
extern vm_map_t (*_vm_map_switch)(vm_map_t	map);
extern kern_return_t (*_task_suspend)(task_t target_task);
extern kern_return_t (*_vm_map_read_user)(vm_map_t map, vm_map_offset_t src_addr, void *dst_p, vm_size_t size);
extern kern_return_t (*_vm_map_write_user)(vm_map_t map, void *src_p, vm_map_address_t dst_addr, vm_size_t size);
extern kern_return_t (*_mach_vm_protect)(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
extern kern_return_t (*_vm_map_copyin)(vm_map_t	src_map, vm_map_address_t src_addr, vm_map_size_t len, boolean_t src_destroy, vm_map_copy_t *copy_result);
extern kern_return_t (*_vm_map_copyout)(vm_map_t dst_map, vm_map_address_t	*dst_addr, vm_map_copy_t copy);
extern kern_return_t (*_mach_vm_copy)(vm_map_t target_task, mach_vm_address_t source_address, mach_vm_size_t size, mach_vm_address_t dest_address);
extern kern_return_t (*_mach_vm_region)(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);
extern kern_return_t (*_task_release)(task_t task);
extern kern_return_t (*_task_hold)(register task_t task);

#endif
