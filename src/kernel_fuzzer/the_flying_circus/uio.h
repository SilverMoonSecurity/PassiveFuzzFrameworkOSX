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
 * uio.h
 * ripped from bsd/sys/uio_internal.h
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


#ifndef the_flying_circus_uio_h
#define the_flying_circus_uio_h

#include <mach/mach_types.h>
#include <sys/types.h>
#include <sys/kernel_types.h>
#include <sys/uio.h>
#include <mach/kern_return.h>
#include <mach/mach_vm.h>
#include <libkern/libkern.h>
#include <sys/param.h>

uio_t uio_createwithbuffer(int a_iovcount, off_t a_offset, int a_spacetype, int a_iodirection, void *a_buf_p, size_t a_buffer_size );

/*
 * user / kernel address space type flags.
 * WARNING - make sure to check when adding flags!  Be sure new flags
 * don't overlap the definitions in uio.h
 */
//      UIO_USERSPACE                           0       defined in uio.h
#define UIO_USERISPACE                  1
//      UIO_SYSSPACE                            2       defined in uio.h
#define UIO_PHYS_USERSPACE              3
#define UIO_PHYS_SYSSPACE               4
//      UIO_USERSPACE32                         5       defined in uio.h
#define UIO_USERISPACE32                6
#define UIO_PHYS_USERSPACE32    7
//      UIO_USERSPACE64                         8       defined in uio.h
#define UIO_USERISPACE64                9
#define UIO_PHYS_USERSPACE64    10
//      UIO_SYSSPACE32                          11      defined in uio.h
//  UIO_PHYS_SYSSPACE32                 12      reserved, never used. Use UIO_PHYS_SYSSPACE
//  UIO_SYSSPACE64                              13      reserved, never used. Use UIO_SYSSPACE
//  UIO_PHYS_SYSSPACE64                 14      reserved, never used. Use UIO_PHYS_SYSSPACE

/* use kern_iovec for system space requests */
struct kern_iovec {
    u_int64_t       iov_base;       /* Base address. */
    u_int64_t       iov_len;        /* Length. */
};

/* use user_iovec for user space requests */
struct user_iovec {
    user_addr_t     iov_base;       /* Base address. */
    user_size_t     iov_len;        /* Length. */
};

/* use user32_iovec/user64_iovec for representing
 * in-memory structures in 32-64 processes during copyin */
struct user32_iovec {
    uint32_t        iov_base;       /* Base address. */
    uint32_t        iov_len;        /* Length. */
};

struct user64_iovec {
    uint64_t        iov_base;       /* Base address. */
    uint64_t        iov_len;        /* Length. */
};

union iovecs {
    struct kern_iovec       *kiovp;
    struct user_iovec       *uiovp;
};

/* WARNING - use accessor calls for uio_iov and uio_resid since these */
/* fields vary depending on the originating address space. */
struct uio {
    union iovecs    uio_iovs;               /* current iovec */
    int             uio_iovcnt;             /* active iovecs */
    off_t           uio_offset;
    enum uio_seg    uio_segflg;
    enum uio_rw     uio_rw;
    user_ssize_t    uio_resid_64;
    int             uio_size;               /* size for use with kfree */
    int             uio_max_iovs;   /* max number of iovecs this uio_t can hold */
    u_int32_t       uio_flags;
};

/* values for uio_flags */
#define UIO_FLAGS_INITED                0x00000001
#define UIO_FLAGS_WE_ALLOCED    0x00000002
#define UIO_FLAGS_IS_COMPRESSED_FILE    0x00000004

/*
 * UIO_SIZEOF - return the amount of space a uio_t requires to
 *      contain the given number of iovecs.  Use this macro to
 *  create a stack buffer that can be passed to uio_createwithbuffer.
 */
#define UIO_SIZEOF( a_iovcount ) \
( sizeof(struct uio) + (MAX(sizeof(struct user_iovec), sizeof(struct kern_iovec)) * (a_iovcount)) )

#define UIO_IS_USER_SPACE32( a_uio_t )  \
( (a_uio_t)->uio_segflg == UIO_USERSPACE32 || (a_uio_t)->uio_segflg == UIO_PHYS_USERSPACE32 || \
(a_uio_t)->uio_segflg == UIO_USERISPACE32 )
#define UIO_IS_USER_SPACE64( a_uio_t )  \
( (a_uio_t)->uio_segflg == UIO_USERSPACE64 || (a_uio_t)->uio_segflg == UIO_PHYS_USERSPACE64 || \
(a_uio_t)->uio_segflg == UIO_USERISPACE64 )
#define UIO_IS_USER_SPACE( a_uio_t )  \
( UIO_IS_USER_SPACE32((a_uio_t)) || UIO_IS_USER_SPACE64((a_uio_t)) || \
(a_uio_t)->uio_segflg == UIO_USERSPACE || (a_uio_t)->uio_segflg == UIO_USERISPACE || \
(a_uio_t)->uio_segflg == UIO_PHYS_USERSPACE )
#define UIO_IS_SYS_SPACE( a_uio_t )  \
( (a_uio_t)->uio_segflg == UIO_SYSSPACE || (a_uio_t)->uio_segflg == UIO_PHYS_SYSSPACE || \
(a_uio_t)->uio_segflg == UIO_SYSSPACE32 )

#endif
