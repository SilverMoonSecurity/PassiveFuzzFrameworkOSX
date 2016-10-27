//moony_li@trendmicro.com
//@Flyic of twitter

#include <string.h>
//#include <ctypes.h>
//#include <stdlib.h>
#include "kernel_IOUserClient.h"
#include "kernel_info.h"
#include <mach/task.h>
#include <mach/vm_map.h>

#include "proc_utils.h"
#include "function_pointers.h"

extern struct kernel_info g_kernel_info;


kern_return_t get_serivce_name_of_connection
(
 io_object_t object,
 io_name_t   className
 )
{
    kern_return_t kr = KERN_FAILURE;
    io_object_t service = NULL;
    kr = k_is_io_connect_get_service(object, &service);
    if (KERN_SUCCESS == kr)
    {
        if (service)
        {
            kr = kr | k_is_io_object_get_class(service, className);
        }
    }
    return kr;
}


void ftest()
{
    
    uint64_t  fnAddr_panic_hook = solve_kernel_symbol(&g_kernel_info, "_panic_hook");
}
static fn_is_io_object_get_class_t fnAddr_is_io_connect_get_service = NULL;
kern_return_t k_is_io_connect_get_service
(
 io_object_t connection,
 io_object_t   *service
 )
{
    kern_return_t kr = KERN_FAILURE;
    mach_vm_address_t addrVtable = 0;
    //moony modify: unexpected crash here
    //strcpy(className, "moony_undefined");
    //return kr;
    //char slassName[0x200] = {0};
    if (!fnAddr_is_io_connect_get_service)
    {
        fnAddr_is_io_connect_get_service = solve_kernel_symbol(&g_kernel_info, "_is_io_connect_get_service");
    }
    if (fnAddr_is_io_connect_get_service)
    {
        if (is_address_readable(fnAddr_is_io_connect_get_service))
        {if ( connection && is_address_readable(connection))
        {
            addrVtable = *(mach_vm_address_t *)connection;
            if (addrVtable && is_address_readable(addrVtable))
            {
                kr = fnAddr_is_io_connect_get_service(connection, service);
            }
        }
        }
    }

    return kr;
}



static fn_is_io_object_get_class_t fnAddr_is_io_object_get_class = NULL;
kern_return_t k_is_io_object_get_class
(
 io_object_t object,
 io_name_t   className
 )
{
    kern_return_t kr = KERN_FAILURE;
    className[0]='\0';
    mach_vm_address_t addrVtable = 0;
    //moony modify: unexpected crash here
    //strcpy(className, "moony_undefined");
    //return kr;
    //char slassName[0x200] = {0};
    if (!fnAddr_is_io_object_get_class)
    {
        fnAddr_is_io_object_get_class = solve_kernel_symbol(&g_kernel_info, "_is_io_object_get_class");
    }
    if (fnAddr_is_io_object_get_class)
    {
        if (is_address_readable(fnAddr_is_io_object_get_class))
            {if ( object && is_address_readable(object))
                {
                    addrVtable = *(mach_vm_address_t *)object;
                    if (addrVtable && is_address_readable(addrVtable))
                        {
                            kr = fnAddr_is_io_object_get_class(object,className);
                        }
                }
            }
    }
    if (!strlen(className))
    {
        strcpy(className, OBJECT_CLASS_NAME_NO_FOUND);
        
    }
    return kr;
}

boolean_t is_address_property(mach_vm_address_t address, vm_prot_t prot)
{
    boolean_t bAble = false;
    proc_t pProc = proc_self();
    if (pProc)
    {
        bAble =  get_proc_mem_protection(pProc, address) & prot;
        proc_rele(pProc);
    }
    return  bAble;
}

boolean_t is_address_readable(mach_vm_address_t address)
{
    return is_address_property(address, VM_PROT_READ);
}

boolean_t is_address_writeable(mach_vm_address_t address)
{
    return is_address_property(address, VM_PROT_WRITE);
}


boolean_t is_address_kernel_txt(mach_vm_address_t address)
{
    boolean_t bRet = false;
    if (address>=g_kernel_info.running_text_addr
        &&address<= (g_kernel_info.running_text_addr+g_kernel_info.text_size))
    {
        bRet = true;
    }
    return bRet;
}

boolean_t is_address_possible_txt(mach_vm_address_t address)
{
    boolean_t bRet = false;
    boolean_t bRetKernel = false;
    boolean_t bRetDriver = false;
    bRetKernel = is_address_kernel_txt(address);
    bRetDriver = (address >0xffffff7f80000000 && address<0xffffff7fefffffff);
    return bRet=(bRetKernel||bRetDriver);
}

boolean_t is_address_range_readable(mach_vm_address_t address, uint64_t uLen)
{
    return is_address_range_property(address, uLen,VM_PROT_READ);
}

boolean_t is_address_range_writeable(mach_vm_address_t address, uint64_t uLen)
{
    return is_address_range_property(address, uLen,VM_PROT_WRITE);
}

boolean_t is_address_range_property(mach_vm_address_t address, uint64_t uLen,vm_prot_t prot)
{
    boolean_t bAble = true;
    boolean_t bAbleTemp = false;
    proc_t pProc = proc_self();
    mach_vm_address_t tempAddress = 0;
    if (pProc)
    {
        //Begin check
        bAbleTemp =  get_proc_mem_protection(pProc, address) & prot;
        bAble = bAble && bAbleTemp;
        //Middel check
        bAbleTemp =  get_proc_mem_protection(pProc, address+uLen/2) & prot;
        bAble = bAble && bAbleTemp;
#if 0
        for(uint64_t i=0;i+=1024*4;i<uLen)
        {
            bAbleTemp =  get_proc_mem_protection(pProc, address+i) & prot;
            if (!bAbleTemp)
            {
                bAble = false;
                break;
            }
        }
#endif
        //End check
        if (uLen)
        {//Consider the last byte
            bAbleTemp =  get_proc_mem_protection(pProc, address+uLen-1) & prot;
            bAble = bAble && bAbleTemp;
        }
        proc_rele(pProc);
    }
    return  bAble;
}

vm_prot_t get_proc_mem_protection(proc_t p, mach_vm_address_t address)
{
    vm_prot_t prot = 0;
    struct task *task = (struct task*)(p->task);
    vm_map_t task_port = (vm_map_t)task->map;
    prot = get_protection(task_port, address);
    return prot;
}

/*
 * retrieve the current memory protection flags of an address
 */
vm_prot_t
get_protection(vm_map_t task_port, mach_vm_address_t address)
{
    vm_region_basic_info_data_64_t info = { 0 };
    mach_vm_size_t size = 0;
    mach_port_t object_name = 0;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    
    if (_mach_vm_region == NULL) _mach_vm_region = (void*)solve_kernel_symbol(&g_kernel_info, "_mach_vm_region");
    
    if (_mach_vm_region(task_port, &address, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object_name))
    {
#if DEBUG
        //moony_modify//printf("[ERROR] get_protection failed!\n");
#endif
        return -1;
    }
    // we just return the protection field
    return(info.protection);
}


mach_vm_address_t getVirtualAddressFromIOMapMemory(mach_vm_address_t *this)
{
    return *(mach_vm_address_t *)((char *)this+0x28);
}

uint64_t getLengthFromIOMapMemory(mach_vm_address_t *this)
{
    return *(mach_vm_address_t *)((char *)this+0x30);
}


__attribute__ ((naked))  uint64_t get_current_cpu_no()
{
     __asm__ volatile (
     "  mov  %gs:0x1c, %rax\n"    );
    __asm__ volatile (
                      "  ret"    );
    /*
    __asm__ volatile (
                      "  mov %1, %%rax\n"
                      //"  jmp *%%rax\n"
                      "  mov %%rax, %0\n"
                      :"=r" (uRet)
                      :"r" (uJmpBackAddr)
                      :"%rax");
     */
    
}