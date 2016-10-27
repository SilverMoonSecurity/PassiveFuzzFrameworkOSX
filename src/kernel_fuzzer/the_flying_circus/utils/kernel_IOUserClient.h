//moony_li@trendmicro.com
//@Flyic of twitter

#ifndef the_flying_circus_kernle_iouserclient_h
#define the_flying_circus_kernle_iouserclient_h

#include <sys/types.h>
#include <IOKit/IOTypes.h>

typedef kern_return_t (* fn_is_io_object_get_class_t)
(
    io_object_t object,
    io_name_t   className
 );

kern_return_t k_is_io_connect_get_service
(
 io_object_t connection,
 io_object_t   *service
 );
kern_return_t get_serivce_name_of_connection(
                                             io_object_t object,
                                             io_name_t   className
                                             );
kern_return_t k_is_io_object_get_class
(
 io_object_t object,
 io_name_t   className
 );

vm_prot_t get_protection(vm_map_t task_port, mach_vm_address_t address);

__attribute__ ((naked))  uint64_t get_current_cpu_no();
boolean_t is_address_possible_txt(mach_vm_address_t address);
boolean_t is_address_readable(mach_vm_address_t address);
boolean_t is_address_writeable(mach_vm_address_t address);
boolean_t is_address_range_readable(mach_vm_address_t address, uint64_t uLen);
boolean_t is_address_range_writeable(mach_vm_address_t address, uint64_t uLen);
mach_vm_address_t getVirtualAddressFromIOMapMemory(mach_vm_address_t *this);
uint64_t getLengthFromIOMapMemory(mach_vm_address_t *this);
#endif
