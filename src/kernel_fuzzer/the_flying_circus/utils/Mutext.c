//
//  Mutext.c
//  flyic, moony_li@trendmicro.com
//
//  Created by flyic on 1/14/16.
//  Copyright © 2016 reverser. All rights reserved.
//

#include "Mutext.h"
kern_return_t init_mutex(
	lck_mtx_t **pp_mutex,
	lck_grp_t **pp_mutex_group,
	char *szMutexName)
{
    kern_return_t  kr =KERN_FAILURE;
    *pp_mutex_group = lck_grp_alloc_init(szMutexName, LCK_GRP_ATTR_NULL);
    if (!*pp_mutex_group) {
        printf("init_mutex: lck_grp_alloc_init(%s) failed\n", szMutexName);
        return KERN_FAILURE;
    }
    
    
    *pp_mutex = lck_mtx_alloc_init(*pp_mutex_group, LCK_ATTR_NULL);
    if (!*pp_mutex) {
        
        lck_grp_free(*pp_mutex_group);
        
        *pp_mutex_group = NULL;
        *pp_mutex = NULL;
        
        printf("init_mutex: lck_mtx_alloc_init(*pp_mutex_group) failed\n");
        
        return KERN_FAILURE;
    }
    

    
    kr = KERN_SUCCESS;
    return kr;
}

kern_return_t un_init_mutex(
	lck_mtx_t **pp_mutex,
	lck_grp_t **pp_mutex_group)
{
    kern_return_t kr = KERN_SUCCESS;

    if (*pp_mutex)
    {
        lck_mtx_free(*pp_mutex, *pp_mutex_group);
        *pp_mutex = NULL;
    }
    if(*pp_mutex_group )
    {
        lck_grp_free(*pp_mutex_group);
        *pp_mutex_group = NULL;
    }
    return kr;
}
