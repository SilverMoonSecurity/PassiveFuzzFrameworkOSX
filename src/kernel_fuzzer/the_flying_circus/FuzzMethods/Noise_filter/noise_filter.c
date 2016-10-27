//@Flyic
//moony_li@trendmicro.com

#include <string.h>
#include "noise_filter.h"
#include "proc.h"
#include "str_utils.h"
#include "configuration.h"
//#include <IOkit/IOUserClient.h>


//FILTER_STATE gCurrentFilterState = UNKNOWN_STATE;

boolean_t match_int(uint64_t uTarget, uint64_t uPattern)
{
    boolean_t bMatched= false;
    if (uPattern == ANY_MATCH_INTEGER)
    {
        bMatched = true;
        goto _EXIT;
    }
    if (uTarget == uPattern)
    {
        bMatched = true;
    }
    
_EXIT:
    return bMatched;
}

boolean_t is_int_range_bypass(uint64_t uFrom, uint64_t uTo)
{
    if (uFrom == ANY_MATCH_INTEGER && uTo == ANY_MATCH_INTEGER)
    {
        return true;
    }
    return false;
}
boolean_t match_int_range(uint64_t uTarget, uint64_t uFrom, uint64_t uTo)
{
    boolean_t bMatched= false;
   if (uFrom == ANY_MATCH_INTEGER && uTo == ANY_MATCH_INTEGER)
   {
       bMatched = true;
   }
   else if (uFrom == ANY_MATCH_INTEGER)
   {
       if (uTarget<=uTo)
       {
           bMatched = true;
       }
   }
   else if (uTo == ANY_MATCH_INTEGER)
   {
       if (uTarget>=uFrom)
       {
           bMatched = true;
       }
   }
   else
   {
       if (uFrom<= uTarget&& uTarget<=uTo)
       {
           bMatched = true;
       }
    }
    
    return bMatched;
}



boolean_t match_str(char longName[PATH_MAX], char entryName[PATH_MAX] )
{
    boolean_t bMatched = false;
    if (!longName)
    {
        goto _EXIT;
    }
    if (!entryName)
    {
        bMatched = true;
        goto _EXIT;
    }    
    ////////////////////////////
    if (entryName[0] == '*')
    {
        bMatched = true;
        goto _EXIT;
    }      



    char name[PATH_MAX] ={0};
    char longNameTemp[PATH_MAX] = {0};
    strncpy(name, entryName, PATH_MAX);
    lower_str(name,PATH_MAX);
    strncpy(longNameTemp, longName, PATH_MAX);
    lower_str(longNameTemp, PATH_MAX);    
    if ( str_str(longNameTemp, name))
    {
        bMatched = true;
        ////moony_modify//printf("[DEBUG] found whitelisting name [%s] at #index %d\r\n", longName, i);
    }
    
_EXIT:    
    return bMatched;
}

boolean_t match_str_list(char longName[PATH_MAX], char listing_name[][PATH_MAX], unsigned int uLen)
{
    boolean_t bMatched = false;
    if ( !listing_name || uLen ==0)
    {
        bMatched = true;
        goto _EXIT;
    }
    if (!longName)
    {
        goto _EXIT;
    }
    for(int i = 0; i<uLen;i++)
    {
        
        char name[PATH_MAX] ={0};
        char longNameTemp[PATH_MAX] = {0};
        strncpy(name, listing_name[i], PATH_MAX);
        lower_str(name,PATH_MAX);
        strncpy(longNameTemp, longName, PATH_MAX);
        lower_str(longNameTemp, PATH_MAX);
        //if (strnstr(path,name,PATH_MAX))
        //if(strcasestr(path, name))
        if (name[0] == '*')
        {
            bMatched = true;
            break;
        }            
        if ( str_str(longNameTemp, name))
        {
            bMatched = true;
            ////moony_modify//printf("[DEBUG] found whitelisting name [%s] at #index %d\r\n", longName, i);
            break;
        }
        
    }
    
_EXIT:

    return bMatched;
}


boolean_t should_match_by_proc_name(
                                     char listing_proc_name[][PATH_MAX],
                                     unsigned int uLen)
{
    boolean_t bMatched = true;
    pid_t pid = 0;
    proc_t pProc = proc_self();
    pid = proc_pid(pProc);
    char path [PATH_MAX+1] = {0};
    proc_name(pid, path,PATH_MAX);
    path[PATH_MAX] = '\0';
    
    //toupper('c');
    ////moony_modify//printf("[DEBUG] current proc_name[%s]\r\n", path);
    //__asm__ volatile ("int3");
    bMatched = match_str_list(
                                path,
                                listing_proc_name,
                                uLen);
_EXIT:
    if (pProc)
    {
        proc_rele(pProc);
    }
    return bMatched;
}


boolean_t should_match_by_class_name(
                                      io_object_t object,
                                      char listing_class_name[][PATH_MAX],
                                      unsigned int uLen)
{
    boolean_t bMatched = true;
    char szClassName[PATH_MAX+1] = {0};
    //IOObjectGetClass(object, szClassName);
    k_is_io_object_get_class(object, szClassName);
    ////moony_modify//printf("[DEBUG] object=0x%llx, className =%s\r\n",
           //object,
           //szClassName);
    //__asm__ volatile ("int3");
    bMatched = match_str_list(
                                szClassName,
                                listing_class_name,
                                uLen);
_EXIT:
    return bMatched;
}




