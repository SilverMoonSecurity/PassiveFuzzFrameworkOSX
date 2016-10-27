//moony_li@trendmicro.com
//@flyic

#include <stdint.h>
#include <string.h>
//#include <ctypes.h>
//#include <stdlib.h>
#include <sys/malloc.h>
#include "StackTrace.h"
#include <IOKit/IOTypes.h>
#include "kernel_info.h"
//Must include this to avoid movsxd rsi, eax for  solve_kernel_symbol
extern struct kernel_info g_kernel_info;
cframe_t *getBaseFrame(cframe_t * _frame)
{
	cframe_t * stackptr = _frame;
	uint32_t uLevel = 0;
	while(stackptr&&uLevel<MAX_FRAME_NUMBER)
	{
			if (!stackptr->prev)
			{
				break;
			}
			uLevel++;
			stackptr = stackptr->prev;
	}
	return stackptr;
}


boolean_t matchStackItem(cframe_t * _frame,uint32_t uCurrLevel, stack_match_item_t *pItem)
{
    boolean_t bMatchItem = false;
    boolean_t bMatchSymbol = false;
    boolean_t bMatchAddr = false;
    boolean_t bMatchLevelRange = false;

    if(!(_frame&&pItem))
    {
        goto _EXIT;
    }
    bMatchItem = false;
    
    //Match rontine name
    if (pItem->symbolRoutine.rountineName[0]=='*')
    {
        bMatchSymbol = true;
    }
    else
    {
        if (pItem->symbolRoutine.uCache == STACK_ANY_INTEGER)
            //Not using cache yet
        {
            pItem->symbolRoutine.uCache =  solve_kernel_symbol(&g_kernel_info, pItem->symbolRoutine.rountineName);
            //__asm__ volatile ("int3");
            
        }
        //Match rontine address found by name
        if (_frame->caller >=pItem->symbolRoutine.uCache+pItem->uOffSetFrom&&
            _frame->caller<= pItem->symbolRoutine.uCache+pItem->uOffSetTo)
        {
            bMatchSymbol = true;
        }
    }
    if (!bMatchSymbol )
    {
        goto _EXIT;
    }
    
    //Match routine address
    if (pItem->addressRoutine == STACK_ANY_INTEGER)
    {
        bMatchAddr = true;
    }
    else
    {
        if (pItem->addressRoutine>=pItem->uOffSetFrom&&
            pItem->addressRoutine<=pItem->uOffSetTo)
        {
            bMatchAddr = true;
        }
    }
    if (!bMatchAddr)
    {
        goto _EXIT;
    }
    
    
    //Match level range
    if (pItem->uLevelLow<=uCurrLevel&&
        uCurrLevel<=pItem->uLevelHigh)
    {
        bMatchLevelRange = true;
    }
    if (!bMatchLevelRange)
    {
        goto _EXIT;
    }
    
    bMatchItem = true;
    
_EXIT:
    return bMatchItem;
}

boolean_t matchFrame(cframe_t * _frame,
                     uint32_t uCurrLevel,
                     stack_match_item_t *stack_match_item_list,
                     uint64_t stack_match_item_list_size)
{
    stack_match_item_t *ret=NULL;
    cframe_t * pFrame = 0;
    boolean_t bMatchFrame = false;
    if (!(_frame&&stack_match_item_list&&stack_match_item_list_size))
    {
        goto _EXIT;
    }

    //Match every item
    for(int i =0;i<stack_match_item_list_size;i++)
    {
        stack_match_item_t * pItem = NULL;
        pItem = &(stack_match_item_list[i]);
        bMatchFrame = matchStackItem(_frame,uCurrLevel, pItem);
        if (bMatchFrame)
        {//If any StackItem match, then bail out
            break;
        }
    }
    
_EXIT:
    return bMatchFrame;
}

boolean_t matchFrameStack_(cframe_t * _frame,
                           uint32_t uCurrLevel,
                     stack_match_item_t *stack_match_item_list,
                     uint64_t stack_match_item_list_size)
{
    cframe_t * stackptr = _frame;
    uint32_t uLevel = uCurrLevel;
    boolean_t bMatchStack= false;
    if (!(_frame&&stack_match_item_list&&stack_match_item_list_size))
    {
        return bMatchStack;
    }
    while(stackptr&&uLevel<MAX_FRAME_NUMBER)
    {
        bMatchStack = matchFrame(stackptr,uLevel, stack_match_item_list, stack_match_item_list_size);
        if (bMatchStack)
        //If any level stack frame match, then bail out
        {
            break;
        }
        
        if (!stackptr->prev)
        {
            break;
        }
        uLevel++;
        stackptr = stackptr->prev;
    }//end of while
    return bMatchStack;
}


boolean_t matchFrameStack(
                           stack_match_item_t *stack_match_item_list,
                           uint64_t stack_match_item_list_size)
{
    cframe_t * pCurrFrame = 0;
    boolean_t bMatch = false;
    //Get current frame
    __asm__ volatile("movq %%rbp, %0" : "=m" (pCurrFrame));
    bMatch = matchFrameStack_(pCurrFrame,0,stack_match_item_list,stack_match_item_list_size);
    return bMatch;
}