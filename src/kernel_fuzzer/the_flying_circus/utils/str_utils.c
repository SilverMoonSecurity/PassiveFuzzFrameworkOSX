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
 * path_utils.c
 *
 * Functions to deal with path names, ripped from OpenBSD libc sources
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


#include <string.h>
//#include <ctypes.h>
//#include <stdlib.h>
#include "str_utils.h"
#include <sys/malloc.h>

const char *kmp_search(const char *text, const char *pattern)
{

    char *pSource = text;
    char *pPattern = pattern;
    if (!pSource)
      {
          return NULL;
      }
      if ( !strlen(pSource))
      {
          if (!strlen(pPattern))
          {
              return pSource;
          }
          else
          {
              return NULL;
          }
      }
      if (!pPattern||!strlen(pPattern))
      {
          return pSource;
      }
      if (strlen(pPattern)>strlen(pSource))
      {
          return NULL;
      }
      
    int *T;
    int i, j;
    const char *result = NULL;
 
    if (pattern[0] == '\0')
        return text;
 
    /* Construct the lookup table */
    
    T = (int*) _MALLOC((strlen(pattern)+1) * sizeof(int), M_TEMP, M_WAITOK);
    //T = (int*) malloc((strlen(pattern)+1) * sizeof(int) );
    T[0] = -1;
    for (i=0; pattern[i] != '\0'; i++) {
        T[i+1] = T[i] + 1;
        while (T[i+1] > 0 && pattern[i] != pattern[T[i+1]-1])
            T[i+1] = T[T[i+1]-1] + 1;
    }
 
    /* Perform the search */
    for (i=j=0; text[i] != '\0'; ) {
        if (j < 0 || text[i] == pattern[j]) {
            ++i, ++j;
            if (pattern[j] == '\0') {
                result = text+i-j;
                break;
            }
        }
        else j = T[j];
    }
 
    //free(T);
    _FREE(T, M_TEMP);
    return result;
}


char * KMP_str_str(char *pSource, char * pPattern)
{
  if (!pSource)
  {
	  return NULL;
  }
  if ( !strlen(pSource))
  {
	  if (!strlen(pPattern))
	  {
		  return pSource;
	  }
	  else
	  {
		  return NULL;
	  }
  }
  if (!pPattern||!strlen(pPattern))
  {
	  return pSource;
  }
  if (strlen(pPattern)>strlen(pSource))
  {
	  return NULL;
  }
  char * string = pSource;
  char *matchcase = pPattern;
  int i=0, index=0, j=0;
  for (i = 0; i < strlen(string) - strlen(matchcase) + 1; i++)
    {
        index = i;
        if (string[i] == matchcase[j])
        {
            do
            {
                i++;
                j++;
            } while(j != strlen(matchcase) && string[i] == matchcase[j]);
            if (j == strlen(matchcase))
            {
                //printf("Match found from position %d to %d.\n", index + 1, i);
                return string+index;
            }
            else
            {
                i = index + 1;
                j = 0;
            }
        }
    }
    //printf("No substring match found in the string.\n");
	return NULL;
}


char * str_str(const char *str1, const char *str2)
{
    //return KMP_str_str(str1, str2);
    return kmp_search(str1, str2);
}


char * str_str_old(const char *str1, const char *str2)
{
 int n;


 if (*str2) 
 {
  while(*str1)
  {
   for(n = 0; *(str1+n) == *(str2+n); n++ )
   {
    if (!*(str2+n+1))
    {
     return (char *)str1;
    }
   }

   str1++;
  }
  return NULL;
 }


 return NULL;
}

char to_lower(char a)
{
	char ret = a;
	if ('A'<=a && a <='Z')
	{
		ret = a - 'A' +'a';
	}
	return ret;
}
void lower_str(char * str, size_t nLen)
{
    for(int i =0 ;i<nLen; i++)
    {
        str[i] = to_lower(str[i]);
    }
}