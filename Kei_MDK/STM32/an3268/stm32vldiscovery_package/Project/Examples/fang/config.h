

#ifndef __CRYPTO_CONFIG_H__
#define __CRYPTO_CONFIG_H__

#ifdef  __cplusplus
   extern "C" {
#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

//#include "bsp/flash.h"


void memPrint( char* prefix, unsigned char* data, int len );
void strPrint( char* prefix, unsigned char* data, int len );
void dbgPrint( const char *format, ...);



#ifdef  __cplusplus
    }
#endif

#endif // __CRYPTO_CONFIG_H__
