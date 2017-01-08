/* created by: fanghui  on 10 Jan. 2011 */


//////////////////////////////////////////////////////////////// for debug

#include "config.h"


#if (defined(_MSC_VER) && ( defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64) ) )

     #define CRYPTO_ON_WINDOWS

#else
     //#include "stm32f10x.h"

#endif

				 

void memPrint( char* prefix, unsigned char* data, int len )
{
#ifdef CRYPTO_ON_WINDOWS

	int i;
	printf("%s(%d):     \t", prefix, len);
	for (i=0;i<len;i++){
		if ( i%16 == 0 ) printf("\r\n");
		printf("%02x ", (unsigned char) *(data+i));
	}
	printf("\r\n");

#endif
}


void strPrint( char* prefix, unsigned char* data, int len )
{
#ifdef CRYPTO_ON_WINDOWS

	int i;
	printf("%s(%d) in string:     \t", prefix, len);
	for (i=0;i<len;i++){
		printf("%c", (char) *(data+i));
	}
	printf("\r\n");

#endif
}


// to replace printf()
void dbgPrint( const char *format, ...)
{
#ifdef CRYPTO_ON_WINDOWS
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
#endif
} 


