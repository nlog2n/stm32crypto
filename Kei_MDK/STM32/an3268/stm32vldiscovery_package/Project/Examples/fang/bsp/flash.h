/*++
   Created by fanghui on 10 Jan. 2011 
 --*/

#ifndef __BSP_FLASH_H__
#define __BSP_FLASH_H__


#if !(defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_AMD64) || defined(_M_X64)))

     #include "stm32f10x.h"

#endif



// Define the STM32F10x FLASH Page Size, 1K
#define FLASH_PAGE_SIZE             ((unsigned int)0x400)   
#define AES_FLASH_WRITE_START_ADDR  ((unsigned int)0x08008000)
#define AES_FLASH_WRITE_END_ADDR    ((unsigned int)0x0800C000)

void readFlash( unsigned char *ram, unsigned int addr, unsigned int len );
int  writeFlash( unsigned char *ram, unsigned int addr, unsigned int len);



#endif // __BSP_FLASH_H__

