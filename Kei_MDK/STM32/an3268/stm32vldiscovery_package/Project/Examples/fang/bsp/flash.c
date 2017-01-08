/*++
   Created by: fanghui  on 10 Jan. 2011 

   STM32 hardware operations
     flash read/write

--*/

#include <stdlib.h>
#include <string.h>

#include "flash.h"


unsigned char PageBuffer[FLASH_PAGE_SIZE]= {0};


////////////////////////////////////////////////////////
// declare a variable to a specified address
//
// #include <absacc.h>
//
// const char MyTextp[] __at (0x1F00) = "TEXT AT ADDRESS 0x1F00"; // for constant
// int x __at (0x40003000);  // for variable
//
///////////////////////////////////////////////////////




//////////////////////////////////////////////////////////////////////////////////  Flash operations
int is_flash_addr( unsigned int addr )
{

// copied from file stm32_flash.h:
//      #define IS_FLASH_ADDRESS(ADDRESS) (((ADDRESS) >= 0x08000000) && ((ADDRESS) < 0x080FFFFF))

   #ifdef __STM32F10x_H

	  return (addr >= AES_FLASH_WRITE_START_ADDR) && (addr < AES_FLASH_WRITE_END_ADDR);

   #else

      return 0;  // false for windows

   #endif
}


//read flash of len bytes to RAM buffer
void readFlash( unsigned char *ram, unsigned int addr, unsigned int len )
{

    unsigned int i;

	// for normal memory copy
	if ( !is_flash_addr( addr ) ) {		// only check starting write address
        memcpy( ram, (unsigned char*)addr, len );
	    return;
	}

    // Disable read protection (RDP)
    for (i=0; i<len; i++) {
        *(ram + i) = *(volatile unsigned char *) addr; 
      	addr ++;
	}
	// Enable read protection
}



// private function, NOT in use yet
int checkFlashPageEmpty( const unsigned int addr )
/*++ Func:   check if a flash page is empty
     Input:  any address, which may not be a page start address
     Ouput:  true for empty
--*/
{
  #define FLASH_EMPTY  ((unsigned int)0xCDAB1032)
  unsigned int i, page_addr;
  page_addr = ( addr / FLASH_PAGE_SIZE ) * FLASH_PAGE_SIZE ;  // start
  for(i=0; i<FLASH_PAGE_SIZE/4; i += 4) {
      // check by words
      if ( FLASH_EMPTY !=  *(volatile unsigned int*)(page_addr+i)  )
	       return 0;   // false, not empty
  } 

  return 1; // true, empty
}


// private function
int writeFlashInOnePage(unsigned char *ram, unsigned int addr, unsigned int len)
/*++ 
	Func:	   write ram data of len bytes into flash adress addr
				 support writing within ONE flash page only
	Input:	   - ram address, 
				  - length
				  - flash addr, not necessarily page start
				  - PageBuffer (implicitly)
				  - FLASH_PAGE_SIZE (global)
	Output:    flash updated
	Require:   [addr, addr +len) falls in ONE page
				   flash unlocked 
	Return:    1, success; 0, fail
	Called by:   writeFlash() only
	Note:          private function
                         does NOT support overlapping if ram points to flash address	
--*/
{

#ifdef __STM32F10x_H

    unsigned int i;
	unsigned int Data;
	unsigned int curPage;
	unsigned int pageAddr;
	unsigned int offset;
	FLASH_Status status = FLASH_COMPLETE;

	// check boundary of write range
    if ( !is_flash_addr( addr ) || !is_flash_addr(addr+len-1) ) {	
	    return 0;
	}

	pageAddr = ( addr / FLASH_PAGE_SIZE ) * FLASH_PAGE_SIZE ;  // start
	offset = addr - pageAddr;  

 	// check if this addr falls in one single page
    if ( ! (addr + len <= pageAddr + FLASH_PAGE_SIZE) )
	    return 0;

    FLASH_Unlock();

    // Clear All pending flags
    FLASH_ClearFlag(FLASH_FLAG_EOP | FLASH_FLAG_PGERR | FLASH_FLAG_WRPRTERR); 

    // Read one-page flash to ram buffer
	readFlash(  PageBuffer, pageAddr, FLASH_PAGE_SIZE );

    // Modify ram buffer
    for (i=0; i<len ; i++)  {
	  *(PageBuffer + offset + i) = *(ram+i);
    }

    // Erase the FLASH pages. This must be done before writing flash.
    curPage =  pageAddr; 
    status  = FLASH_ErasePage( curPage );

    // PageBuffer --> Flash by words
	for (i=0; i< FLASH_PAGE_SIZE && status == FLASH_COMPLETE ; i += 4) {
	  Data = * (unsigned int *) (PageBuffer+i);
	  status = FLASH_ProgramWord( pageAddr + i,  Data );
	} 

    FLASH_Lock();

    if ( status != FLASH_COMPLETE ) {
	  return 0;
    } 

#endif

	return 1;

}




int writeFlash(unsigned char *ram, unsigned int addr, unsigned int len)
/*++ 
	Func:	   write ram data of len bytes into flash adress addr
	Input:	   - ram address, 
			  - length
			  - flash addr, not necessarily page start
	Output:    flash updated
	Return:    1, success; 0, fail
	Note:       does NOT support overlapping if ram points to flash address
--*/
{
    unsigned char *curRam;
	unsigned int   curAddr, curLen, curPage, curOffset, restLen;

	// for normal memory copy
	if ( !is_flash_addr( addr ) ) {	 
		memcpy( (unsigned char*)addr, ram, len );
	    return 1;
	}

    // for flash destination
    curRam  = ram;
	curAddr = addr;
	restLen = len;

    while ( curAddr < (addr + len) ) {

   	    curPage   = ( curAddr      / FLASH_PAGE_SIZE    ) * FLASH_PAGE_SIZE ; 
	    curOffset = curAddr - curPage;
	    curLen    = FLASH_PAGE_SIZE - curOffset;
		curLen    = (curLen <= restLen)? curLen:restLen;

		if ( !writeFlashInOnePage( curRam, (unsigned int)curAddr, curLen )  )
		     return 0;  // fail on this step

		curRam  += curLen;
		curAddr += curLen;
		restLen -= curLen;
	}

    return 1; // success
}




