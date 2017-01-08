
/* created by: fanghui  on 10 Jan. 2011 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "config.h"
#include "aes/aes.h"
#include "pack.h"



/////////////////////////////////////////////////////////////////// new interface: packing block by block 
/////////////////////////////////////////////////////////////////// refer to hash.c and packall.c


// for old HMAC in block-by-block style
// Input for hash:  Key || SenderCounter || Len || Data



unsigned int HMAC_prefix_len( void )
{
	// Prefix include :   Key(16) || SenderCounter(4) || Len(4) , in Table 1&2
	return AES_BLOCK_SIZE + 4 + 4;
}


unsigned int HMAC_get_pack_len( unsigned int totalLen )
{
    return HMAC_prefix_len() + totalLen;
}


// Func:  set offset and my offset, which is offset in [ key, SenderCounter, totalLen, inData ] 
void HMAC_set_next_read_offset(
	unsigned int   totalLen,
	unsigned int  *offset,
	unsigned int  *myOffset)
{
    if ( *myOffset == 0 ) {
		*myOffset += AES_BLOCK_SIZE;
		// keep offset		
		*offset = 0;
		return;
    }

	if ( *myOffset == AES_BLOCK_SIZE ) {
		// change read offset
		*myOffset += AES_BLOCK_SIZE; 
		*offset    = AES_BLOCK_SIZE - HMAC_prefix_len () % AES_BLOCK_SIZE;
		return;
	}

	if ( *myOffset > AES_BLOCK_SIZE ) {
		// already adjusted, now move forward synchrnonously
		*myOffset += AES_BLOCK_SIZE;
		*offset   += AES_BLOCK_SIZE;
		return;
	}
}


// Func: get one block and one input, from my offset
// Input: 
// Output:   myBlock
// Called by:   HMAC_step() only
void HMAC_get_intermediate_input(
         unsigned char *key, 
         unsigned int   SenderCounter,
         unsigned int   totalLen,
         unsigned char *inBlock,
         unsigned int   myOffset,
         unsigned char *myBlock /* as encryption key */ )
{
	unsigned int packLen;

	// will choose key as block
    if ( 0 == myOffset ) {
		// get first block
		memcpy( myBlock, key, AES_BLOCK_SIZE );   
		return ; 
    }

	// will choose [ SenderCounter, length] and partial inBlock
	if ( AES_BLOCK_SIZE == myOffset ) {
		memcpy( myBlock,   (unsigned char*)&SenderCounter, 4 );  /* 4 bytes for SenderCounter */
		memcpy( myBlock+4, (unsigned char*)&totalLen, 4 );  /* 4 bytes for length field */
		memcpy( myBlock+8, inBlock, AES_BLOCK_SIZE - 8 );

		return ;
	}

	packLen = HMAC_get_pack_len( totalLen);
	if ( AES_BLOCK_SIZE < myOffset  && myOffset < packLen ) { 	// will choose inBlock

		// pad message tail with zero, if vacant
	    if ( myOffset + AES_BLOCK_SIZE > packLen ) {
			memcpy( myBlock, inBlock, packLen - myOffset );
			memset( myBlock + packLen - myOffset, 0, AES_BLOCK_SIZE - (packLen - myOffset) );
		}
		else {
			memcpy( myBlock, inBlock, AES_BLOCK_SIZE ); 
		}

		return ;
	}

    return;	
}




int HMAC_step(unsigned char *key, 
         unsigned int   SenderCounter,
         unsigned int   totalLen,
         unsigned char *inBlock,
         unsigned char *outBuf,
         unsigned int  *outBufLen,
         unsigned int  *offset)
{
    static unsigned int myOffset = 0;
	static unsigned char HMAC_block[AES_BLOCK_SIZE] = {0};

	unsigned char HMAC_key[AES_BLOCK_SIZE] = {0};   
	
    // print input
	dbgPrint("HMAC_step:offset =%d, myOffset = %d\r\n", *offset, myOffset );


    // jump out if finished
	if ( myOffset >= HMAC_get_pack_len( totalLen) ) {
        // output
		memcpy( outBuf, HMAC_block, AES_BLOCK_SIZE );
		//*outBufLen = AES_BLOCK_SIZE;
		*outBufLen = MAC_LEN;   // only choose 96-bit MAC

		// reset offset to zero
		myOffset = 0;
		return 1;
	}


	//
	// get my intermediate input and intermediate key
	//
	HMAC_get_intermediate_input( key, 
	                      SenderCounter, totalLen, 
	                      inBlock, 
	                      myOffset, 
	                      HMAC_key);

    if ( 0 == myOffset ) {	// get first input
		memset( HMAC_block, 0, AES_BLOCK_SIZE );
 	    // Otherwise, from last stored HMAC_block
    }



	//
	// intermediate encryption for HMAC
	//
	memPrint("input block",  HMAC_key, AES_BLOCK_SIZE );
	AES_encrypt_block( HMAC_block, HMAC_block, HMAC_key );
	memPrint("output block", HMAC_block, AES_BLOCK_SIZE );

	//
	// set internal offset for next 
	//
    HMAC_set_next_read_offset( totalLen, offset, &myOffset);
	*outBufLen = 0;
	
    return 0;
}





