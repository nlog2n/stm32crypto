/* created by: fanghui  on 10 Jan. 2011 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../config.h"
#include "../aes/aes.h"
#include "pack.h"




//////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////// new interface: unpacking block by block 
/////////////////////////////////////////////////////////////////// refer to hash.c and packall.c
//////////////////////////////////////////////////////////////////////////////////////////////



// Return:	0: continue; >0: finished len; negative: fail
int AES_DEC_step(
								  unsigned char *key, 
								  unsigned int   SenderCounter,  /* for IV */
								  unsigned int   totalLen,   /* including MAC */
								  unsigned char *inBlock, 
								  unsigned char *outBuf, 
								  unsigned int  *outBufLen,
								  unsigned int  *offset)
{
	static unsigned char DECRYPT_IV_BLOCK[AES_BLOCK_SIZE] = {0};

	unsigned char tmp_last_block[AES_BLOCK_SIZE] = {0};
	int padLen;

    // jump out if finished
	if ( *offset >= totalLen ) {
		// no output this time
		*outBufLen = 0;

        // reset offset
		*offset = 0;
		return 1;
	}

	memPrint("input block for Decryption", inBlock, AES_BLOCK_SIZE );

	//
	// Set intermediate IV
	//
	if ( 0 == *offset ) {
    	// for the first block, IV is taken from input 		
		AES_get_IV_from_SenderCounter( SenderCounter, DECRYPT_IV_BLOCK);
	} 
    // otherwise IV from last cipher block stored internally


	//
	// intermediate decryption
	//
	{
		memcpy( tmp_last_block, inBlock, AES_BLOCK_SIZE ); // save tmply
		
		AES_decrypt_block( inBlock, outBuf, key );
		memxor( DECRYPT_IV_BLOCK, outBuf, AES_BLOCK_SIZE);

		memcpy( DECRYPT_IV_BLOCK, tmp_last_block, AES_BLOCK_SIZE ); // save to 
	}

    //
	// output, and adjust out length
	//
    *outBufLen = AES_BLOCK_SIZE; 
	if ( *offset + AES_BLOCK_SIZE == totalLen )	{ // the last block
		// deduce the padding length from the last block
		padLen = outBuf[AES_BLOCK_SIZE-1]; // get rest length, check ?
		if ( (padLen >=1 && padLen <= AES_BLOCK_SIZE) ) {  // check but do NOT return error
			*outBufLen -= padLen;
		}
		else {
			dbgPrint("AES_DEC_step: Error padLen =%d<---------\r\n", padLen );
		}
	}


	memPrint("output block", outBuf, *outBufLen );

	// increase offset
    *offset   += AES_BLOCK_SIZE;
	return 0;
}






//////////////////////////////////////////////////////////////////////////////////////////////

int unpack_step( unsigned char keyMode,
	             unsigned char *key,
				 unsigned char *inBlock,
  	             unsigned int   totalLen,
				 unsigned char *outBuf,
				 unsigned int  *outBufLen,
				 unsigned int  *offset,
				 unsigned int   SenderCounter)
/*++
  Func:
  Assumption: 
     MAC is appended to message closely
  Input:
  Output:
  Return:
--*/
{
	static int status = 0;
	static unsigned char HMAC_BLOCK[AES_BLOCK_SIZE];
	static unsigned int decryptedLen = 0;

	int retVal;


    // added on 20110412, supporting keyMode == 0
	if( 0 == keyMode) { // no encryption, no MAC
		if(*offset < totalLen - AES_BLOCK_SIZE)	{
			*outBufLen=AES_BLOCK_SIZE;
			*offset+=AES_BLOCK_SIZE;
			retVal=0;   //not finished
		}
		else if(*offset < totalLen) {
			*outBufLen=totalLen- *offset;
			*offset=totalLen;
			retVal = 1;
		}
		else { 
			dbgPrint("unpack_step: Error 1 !\r\n");
			retVal=-1;
		}
		
		if(outBuf!=inBlock) {
			memcpy(outBuf, inBlock, *outBufLen);
		}
		
		return 	retVal;
	} 



    // check length
	if ( totalLen == 0 ) {
		dbgPrint("unpack_step: Error input length =%d!\r\n", totalLen);
		return -1;
	}

	if ( 1 == keyMode ) {  // no encryption with MAC
		if ( totalLen  < MAC_LEN ) {
			dbgPrint("unpack_step: Error input length =%d!\r\n", totalLen);
			return -1;
		}
	}else {  // assume encryption with MAC
		if ( totalLen%AES_BLOCK_SIZE != 0 ) {
			dbgPrint("unpack_step: Error input length =%d!\r\n", totalLen);
			return -1;
		}
	}

	

	//
	// Entry
	//
	if ( (0 == *offset) && (0 == status) ) {
		decryptedLen = 0;
		status = 10; // jump to Step 10
	}

	// Step 10: scan inData once for decryption
	if ( status == 10 ) {

		if ( keyMode == 1 ) {  // plaintxt with MAC

			retVal = NoEncryption_MAC_step( totalLen, inBlock, 
				                            0, 0,
				                            outBuf, outBufLen, offset);
		}
		else {  // AES encryption with MAC

			retVal = AES_DEC_step( key, SenderCounter, 
			              totalLen, inBlock, outBuf, outBufLen, 
			              offset);
		}
		
		decryptedLen += *outBufLen;
		if ( retVal == 0 ) { // not finished 
			return 0; // will continue in next step
		}
		else // finish decryption, jump to Step 20
		{
			dbgPrint("unpack_step:decryptedLen=%d<-------\r\n", decryptedLen );
			if ( decryptedLen <= MAC_LEN ) {
			    dbgPrint("unpack_step: Error decryptedLen <= MAC_LEN!\r\n");
				status = 0;  // reset
				return -1;
			}

			*outBufLen -= MAC_LEN; // do not output MAC part

			status = 20;  
			*offset = 0;  // reset offset
			return 0;
		}
	}


	// Step 20: scan inData again to compute HMAC
	if ( status == 20 ) {
	    retVal = HMAC_step( key, 
		                    SenderCounter,  
		                    decryptedLen - MAC_LEN,
		                    inBlock, 
		                    HMAC_BLOCK, outBufLen,
		                    offset);

		if ( retVal == 0 ) { // not finished
			return 0; 
		}
		else // finish HMAC
		{
			status = 30; // jump to Step 30, which will extract MAC from data
			*offset = decryptedLen - MAC_LEN;  // pointer to start of MAC
			*outBufLen = 0;  // no writing
			return 0;
		}
	}


    // Step 30: extract MAC and compare with the saved one
	if ( status == 30 ) {
		// save MAC
		if ( memcmp( HMAC_BLOCK, inBlock, MAC_LEN ) != 0 ) {
			// MAC mismatch!
			dbgPrint("unpack_step: Error MAC mismatch!\r\n");
			memPrint("message  MAC", inBlock, MAC_LEN);
			memPrint("computed MAC", HMAC_BLOCK, MAC_LEN);
			status = 0;  // reset
			return -1;
		}

		memPrint("unpack_step:matched MAC=--------->", HMAC_BLOCK, MAC_LEN );

		status = 40; // jump to finish
		*offset = 0;
		return 0;
	}


	// 
	// Exit
	//
	if ( status == 40 ) {
		status = 0;
		return 1;
	}

	dbgPrint("unpack_step: Error unknown ending!\r\n");
	status = 0;
	return -1;
}



