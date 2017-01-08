/* created by: fanghui  on 10 Jan. 2011 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "../config.h"
#include "../aes/aes.h"
#include "pack.h"



/////////////////////////////////////////////////////////////////// new interface: packing block by block 
/////////////////////////////////////////////////////////////////// refer to hash.c and packall.c


// for new HMAC
// Input for hash:  SenderCounter(4) || Len(4) || Data(Len) || Pad  || Key(16)


unsigned int HMAC_get_PAD_len( unsigned int dataLen )
{
    unsigned int d = ( 4 + 4 + dataLen ) % AES_BLOCK_SIZE;
	return ( d == 0 )? 0: (AES_BLOCK_SIZE - d);
}


unsigned int HMAC_get_pack_len( unsigned int dataLen )
{
    return 4 + 4 + dataLen + HMAC_get_PAD_len( dataLen ) + AES_BLOCK_SIZE;
}



unsigned char HMAC_get_current_offset_byte( 
    unsigned int myOffset,
    unsigned char *inBlock,
    unsigned int SenderCounter,
    unsigned int dataLen,
    unsigned char *key)
{
	    
	// ---------------------------------------------------------------
	// | SenderCounter(4) | Len(4) |     Data(Len)               | Pad	| Key(16)  |
	// ---------------------------------------------------------------

    unsigned int padLen = HMAC_get_PAD_len(dataLen);

	unsigned char *ptr;


    // added on 20110412
    unsigned int SenderCounterNet = SWITCH_ENDIAN( (unsigned char*)&SenderCounter );
	unsigned int dataLenNet       = SWITCH_ENDIAN( (unsigned char*)&dataLen );

	

    if ( myOffset < 4 ) {
		ptr = (unsigned char*)&SenderCounterNet;   // modified on 20110412
		return ptr[ myOffset ];   // senderCounter
   	}

	if ( 4 <= myOffset && myOffset < 4 + 4 ) {
		ptr = (unsigned char*)&dataLenNet;        // modified on 20110412
		return ptr[ myOffset - 4 ];   // dataLen
	}

	if ( 4+4 <= myOffset && myOffset < 4+4+ dataLen ) {
		// read data by block
		if (  myOffset < AES_BLOCK_SIZE ) {
			return inBlock[ myOffset - (4+4) ];
		}
		else {
			return inBlock[ myOffset % AES_BLOCK_SIZE ]; 
		}
	}

    if ( 4+4+dataLen <= myOffset && myOffset < 4+4+dataLen + padLen ) {
		return 0; // pad with zero
	}
	
    if ( 4+4+dataLen+padLen <= myOffset && myOffset < 4+4+dataLen+padLen + AES_BLOCK_SIZE ) {
		return key[ myOffset - ( 4+4+dataLen+padLen ) ];  // key as last block
	}

	return 0; // error, should not be here
}



// Func: get one block and one input, from my offset
// Input: 
// Output:   myBlock
// Called by:   HMAC_step() only
void HMAC_get_intermediate_input(
         unsigned char *key, 
         unsigned int   SenderCounter,
         unsigned int   dataLen,
         unsigned char *inBlock,
         unsigned int   myOffset,
         unsigned char *outBlock /* as AES encryption key */ )
{
    int i;
	for (i=0; i<AES_BLOCK_SIZE; i++) {
		outBlock[i] = HMAC_get_current_offset_byte( myOffset + i,
			                                        inBlock,
			                                        SenderCounter,
			                                        dataLen,
			                                        key);
	}
}





void ADJUST_OFFSET( unsigned int *x, unsigned int minx, unsigned int range)
{
    if ( *x < minx ) {
		*x = minx;  // set to first legal value
		return;
    }

	if ( *x >= (minx + range) ) {
		*x = ( minx + range -1 );  // set to last legal value
		return;
	}
}



// Func:  set offset and my offset, which is offset in [ key, SenderCounter, totalLen, inData ] 
void HMAC_set_next_read_offset(
	unsigned int   dataLen,
	unsigned int  *offset,
	unsigned int  *myOffset)
{
    //unsigned int totalLen = HMAC_get_pack_len(dataLen);

    *myOffset += AES_BLOCK_SIZE;  // always increase by a  block

	// turn myOffset into offset in data
    if ( *myOffset == 0 ) {
		// keep offset		
		*offset = 0;
		return;
    }

	if ( *myOffset == AES_BLOCK_SIZE ) {
		// change read offset
		*offset    = AES_BLOCK_SIZE - (4+4);

		ADJUST_OFFSET( offset, 0, dataLen );
		return;
	}

	if ( *myOffset > AES_BLOCK_SIZE ) {
		// already adjusted, now move forward synchrnonously
		*offset   += AES_BLOCK_SIZE;
		ADJUST_OFFSET( offset, 0, dataLen );		
		return;
	}
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
//	dbgPrint("HMAC_step:offset =%d, myOffset = %d\r\n", *offset, myOffset );


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
	memPrint("input block for HMAC",  HMAC_key, AES_BLOCK_SIZE );
	AES_encrypt_block( HMAC_block, HMAC_block, HMAC_key );
	memPrint("output block for HMAC", HMAC_block, AES_BLOCK_SIZE );

	//
	// set internal offset for next 
	//
    HMAC_set_next_read_offset( totalLen, offset, &myOffset);
	*outBufLen = 0;

    return 0;
}




//////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////


void AES_get_IV_from_SenderCounter( unsigned int SenderCounter, unsigned char *IV )
{
    // added on 20110412, to big endian
    int i;
	unsigned int SenderCounterNet = SWITCH_ENDIAN( (unsigned char*)&SenderCounter );

	memset( IV, 0, AES_BLOCK_SIZE );

	// modified on 20110412, repeat four times on SenderCounter
	//
	//memcpy( IV, (unsigned char*)&SenderCounter, 4 );  // 4 bytes for SenderCounter
	//
    for(i=0; i<4; i++) {
		memcpy( IV+i*4, (unsigned char*)&SenderCounterNet, 4 );	
    }
}


unsigned int AES_get_pack_len( unsigned int dataLen, unsigned int macLen )
{
    return AES_get_enc_len( dataLen + macLen );
}


unsigned char AES_get_current_offset_byte(
	unsigned int myOffset,
	unsigned char *inBlock,
	unsigned char *MAC,
	unsigned char *PAD,
	unsigned int dataLen,
	unsigned int macLen,
	unsigned int padLen)
{
    //  Input:  myOffset, dataLen, macLen, padLen

    // 0 -----> [myOffset, myOffset+16)------------------------------->
    //  --------------------------------------------------------------
    // |             dataLen          |    macLen   |     padLen      |
    //  --------------------------------------------------------------
    // address:
    // inBlock                               MAC             PAD

	if ( myOffset < dataLen ) {
		return inBlock[ myOffset%AES_BLOCK_SIZE ];
	}


    if ( dataLen <= myOffset && myOffset < dataLen + macLen ) {
		return MAC[ myOffset - dataLen ];
    }

    if ( dataLen + macLen <= myOffset && myOffset < dataLen + macLen + padLen ) {
		return PAD[ myOffset - dataLen - macLen ];
    }

	return 0; // error, should not be here
}
	

void AES_get_enc_intermediate_input(
								unsigned int   dataLen,   /* exclude MAC leng */
								unsigned char *inBlock,
								unsigned char *MAC,
								unsigned int   macLen,
								unsigned char *outBlock,  /* plain block before xor*/
								unsigned int   myOffset   /* which may be greater than offset */
								)
{
	unsigned int totalLen, padLen;
	unsigned char PAD[AES_BLOCK_SIZE];
	int i;

	totalLen = AES_get_pack_len( dataLen, macLen );
	padLen   = totalLen - ( dataLen + macLen );

	// create PAD
	memset( PAD, padLen, padLen );

    // create current block
	for (i=0; i< AES_BLOCK_SIZE; i++) {
		outBlock[i] = AES_get_current_offset_byte( myOffset+i, 
 			                                       inBlock, MAC, PAD, 
			                                       dataLen, macLen,padLen);
	}
}


// Return:	0: continue; >0: finished len; negative: fail
int AES_ENC_MAC_step(
								  unsigned char *key, 
								  unsigned int   SenderCounter,  /* for IV */
								  unsigned int   dataLen,   /* exclude MAC */
								  unsigned char *inBlock, 
								  unsigned char *MAC,
								  unsigned int   macLen,
								  unsigned char *outBuf, 
								  unsigned int  *outBufLen,
								  unsigned int  *offset)
{
    static unsigned int myOffset = 0;
	static unsigned char ENCRYPT_IV_BLOCK[AES_BLOCK_SIZE] = {0};

    // print input
//	dbgPrint("AES_ENC_MAC_step:offset =%d, myOffset = %d\r\n", *offset, myOffset );

    // jump out if finished
	if ( myOffset >= AES_get_pack_len( dataLen , macLen )  ) {
        // output
		*outBufLen = 0;

		// reset offset to zero
		myOffset = 0;
		
		return 1;
	}

	//
	// Set intermediate input plain block
	//
	AES_get_enc_intermediate_input( dataLen, inBlock, MAC, macLen, outBuf, myOffset);
	*outBufLen = AES_BLOCK_SIZE; // always a block
 
	memPrint("input block for Encryption", outBuf, AES_BLOCK_SIZE );

	//
	// Set intermediate IV
	//
	if ( 0 == myOffset ) {
    	// for the first block, IV is taken from input 		
		AES_get_IV_from_SenderCounter( SenderCounter, ENCRYPT_IV_BLOCK);
	}
	// otherwise IV from last cipher block stored internally


	memPrint("IV or output block", ENCRYPT_IV_BLOCK, AES_BLOCK_SIZE);

	//
	// intermediate encryption
	//
	{
		memxor( ENCRYPT_IV_BLOCK, outBuf, AES_BLOCK_SIZE );
		AES_encrypt_block( outBuf, outBuf, key );
		memcpy( ENCRYPT_IV_BLOCK, outBuf, AES_BLOCK_SIZE );  // save
	}

    //
	// output
	//

	// increase offset
    *offset   += AES_BLOCK_SIZE;
	myOffset += AES_BLOCK_SIZE;

	return 0;
}





///////////////////////////////////////////////////////////////////////////////////////////// No encryption step



unsigned int NoEncryption_get_intermediate_input(
								unsigned int   dataLen,   /* exclude MAC leng */
								unsigned char *inBlock,
								unsigned char *MAC,
								unsigned int   macLen,
								unsigned char *outBlock,  /* plain block */
								unsigned int   myOffset   /* which may be greater than offset */
								)
{
	unsigned int i;
	unsigned int outLen, leftLen, totalLen;

    totalLen = dataLen + macLen ;
	leftLen  = ((myOffset<totalLen)?(totalLen-myOffset):0);
	outLen   = ((leftLen > AES_BLOCK_SIZE)?AES_BLOCK_SIZE:leftLen);
		
	for (i=0; i< outLen; i++) {
		outBlock[i] = AES_get_current_offset_byte( myOffset+i, 
 			                                       inBlock, MAC, 0, 
			                                       dataLen, macLen, 0);
	}

	return outLen;
}


// Func:        by pass the encryption, and still follow block-by-block working style
// Input:       (already get MAC, no need to have key or senderCounter)
// Return:	0: continue; >0: finished len; negative: fail
// Refer to:   AES_ENC_MAC_step() and AES_DEC_step()
int NoEncryption_MAC_step(
								  unsigned int   dataLen,   /* exclude MAC */
								  unsigned char *inBlock, 
								  unsigned char *MAC,
								  unsigned int   macLen,    /* be 0 for decryption step */
								  unsigned char *outBuf, 
								  unsigned int  *outBufLen,
								  unsigned int  *offset)
{
    // jump out if finished
	if ( *offset >=  ( dataLen + macLen )  ) {
        // output
		*outBufLen = 0;
		return 1;
	}

	// Set intermediate input plain block
	*outBufLen = NoEncryption_get_intermediate_input( dataLen, inBlock, MAC, macLen, outBuf, *offset);

	// increase offset
    *offset   += *outBufLen;
	return 0;
}






////////////////////////////////////////////////////////////////////////////////////////////// status machine

// keyMode:
//     0:    No encryption, no MAC               -- no support yet
//     1:    No encryption, with MAC             --support
//     2:    Encryption, no MAC                    --no support yet
//     3:    Encryption, with MAC                  --support


int pack_step( unsigned char keyMode,
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

	int retVal;

    // added on 20110412, supporting keyMode == 0
	if( 0 == keyMode) { // no encryption, no MAC
		if(*offset < totalLen - AES_BLOCK_SIZE)	{
			*outBufLen=AES_BLOCK_SIZE;
			*offset+=AES_BLOCK_SIZE;
			retVal=0;   //not finished
		}
		else if(*offset < totalLen)	{
			*outBufLen=totalLen- *offset;
			*offset=totalLen;
			retVal = 1;
		}
		else {
			retVal=-1;
		}
		
		if(outBuf!=inBlock) {
			memcpy(outBuf, inBlock, *outBufLen);
		}
		
		return 	retVal;
	} 



	//
	// Entry
	//
	if ( (0 == *offset) && (0 == status) ) {
		status = 10; // jump to Step 10
	}

	// Step 10: scan inData once for HMAC
	if ( status == 10 ) {
		retVal = HMAC_step( key, 
		                    SenderCounter, totalLen,
		                    inBlock, 
		                    HMAC_BLOCK, outBufLen,
		                    offset);

		if ( retVal == 0 ) { // not finished 
			return 0; // will continue in next step
		}
		else // finish HMAC, jump to Step 20
		{
			memPrint("pack_step:HMAC_BLOCK--------------->", HMAC_BLOCK, AES_BLOCK_SIZE );
			memPrint("pack_step:choose HMAC=------------->", HMAC_BLOCK, MAC_LEN );

			status = 20;  
			*offset = 0;  // reset offset
			*outBufLen = 0;  // do NOT write MAC right now
			return 0;
		}
	}


	// Step 20: scan inData again for encryption
	if ( status == 20 ) {

		if ( keyMode == 1 ) {   // plaintxt with MAC
			retVal = NoEncryption_MAC_step( totalLen, inBlock,
				                            HMAC_BLOCK, MAC_LEN,
				                            outBuf, outBufLen,
				                            offset);
		}
		else {  // AES encryption with MAC
			retVal = AES_ENC_MAC_step( key, 
		           SenderCounter, totalLen, 
		           inBlock, HMAC_BLOCK, MAC_LEN, outBuf, outBufLen,
		           offset);
		}

		if ( retVal == 0 ) { // not finished
			return 0; 
		}
		else // finish AES
		{
			status = 30; // jump to Step 30, which is the last step
			return 0;
		}
	}


	// 
	// Exit
	//
	if ( status == 30 ) {
		status = 0;
		return 1;
	}

	status = 0;
	return -1;
}



