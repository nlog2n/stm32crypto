/*++

 Created by: fanghui  on 10 Jan. 2011 

--*/

#include <string.h>

#include "../aes/aes.h"
#include "../hash/hash.h"
#include "pack.h"

//typedef enum { false = 0, true = !false} bool;

#include "sies.h"





/*
typedef int (*PFUNC) (int x);

void test_callback( PFUNC pfunc, int x )
{
  (*pfunc) (x);
} */






////////////////////////////////////////////////////////////////////  New block-by-block interface, 23 Feb 2011

void GenerateMAC_step(const unsigned char *key,
                  unsigned char       *inBlock,
                  unsigned int         dataLen,
                  unsigned char       *outBuf,
                  unsigned int        *outBufLen, 
				  unsigned int        *offset)
/*++
   Func:  generate 96-bit MAC for message in multi steps, i.e., block by block
   Input:
            key, 128-bit
            inTempBuf
            inDataOffset, starting from 0
            inDataTotalLen
            outTempBuf
   Output:
            outTempBuf, from the last intermediate result
            outTempBufLen
            inDataOffset
   Return: None
   Refer to: 
             GenerateMAC()
--*/
{
	unsigned char  tmpKey[16] = {0};

    if ( *offset >= dataLen )
		return;

	//
	// Set intermediate input
	//
    // For the first block, input is zero, and key from key itself
    if ( 0 == *offset ) {   

		// before taking message block 0, take key first
		memset( outBuf, 0, 16 );
		memcpy( tmpKey, key, 16 );
		AES_encrypt_block( outBuf, outBuf, tmpKey );
    }
	// Otherwise, input is from outTempBuf, and key from inTempBuf


	//
	// set intermediate key
	//
	if ( *offset + 16 < dataLen )	{
		memcpy( tmpKey, inBlock, 16 );
        *outBufLen = 0;  // No output 
	}
	else {  // the last block
		memset( tmpKey, 0, 16 ); 
        memcpy( tmpKey, inBlock, dataLen - *offset );

        // cut MAC to 96 bits for the last block
        *outBufLen = MAC_LEN; //96/8; 
	}


	//
	// intermediate encryption
	//
	AES_encrypt_block( outBuf,  outBuf, tmpKey );

	// increase offset
    *offset += 16;
}



int ExtractMAC_step(unsigned char *inTempBuf,
				  unsigned int   inDataTotalLen, /*incl. 12-byte MAC*/
				  unsigned int   curOffset,
				  unsigned char *outMAC)
/*++
   Func:  private, used by CheckMAC_step() only
   Input:
   Output: outMAC
   Return: 1 - get mac, 0 - not yet
--*/
{
	unsigned int last_block_len;

	inDataTotalLen -= MAC_LEN;

	if ( curOffset + 16 < inDataTotalLen ) {
		return 0; // for normal block;
	}

	// reach the last data block (excl. MAC)
	// need to get full MAC at the end of message, which may be in two separate blocks!
	if (  ( curOffset     <   inDataTotalLen )
		&&( curOffset +16 >=  inDataTotalLen ) ) {

        last_block_len = inDataTotalLen - curOffset;
		if ( last_block_len <= 16-MAC_LEN ) {
			//  last block, which also contains full MAC
			memcpy( outMAC, inTempBuf + last_block_len, MAC_LEN );
			return 1; // finishe fetching
		}
		else {
            // last block, which also contains partial MAC
			memcpy( outMAC, inTempBuf + last_block_len, 16 - last_block_len );
			return 0; // not yet finished fetching MAC
		}

	}

	// reach the last MAC block
	if (   ( curOffset >= inDataTotalLen )
		&& ( curOffset <  inDataTotalLen + MAC_LEN ) ) {

			// last block, which only contains partial MAC
			last_block_len = inDataTotalLen + MAC_LEN - curOffset;
			memcpy( outMAC + MAC_LEN - last_block_len, inTempBuf, last_block_len );
			return 1; // finished
	}

    return 1; //for nothing;
}



int CheckMAC_step(const unsigned char *key,
              unsigned char       *inTempBuf,
              unsigned int         inDataTotalLen,
			  unsigned int        *inDataOffset)
/*++
Func:  check 96-bit MAC for message in multi steps
Input: 
         key, 128-bit
         inTempBuf
		 inDataOffset, starting from 0
		 inDataTotalLen, including a 96-bit MAC at the end
Output:
		 inDataOffset, increasing 
Return: 
               1: success; 0: continue; -1: fail
Refer to: 
         Section 5.3&5.4&5.12 in Design document 
         GenerateMAC() in pack.c
--*/
{

	static unsigned char CHECK_MAC_BLOCK[16] = {0};  // compute MAC
	static unsigned char CHECK_MAC2_BLOCK[16] = {0}; // store MAC
    static unsigned int  tmp_check_mac_len;

	int status;

	if ( inDataTotalLen <= MAC_LEN )  
		return -1;  //  no enough message length

    // extract MAC from the end of message
    status = ExtractMAC_step(inTempBuf, 
		                 inDataTotalLen, 
						 *inDataOffset, 
						 CHECK_MAC2_BLOCK);

    // compute MAC block by block
	GenerateMAC_step( key, 
		          inTempBuf, 
		          inDataTotalLen - MAC_LEN,
		          CHECK_MAC_BLOCK,
		          &tmp_check_mac_len,
		          inDataOffset);

	// already obtain two MACs, and compare
	if ( (1 == status) && ( MAC_LEN == tmp_check_mac_len) ) {  
		status = memcmp( CHECK_MAC_BLOCK, CHECK_MAC2_BLOCK, MAC_LEN );
		if ( 0 == status )
			return 1;  // success
		else
			return -1; // fail
	}
	else 
		return 0;
}








///////////////////////////////////////////////////////////////// New AES enc/dec block-by block API

int AES_cbc_enc_step( unsigned char    *inTempBuf, 
							   unsigned char *outTempBuf, 
							   unsigned int  inDataTotalLen, 
							   unsigned int  *outTempBufLen,
							   unsigned int  *inDataOffset,
							   unsigned char *key, 
							   unsigned char *ivec)
/*++
	 Func:		encrypt data with variable length by CBC mode
 	            encrypt the message with AES 128-bit /CBC, output ciphertext, return ciphertext length
	 Assumption:	output pointing to an sufficient buffer
	                     padding mode = PKCS #5
	 Input: 		
	            key128, IV, 
				inTempBuf, inDataTotalLen, inDataOffset
	 Output:	
	            outTempBuf, outTempBufLen
				inDataOffset
	 Return:	
	            -1: fail; 0:continue; 1: finished
	 Note:      
	            allow inTempBuf/outTempBuf overlap, if outTempBuf has sufficient buffer
	 Refer to: 
	            AES_cbc_encrypt() and encrypt() in aes_cbc.c
--*/
{
	static unsigned char ENCRYPT_IV_BLOCK[16] = {0};

	unsigned int restLen;

	int status;  // 0: continue; >0: finished len; negative: fail

	if ( *inDataOffset >= inDataTotalLen )
		return -1;

	//
	// Set intermediate IV
	//
	// for the first block, IV is taken from input 
	if ( 0 == *inDataOffset ) {
		memcpy( ENCRYPT_IV_BLOCK, ivec, 16 );
	}
	// otherwise IV from last cipher block stored


	//
	// Set intermediate input plain block
	//
	if ( *inDataOffset + 16 < inDataTotalLen )	{ // for normal block
		memcpy( outTempBuf, inTempBuf, 16 );
        *outTempBufLen = 16; 
		status = 0; // continue
	}
	else {  // the last block
		if ( *inDataOffset + 16 == inDataTotalLen ) { // exactly, need one more block appended
			restLen = inDataTotalLen - *inDataOffset;
			memcpy( outTempBuf, inTempBuf, restLen );

			{
				memxor( ENCRYPT_IV_BLOCK, outTempBuf, 16 );
				AES_encrypt_block( outTempBuf, outTempBuf, key );
				memcpy( ENCRYPT_IV_BLOCK, outTempBuf, 16 );
			}

			outTempBuf += 16;
			memset( outTempBuf, 16, 16 ); // one more block with byte value all 16.
			*outTempBufLen = 32;
			status = 1; // finished
		}
		else { // ">": can pad in last vacant byte
			restLen = inDataTotalLen - *inDataOffset;
			memcpy( outTempBuf, inTempBuf, restLen );
			
			// padding
			memset( outTempBuf + restLen, 16 - restLen, 16 - restLen );
			*outTempBufLen = 16;
			status = 1; // finished
		}
	}


	//
	// intermediate encryption
	//
	{
		memxor( ENCRYPT_IV_BLOCK, outTempBuf, 16 );
		AES_encrypt_block( outTempBuf, outTempBuf, key );
		memcpy( ENCRYPT_IV_BLOCK, outTempBuf, 16 );  // save
	}

    //
	// output
	//

	// increase offset
    *inDataOffset += 16;

	return status;
}





int AES_cbc_dec_step( unsigned char *inTempBuf, 
							   unsigned char *outTempBuf, 
							   unsigned int  inDataTotalLen, 
							   unsigned int  *outTempBufLen,
							   unsigned int  *inDataOffset,
							   unsigned char *key, 
							   unsigned char *ivec)
/*++
 Func:          decrypt the message with AES/CBC, output plaintext, return plaintext length
 Assumption:    output pointing to an sufficient buffer
 Input:         
            key128, IV, 
		    inTempBuf, inDataTotalLen, inDataOffset
 Output:        
            outTempBuf, outTempBufLen
		    inDataOffset
 Return:  
            -1: fail; 0:continue; 1: finished
 Note:    
            allow inTempBuf/outTempBuf overlap, if outTempBuf has sufficient buffer
 Refer to: 
	        AES_cbc_decrypt() and decrypt() in aes_cbc.c
--*/
{
	static unsigned char DECRYPT_IV_BLOCK[16] = {0};

	unsigned char tmp_last_block[16] = {0};

	unsigned int padLen;

	int status;  // 0: continue; >0: finished len; negative: fail

	if ( inDataTotalLen == 0 || inDataTotalLen%AES_BLOCK_SIZE != 0 )
		return -1;

	if ( *inDataOffset >= inDataTotalLen )
		return -1;

	//
	// Set intermediate IV
	//
	// for the first block, IV is taken from input 
	if ( 0 == *inDataOffset ) {
		memcpy( DECRYPT_IV_BLOCK, ivec, 16 );
	}
	// otherwise IV from last input cipher block stored


	//
	// intermediate decryption
	//
	{
		memcpy( tmp_last_block, inTempBuf, 16 ); // save tmply

		AES_decrypt_block( inTempBuf, outTempBuf, key );
		memxor( DECRYPT_IV_BLOCK, outTempBuf, 16);

		memcpy( DECRYPT_IV_BLOCK, tmp_last_block, 16 ); // save to 
	}


	// output length
    *outTempBufLen = 16; 
	if ( *inDataOffset + 16 < inDataTotalLen )	{ // for normal block
		status = 0; // continue
	}
	else {  // the last block

		// deduce the padding length from the last block
		if ( *inDataOffset + 16 == inDataTotalLen ) { // exactly multi blocks
			padLen = outTempBuf[AES_BLOCK_SIZE-1]; // get rest length, check ?
			if ( (padLen >=1 && padLen <=16) )  // check but do NOT return error
				*outTempBufLen -= padLen;
				   
			status = 1; // finished
		}
		else { 
			// error of the length of ciphertxt: should be exact multi blocks
			status = -1;
		}
	}

	// increase offset
    *inDataOffset += 16;

	return status;
}




