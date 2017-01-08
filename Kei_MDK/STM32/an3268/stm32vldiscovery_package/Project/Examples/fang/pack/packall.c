
/* created by: fanghui  on 10 Jan. 2011 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "../config.h"
#include "../aes/aes.h"
#include "../hash/hash.h"
#include "pack.h"



int AuthEncrypt( const unsigned char* key, 
                        unsigned char* IV,
                        unsigned char* message, 
				        unsigned int msgLen,                        
                        unsigned char* output)
/*++
     Func:      generated data in format Encrypted[message||MAC]
     Input:     input message, output address, input message length, 128-bit key, 128-bit IV
     Output:    Enc(message||MAC)
     Return:    length of output. 
	 Called by:  external
     Note:      support input/output overlapping.
	            support flash input/output
                user should ensure sufficient output buffer
--*/
{
	//unsigned int outLen;
	//unsigned char MAC[AES_BLOCK_SIZE];

	memcpy( output, message, msgLen );
	GenerateMAC( key, message, msgLen,  output + msgLen);

	return encrypt( key, IV, output, msgLen + AES_BLOCK_SIZE, output);
}


int CheckDecrypt(const unsigned char* key, 
                        unsigned char* IV,
                        unsigned char* message, 
				        unsigned int msgLen,                        
                        unsigned char* output)
/*++
     Func:      decrypt authenticated message in format Encrypted[message||MAC]
     Input:     input message, output address, input message length, 128-bit key, 128-bit IV     
     Output:    original message, without MAC
     Return:    length of output. Negative value for error
	 Called by:  external
     Note:      support input/output overlapping
	            support flash input/output
--*/
{
	unsigned int outLen;
	unsigned char MAC[AES_BLOCK_SIZE];

	outLen = decrypt( key, IV, message, msgLen, output);
	if ( outLen <= AES_BLOCK_SIZE) return -1;

	// check
	outLen -= AES_BLOCK_SIZE;
	GenerateMAC( key, output, outLen, MAC);
	if ( memcmp( MAC, output + outLen , AES_BLOCK_SIZE ) != 0 ) return -2;

	return  outLen ;
}




// Func:  Given session skey, DCU_MCU key, and input message, output the ciphertext
// Prerequisite:  output pointing to an sufficient buffer
int pack( unsigned char     *key,
			  unsigned char *inData, 
    		  unsigned int   inDataLen,
			  unsigned char *outData,    		  
	          unsigned int   SenderCounter)
{
    unsigned char IV[AES_BLOCK_SIZE];
	int outLen;

	unsigned char *XXX;
	unsigned int mac_prefix_len;  /* for MAC geneartion */
	unsigned char outMAC[AES_BLOCK_SIZE];

    // added on 20110412
    unsigned int SenderCounterNet = SWITCH_ENDIAN( (unsigned char*)&SenderCounter );
	unsigned int inDataLenNet     = SWITCH_ENDIAN( (unsigned char*)&inDataLen );

    /// compute MAC
	mac_prefix_len = 4+4;
	XXX = malloc( mac_prefix_len + inDataLen );
	if ( !XXX )
		return -1;

	memcpy( XXX,   (unsigned char*)&SenderCounterNet, 4 );   // big-endian
	memcpy( XXX+4, (unsigned char*)&inDataLenNet, 4 );       // big-endian
	memcpy( XXX+8,  inData, inDataLen );
	GenerateMAC( key, XXX, 8 + inDataLen , outMAC);

	free( XXX );

	memPrint("pack:outMAC", outMAC, AES_BLOCK_SIZE);
	memPrint("pack:choose MAC=", outMAC, MAC_LEN);	

	memcpy( outData, inData, inDataLen );    
	memcpy( outData + inDataLen, outMAC, MAC_LEN );
	outLen = inDataLen + MAC_LEN;  

	// Enc( key, IV, inData || MAC )
	AES_get_IV_from_SenderCounter( SenderCounter, IV);    // the function will take care of big-endian
	outLen = encrypt( key, IV, outData, outLen, outData);
	return outLen;
}



int unpack( unsigned char     *key,
			  unsigned char *inData, 
    		  unsigned int   inDataLen,
			  unsigned char *outData,    		  
	          unsigned int   SenderCounter)
{
    unsigned char IV[AES_BLOCK_SIZE];
	int outLen, dataLen;

	unsigned char *XXX;
	unsigned int mac_prefix_len;  /* for MAC geneartion */
	unsigned char outMAC[AES_BLOCK_SIZE];
	unsigned char outMAC2[AES_BLOCK_SIZE];

    // added on 20110412
    unsigned int SenderCounterNet, dataLenNet;


	// Dec( key, IV, inData || MAC )
	AES_get_IV_from_SenderCounter( SenderCounter, IV);   // the function will take care of big-endian
    outLen = decrypt( key, IV, inData, inDataLen, outData );
	if ( outLen <= MAC_LEN ) {
		//printf("unpackData: first decryption error!\r\n");
		return 0;
	}

    // extract MAC
	dataLen = outLen - MAC_LEN;    
    memcpy( outMAC2, outData + dataLen, MAC_LEN );

    // compute MAC
	mac_prefix_len =  4 + 4; 
	XXX = malloc( mac_prefix_len + dataLen );
	if ( !XXX )
		return -1;

    // added on 20110412
    SenderCounterNet = SWITCH_ENDIAN( (unsigned char*)&SenderCounter ); 
	dataLenNet     = SWITCH_ENDIAN( (unsigned char*)&dataLen );      

	memcpy( XXX,   (unsigned char*)&SenderCounterNet, 4 );  // big-endian
	memcpy( XXX+4, (unsigned char*)&dataLenNet, 4 );        // big-endian
	memcpy( XXX+8,  outData, dataLen );
	GenerateMAC( key, XXX, mac_prefix_len + dataLen , outMAC);

	free( XXX );

	memPrint("unpack:compute MAC block", outMAC, AES_BLOCK_SIZE);
	memPrint("unpack:compute  MAC=", outMAC, MAC_LEN);	
	memPrint("unpack:retrieve MAC=", outMAC2, MAC_LEN);	

	if ( memcmp( outMAC, outMAC2, MAC_LEN ) != 0 ) 
		return -1;  // HMAC mismatch!

	return dataLen;
}



