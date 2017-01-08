/*++
Created by fanghui on 10 Jan. 2011

Hash functions

--*/


#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#include "../aes/aes.h"
#include "hash.h"



/*
void hash(unsigned char *message, int msgSize, unsigned char *hashValue)
{
    unsigned int h =  crc32( message, msgSize ); 
	memcpy( hashValue, &h, 4 );
}
*/



void hash(       unsigned char       *in, 
                   unsigned int         inLen, 
				   unsigned char       *outBlock)
/*++
     Func:      generate hash
     Input:     input message, input message length, 128-bit key
     Output:    128-bit hash in a block
     Return:    None
     Called by:  
--*/
{
	unsigned int i,restLen, Iter;
	unsigned char key[AES_BLOCK_SIZE];

	memset( outBlock, 0, AES_BLOCK_SIZE );

	restLen =  inLen%AES_BLOCK_SIZE;
    Iter = inLen/AES_BLOCK_SIZE;
	Iter = (restLen == 0) ? Iter : Iter+1;
	for(i=0; i < Iter; i++) {

		//memcpy( key, in, AES_BLOCK_SIZE );

		if ( i == Iter -1 ) {  
			memcpy( key, in, restLen );

			// pad zero for the rest of last block
			memset( key + restLen, 0, (AES_BLOCK_SIZE - restLen)%AES_BLOCK_SIZE );   
		}
		else {
			memcpy( key, in, AES_BLOCK_SIZE );			
		}

		AES_encrypt_block( outBlock, outBlock, key );
		in  += AES_BLOCK_SIZE;
	}
}





////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//  GenerateMAC():   MAC based on AES_encrypt_block
//
///////////////////////////////////////////////////////////////////////////////// 
///////////////////////////////////////////////////////////////////////////////// 

/*++
     Func:      generate Message Authentication Code  (old version)
     Input:     input message, input message length, 128-bit key
     Output:    128-bit MAC in a block
     Return:    None
	 Called by:  GenerateMAC() only

	 Details:   
	            1. split inData M into exact n blocks <M1,M2,...,Mn>,
				   where the last block is padded with zeros if necessary.
			    2. h = AES_enc_block( 128-bit 0 ) with input key.
				3. for i=1 to n
				        h = AES_enc_block(h) with key= Mi
			    4. return h
--*/

/*********************************************************************


void generate_mac( const unsigned char *key128,
                   unsigned char       *in, 
                   unsigned int         inLen, 
				   unsigned char       *outBlock)
{
	unsigned int i,restLen, Iter;
	unsigned char key[AES_BLOCK_SIZE]={0};

    AES_encrypt_block( key, outBlock, key128 );


    Iter = inLen/AES_BLOCK_SIZE;
	Iter = (inLen%AES_BLOCK_SIZE == 0) ? Iter : Iter+1;

	for(i=0; i < Iter; i++) {

		memcpy( key, in, AES_BLOCK_SIZE );

		if ( i == Iter -1 ) {  
			// pad zero for the rest of last block
	        restLen = inLen%AES_BLOCK_SIZE;
			if ( restLen == 0  ) 
				restLen = AES_BLOCK_SIZE;

			memset( key + restLen, 0, AES_BLOCK_SIZE - restLen );   
		}

		AES_encrypt_block( outBlock, outBlock, key );
		in  += AES_BLOCK_SIZE;
	}

}



extern void readFlash( unsigned char *ram, unsigned int addr, unsigned int len );
extern int writeFlash(unsigned char *ram, unsigned int addr, unsigned int len);

//	 Note:      outBlock in flash or ram
//   called external flash functions:
//         readFlash()
//         writeFlash()
void generate_mac_flash( const unsigned char *key128,
                   unsigned char       *in, 
                   unsigned int         inLen, 
				   unsigned char       *outBlock)
{
	unsigned int i,restLen, Iter= inLen/AES_BLOCK_SIZE;
	unsigned char key[AES_BLOCK_SIZE]={0};
	unsigned char tmpBlock[AES_BLOCK_SIZE]={0};

    AES_encrypt_block( key, tmpBlock, key128 );

    Iter = inLen/AES_BLOCK_SIZE;
	Iter = (inLen%AES_BLOCK_SIZE == 0) ? Iter : Iter+1;

	for(i=0; i < Iter; i++) {

		//memcpy( key, in, AES_BLOCK_SIZE );
		readFlash( key, (unsigned int)in, AES_BLOCK_SIZE );

		if ( i == Iter -1 ) {  
			// pad zero for the rest of last block
	        restLen = inLen%AES_BLOCK_SIZE;
			if ( restLen == 0 )
				restLen = AES_BLOCK_SIZE;

			memset( key + restLen, 0, AES_BLOCK_SIZE - restLen );   
		}

		AES_encrypt_block( tmpBlock, tmpBlock, key );
		in  += AES_BLOCK_SIZE;
	}

	// tmpBlock stores outMAC
    writeFlash( tmpBlock, (unsigned int)outBlock, AES_BLOCK_SIZE );
}



*********************************************************************/





void generate_mac_new( const unsigned char *key128,
                   unsigned char       *in, 
                   unsigned int         inLen, 
				   unsigned char       *outBlock)
/*++
     Func:      generate Message Authentication Code
     Input:     input message, input message length, 128-bit key
     Output:    128-bit MAC in a block
     Return:    None
	 Called by:  GenerateMAC() only
--*/
{
    hash( in, inLen, outBlock);
    AES_encrypt_block( outBlock, outBlock, key128);
}





void GenerateMAC( const unsigned char *key128,
                      unsigned char *message, 
                      unsigned int msgLen, 
				      unsigned char *outMAC)
/*++
     Func:      generate Message Authentication Code
     Input:     input message, input message length, 128-bit key
     Output:    128-bit MAC in a block
     Return:    None
	 Called by: AuthEncrypt(), CheckDecrypt(), and external
	 Note:      support flash output
--*/
{
    //generate_mac_flash( key128, message, msgLen, outMAC );     // output to flash/ram
    //generate_mac( key128, message, msgLen, outMAC ); 	// output to ram
    generate_mac_new( key128, message, msgLen, outMAC ); 	// new    
}



