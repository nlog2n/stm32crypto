//#include <assert.h>
#include <string.h>

#include "aes.h"




//////////////////////////////////////////////////////////////////////////////////////////////////  
//
// AES CBC mode
//
//////////////////////////////////////////////////////////////////////////////////////////////////

unsigned int AES_cbc_encrypt( unsigned char *in, 
							   unsigned char *out, 
							   unsigned int  length, 
							   const AES_KEY *key, 
							   unsigned char *ivec)
/*++
	 Func:		encrypt data with variable length by CBC mode
 	            encrypt the message with AES 128-bit /CBC, output ciphertext, return ciphertext length
	 Prerequisite:	output pointing to an sufficient buffer
	                     padding mode = PKCS #5
	 Input: 		key128, IV, message, msgLen
	 Output:		output
	 Return:		output length
	 Note:          allow in/out overlap, if out has sufficient buffer
--*/
{
	unsigned int i,restLen, Iter= length/AES_BLOCK_SIZE;
	unsigned char *iv = ivec;

	for(i=0; i <=  Iter; i++) {

		memcpy( out, in, AES_BLOCK_SIZE );			
		if ( i == Iter ) {  
            // pad the last block with rest length value 
		    // PKCS#5:
		    // if message length is not multi blocks (128-bit), pad tail to length value and encrypt
		    // if it is exactly multi blocks, add one more block with all zeroes
	        restLen = length%AES_BLOCK_SIZE;
			memset( out + restLen, AES_BLOCK_SIZE - restLen , AES_BLOCK_SIZE - restLen );   
		}

		// XOR with initial vector
		memxor( iv, out, AES_BLOCK_SIZE );
		
		// Encrypt the block
		Cipher( out, out, key );
		
		iv = out;
		in  += AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;
	}
	
	return i* AES_BLOCK_SIZE;
}


unsigned int AES_cbc_decrypt( unsigned char *in, 
							   unsigned char *out, 
							   unsigned int  length, 
							   const AES_KEY *key, 
							   unsigned char *ivec)
/*++
 Func:          decrypt the message with AES/CBC, output plaintext, return plaintext length
 Prerequisite:  output pointing to an sufficient buffer
 Input:         key, IV, message, msgLen
 Output:        output
 Return:        output length
 Note:          allow in/out overlap
--*/
{
	unsigned int i, Iter=length/AES_BLOCK_SIZE;
	unsigned int padLen, retLen = 0;
	unsigned char *iv = ivec;
	unsigned char inBlock[AES_BLOCK_SIZE]={0};
	unsigned char outBlock[AES_BLOCK_SIZE]={0};

	if ( length == 0 || length%AES_BLOCK_SIZE != 0 )
		return 0;

	// decrypt from the first block, allowing in/out overlap
    for (i= 0;i<Iter;i++) {

		// decrypt
		InvCipher( in, outBlock, key );  

        // xor with IV
		memxor( iv, outBlock, AES_BLOCK_SIZE);

        // output		
		memcpy( inBlock, in, AES_BLOCK_SIZE);  // inBlock <--  in
		memcpy( out, outBlock, AES_BLOCK_SIZE); //             out  <--  outBlock. note that out may be equal to in!

		retLen += AES_BLOCK_SIZE;
		// deduce the padding length from the last block
		if ( i == Iter -1 ) { 
			padLen = out[AES_BLOCK_SIZE-1];  // get rest length, check ?
			if ( (padLen >=1 && padLen <=16) )  // check but do NOT return error
  			        retLen -= padLen;
		} 

		iv    = inBlock; // get IV as previous block
	    in	 += AES_BLOCK_SIZE;
	    out  += AES_BLOCK_SIZE;
    }

	return retLen;
}




unsigned int AES_cbc_decrypt_reverse( unsigned char *in, 
							   unsigned char *out, 
							   unsigned int  length, 
							   const AES_KEY *key, 
							   unsigned char *ivec)
/*++
 Func:          decrypt the message with AES/CBC, output plaintext, return plaintext length
 Prerequisite:  output pointing to an sufficient buffer
 Input:         key, IV, message, msgLen
 Output:        output
 Return:        output length
 Note:          allow in/out overlap
--*/
{
	unsigned int Iter=length/AES_BLOCK_SIZE;
	unsigned int padLen, retLen = 0;
	unsigned char *iv;
	int           i;   // can not be unsigned due to i--.

	if ( length == 0 || length%AES_BLOCK_SIZE != 0 )
		return 0;

	// decrypt from the last block, allowing in/out overlap
	in  += length - AES_BLOCK_SIZE;
	out += length - AES_BLOCK_SIZE;

    for (i= Iter-1; i >= 0; i--) {

		// decrypt
		InvCipher( in, out, key );  

	    in	 -= AES_BLOCK_SIZE;
		iv    = (i==0)? ivec: in;	// get IV as previous block

        // xor with IV
		memxor( iv, out, AES_BLOCK_SIZE);

		retLen += AES_BLOCK_SIZE;
		// deduce the padding length from the last block
		if ( i == Iter -1 ) { 
			padLen = out[AES_BLOCK_SIZE-1];  // get rest length, check ?
			if ( (padLen >=1 && padLen <=16) )  // check but do NOT return error
  			        retLen -= padLen;
		} 

	    out  -= AES_BLOCK_SIZE;
    }

	return retLen;
}


///////////////////////////////////////////////////////////////////////////////// for flash
//
//  AES_cbc_encrypt_flash()
//  AES_cbc_decrypt_flash()
//
//   called external flash functions:
//         readFlash()
//         writeFlash()
//        
//
///////////////////////////////////////////////////////////////////////////////// 

/********************************************************************************
extern void readFlash( unsigned char *ram, unsigned int addr, unsigned int len );
extern int writeFlash(unsigned char *ram, unsigned int addr, unsigned int len);

unsigned int AES_cbc_encrypt_flash( unsigned char *in, 
							   unsigned char *out, 
							   unsigned int  length, 
							   const AES_KEY *key, 
							   unsigned char *ivec)
{
	unsigned int i,restLen, Iter= length/AES_BLOCK_SIZE;
	unsigned char *iv = ivec;

	unsigned char inBlock[AES_BLOCK_SIZE] ={0};
	unsigned char outBlock[AES_BLOCK_SIZE] ={0};

	for(i=0; i <=  Iter; i++) {
		
		//memcpy( out, in, AES_BLOCK_SIZE ); ///////////////////////////////////
	    readFlash( inBlock, (unsigned int)in, AES_BLOCK_SIZE );

		if ( i == Iter ) {  
            // pad the last block with rest length value 
		    // PKCS#5:
		    // if message length is not multi blocks (128-bit), pad tail to length value and encrypt
		    // if it is exactly multi blocks, add one more block with all zeroes
	        restLen = length%AES_BLOCK_SIZE;

			//memset( out + restLen, AES_BLOCK_SIZE - restLen , AES_BLOCK_SIZE - restLen );   
			memset( inBlock + restLen, AES_BLOCK_SIZE - restLen , AES_BLOCK_SIZE - restLen );   

		}

		// XOR with initial vector
		memxor( iv, inBlock, AES_BLOCK_SIZE );
		
		// Encrypt the block
		Cipher( inBlock, outBlock, key );

		// Write to Flash
        writeFlash( outBlock, (unsigned int)out, AES_BLOCK_SIZE );  ///////////////////////////////////
		
		iv = outBlock;
		in  += AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;
	}
	
	return i* AES_BLOCK_SIZE;
}


unsigned int AES_cbc_decrypt_flash(  unsigned char *in, 
							   unsigned char *out, 
							   unsigned int  length, 
							   const AES_KEY *key, 
							   unsigned char *ivec)
{
	unsigned int i, Iter=length/AES_BLOCK_SIZE;
	unsigned int padLen, retLen = 0;
	unsigned char *iv = ivec;
	unsigned char inBlock[AES_BLOCK_SIZE]  ={0};
	unsigned char outBlock[AES_BLOCK_SIZE] ={0};
	unsigned char tmpBlock[AES_BLOCK_SIZE] ={0};  // for IV

	if ( length == 0 || length%AES_BLOCK_SIZE != 0 )
		return 0;

	// decrypt from the first block, allowing in/out overlap
    for (i= 0;i<Iter;i++) {

		readFlash( inBlock, (unsigned int)in, AES_BLOCK_SIZE );  // inBlock <-- in /////////////////

		// decrypt
		InvCipher( inBlock, outBlock, key );  

        // xor with IV
		memxor( iv, outBlock, AES_BLOCK_SIZE);

        // output	
		memcpy( tmpBlock, inBlock, AES_BLOCK_SIZE);  //   tmpBlock <-- inBlock
		//memcpy( out, outBlock, AES_BLOCK_SIZE); //          out(which may be in!) <-- outBlock 
        writeFlash(outBlock, (unsigned int)out, AES_BLOCK_SIZE); ///////////////////////////////////


		retLen += AES_BLOCK_SIZE;
		// deduce the padding length from the last block
		if ( i == Iter -1 ) { 
			padLen = outBlock[AES_BLOCK_SIZE-1];  // get rest length, check ?
			if ( (padLen >=1 && padLen <=16) )  // check but do NOT return error
  			        retLen -= padLen;
		} 

		iv    = tmpBlock; // get IV as previous block
	    in	 += AES_BLOCK_SIZE;
	    out  += AES_BLOCK_SIZE;
    }

	return retLen;
}
********************************************************************************/



//////////////////////////////////////////////////////////////////////////////// API wrapper
//
// note: the order of paramters is different from AES_cbc_encrypt
//
//////////////////////////////////////////////////////////////////////////////// 


unsigned int encrypt(        const unsigned char* key, 
	                          unsigned char* IV,
 	                          unsigned char* in, 
                              unsigned int   len, 
	                          unsigned char* out)
/*++
		 Func:		  encrypt the message with AES/CBC 128-bit, output ciphertext, return ciphertext length
		 Prerequisite:	output pointing to an sufficient buffer
		 Input: 	  key, IV, message, msgLen
		 Output:		  output
		 Return:		  output length
--*/
{
	AES_KEY  K;
	AES_set_encrypt_key( key, 128, &K);

	//return AES_cbc_encrypt_flash( in, out, len, &K, IV ); // output to flash/ram
	return AES_cbc_encrypt( in, out, len, &K, IV );  // support output to ram only
}


unsigned int decrypt(       const unsigned char* key, 
	                          unsigned char* IV,
 	                          unsigned char* in, 
                              unsigned int   len, 
	                          unsigned char* out)
/*++
		 Func:		  decrypt the message with AES/CBC, output plaintext, return plaintext length
		 Prerequisite:	output pointing to an sufficient buffer
		 Input: 	  key, IV, message, msgLen
		 Output:		  output
		 Return:		  output length
--*/
{
	AES_KEY  K;
	AES_set_decrypt_key( key, 128, &K);

    //return AES_cbc_decrypt_flash( in, out, len, &K, IV ); 	// output to flash/ram
    return AES_cbc_decrypt( in, out, len, &K, IV );     // output to ram
}
