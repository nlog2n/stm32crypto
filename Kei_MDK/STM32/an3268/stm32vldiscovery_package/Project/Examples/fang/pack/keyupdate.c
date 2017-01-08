/*++

 Created by: fanghui  on 10 Jan. 2011 

--*/

#include <string.h>

#include "../aes/aes.h"
#include "../hash/hash.h"



void getNewForwardKey(unsigned char *FK, unsigned char *newFK)
{
	memset( newFK, 0, AES_BLOCK_SIZE );   // set plaintext as zero
    AES_encrypt_block( newFK, newFK, FK ); // key = FK
}


void getNewSessionKey( unsigned char* FK, unsigned char* BK, unsigned char* R, unsigned char* SK )
/*++
 Func:   generating new session key for MCU
 Input:  FK,BK,R are received from NMS
            FK - forward key, 16 byte
            BK - backward key, 16 byte
	     R  - randome number, 16 byte
 Output: SK - session key, 16 byte
--*/
{
    memset( SK, 0,  AES_BLOCK_SIZE );
    memxor( FK, SK, AES_BLOCK_SIZE);  // SK = FK
	memxor( BK, SK, AES_BLOCK_SIZE);  // SK = BK ^ SK
	memxor( R,  SK, AES_BLOCK_SIZE);  // SK = R ^ SK
}



//////////////////////////////////////////////////////////////////  key generation

extern unsigned int anchorNMSCnt;


// Input:  
//              receivedBK,   is new BK
//              R, 
//              storedBK,  is old BK
//              storedFK
// Output: 
//              newFK, 
//              newSK
// Return:  0 - fail; 1 - success
int MCU_updateUK4NMS( unsigned char *receivedBK,
			 unsigned char *R,
			 unsigned char *storedBK,
             unsigned char *storedFK,   
             unsigned char *newSK,
             unsigned int   receivedCounter)
{
    unsigned char HBK[AES_BLOCK_SIZE];
	unsigned char newFK[AES_BLOCK_SIZE];

    // check if  hash(new BK) == BK
    hash( receivedBK, AES_BLOCK_SIZE , HBK );
    if ( memcmp( HBK, storedBK, AES_BLOCK_SIZE ) != 0 )
		return 0; // fail

    // generate new forward key locally
	getNewForwardKey( storedFK, newFK);  // or newFK = hash(storedFK)
	memcpy( storedFK, newFK, AES_BLOCK_SIZE );  // update

    // new session key
    getNewSessionKey( newFK, receivedBK, R, newSK);

    anchorNMSCnt = receivedCounter;  //update last NMS Cnt
	
    return 1;
}


int DCU_updateUK4NMS( unsigned char *receivedUK,
	                          unsigned char *storedUK,
	                          unsigned int   receivedCounter)
{
//    if ( memcmp( receivedUK, storedUK, AES_BLOCK_SIZE ) != 0 )
//		return 0; // fail

    memcpy( storedUK, receivedUK, AES_BLOCK_SIZE ); // update

    anchorNMSCnt = receivedCounter; // update last NMS Cnt

	return 1; // success
}



int CalcKey( unsigned char *receivedBK,
			 unsigned char *R,
			 unsigned char *storedBK,
             unsigned char *storedFK,   
             unsigned char *newFK,
             unsigned char *newSK,
             unsigned int   receivedCounter)
{
    return MCU_updateUK4NMS( receivedBK, R, storedBK, storedFK, newSK, receivedCounter);
}



