/* created by: fanghui  on 10 Jan. 2011 */

#include "../aes/aes.h"
#include "pack.h"



int detectReplay = 0;


////////////////////////////////////////////////////////////////// Key Type

int PACK_status = 0;   // 0 : DCU, 1: MCU/NMS
int UNPACK_status = 0;

unsigned int SenderCounterInUse = 0;  // hide this parameter in use by packData and unpackData

// for NMS counter only
unsigned int anchorNMSCnt = 0;
unsigned int lastTime = 0;



void initSecurityPack(int Detect_REPLAY)
{
    detectReplay = Detect_REPLAY;
}





// keyMode:
//     0:    No encryption, no MAC               -- support
//     1:    No encryption, with MAC             --support
//     2:    Encryption, no MAC                  --no support yet
//     3:    Encryption, with MAC                --support
unsigned char getKeyMode( unsigned char keyType, int pack_status)
{
    // get keyMode separately
	if ( pack_status == 0 ) {  // for DCU
		keyType >>= 4;
	}
	else { // for MCU/NMS
        keyType &= 0x0F;
	}

	
    if ( !(keyType & 0x07) ) {
		return 0 ;   // according to document, "No key" implies no encryption nor MAC
    }


	if ( keyType & 0x08 ) {  // MAC + encryption
		return 3;
	}
	else if ( keyType ) {  // MAC only, no encryption
		return 1;
	}

	return 0; // Neither encryption nor MAC
}




/////////////////////////////////////////////////////////////// packing and unpacking

// Func:
// Input:
// Implicit input:  PACK_status, SenderCounterInUse
int packData( unsigned char keyType,
	             unsigned char *key,
				 unsigned char *inBlock,
  	             unsigned int   totalBytes,
				 unsigned char *outBuf,
				 unsigned int  *outBufLen,
				 unsigned int  *offset)
{
	unsigned char keyMode;

//	if ( !key ) 
//		return -1;

    keyMode = getKeyMode( keyType, PACK_status);

	return pack_step( keyMode, key,
				 inBlock, totalBytes,
				 outBuf, outBufLen,
				 offset,
				 SenderCounterInUse);

}


// Func:
// Input:
// Implicit input:  PACK_status, SenderCounterInUse
int unpackData( unsigned char keyType,
	             unsigned char *key,
				 unsigned char *inBlock,
  	             unsigned int   totalBytes,
				 unsigned char *outBuf,
				 unsigned int  *outBufLen,
				 unsigned int  *offset)
{
	unsigned char keyMode;

//	if ( !key ) 
//		return -1;

    keyMode = getKeyMode( keyType, UNPACK_status);

	return unpack_step( keyMode, key,
				 inBlock, totalBytes,
				 outBuf, outBufLen,
				 offset,
				 SenderCounterInUse);
}


///////////////////////////////////////////////////////////////////  Check sender counter 


// Func: to prevent replay attack
//       If OK returned, external caller should update and store receivedCounter 
//
// Called by: MCU_MiddleUnpack() and DCU_MiddleUnpack() only
int CheckSenderCounter( unsigned int  storedCounter,
                              unsigned int  receivedCounter,
                              unsigned int  localTime)
{
#define MY_ABS(x,y)  (((x)>(y))? ((x)-(y)):((y)-(x)))

	unsigned int recvCnt, savedCnt;

	recvCnt = (unsigned int ) (receivedCounter - anchorNMSCnt);
	savedCnt = (unsigned int ) (storedCounter - anchorNMSCnt);

	if( !detectReplay ) { //does not check replay attack in phase 1
		lastTime = localTime;
		return 1;  
	}

    // normally, we judge ( receivedSenderCounter <= storedSenderCounter ) 
    // to determine that detected replay attack happened

	if ( recvCnt < savedCnt )	
		return 0; // detected replay attack

	if ( recvCnt == savedCnt ) {
		
		//if ( abs(localTime - lastTime) > 2 ) 		
		if ( MY_ABS(localTime , lastTime) > 2 )	
			return 0;  // detected replay attack
	}

	// update
	lastTime = localTime;
	
	return 1; // OK
}




///////////////////////////////////////////////////////////////////  MCU supporting APIs

int MCU_BeginPack( unsigned char keyType, 
                   unsigned int  MCUcounterOffset,
                   unsigned int *MCU2NMS_dataLen)
{
    unsigned char keyMode;
	unsigned int outLen;

	// check if counter offset lies in [0, 16)
	if ( MCUcounterOffset > 15 ) 
		return -1; //wrong position of counter


    PACK_status = 0;         // for data for DCU
	SenderCounterInUse = 0;  // for data for DCU

	keyMode = getKeyMode( keyType, PACK_status /* for MCU */ );
	if ( keyMode == 3 ) {  //  datalen + maclen + padlen
		outLen = AES_get_pack_len( *MCU2NMS_dataLen, MAC_LEN );
	}
	else if ( keyMode == 1 ) {  // no encryption, MAC pad
        outLen = *MCU2NMS_dataLen + MAC_LEN ;
	}
	else {  // plain
        outLen = *MCU2NMS_dataLen ;		
	}

	*MCU2NMS_dataLen = outLen;

    return 1;  // OK
}



void MCU_MiddlePack( unsigned char keyType, unsigned int storedSenderCounter )
{
	PACK_status = 1;   // for MCU/NMS
    SenderCounterInUse = storedSenderCounter;
	
    return ;
}


void MCU_EndPack( unsigned char keyType)
{
    //
    // save increased sender counter externally
    //
	// localCounter = SenderCounterInUse +1; // where SenderCounterInUse is from stored.
	

	// if ( keyType & 0x0F )          senderCounter4NMS++;
	// else if ( keyType & 0x0F0 ) senderCounter4NotNMS++;
	
    return ;
}



void MCU_BeginUnpack( unsigned char keyType )
{
    UNPACK_status = 0;   // for DCU
    SenderCounterInUse = 0; // for DCU
    
    return ;
}


void MCU_MiddleUnpack( unsigned char keyType,
	                        unsigned int  receivedSenderCounter)
{
    UNPACK_status = 1; // for MCU/NMS
    SenderCounterInUse = receivedSenderCounter; // update internal counter
}


int MCU_EndUnpack( unsigned char keyType,
	                      unsigned int storedSenderCounter,
	                      unsigned int receivedSenderCounter,
	                      unsigned int localTime)
{
    int status;

    status = CheckSenderCounter( storedSenderCounter, receivedSenderCounter, localTime );
	if ( !status ) {
		return -1;  // fail
	}


    //
    // update received sender counter externally
    //
    // storedSenderCounter = SenderCounterInUse; 

    return 1; // OK
}


///////////////////////////////////////////////////////////////////  DCU supporting APIs


// handling DCU originated packing
void DCU_BeginPack( unsigned char keyType)
{
    PACK_status = 0; // for DCU only
    SenderCounterInUse = 0;
	
    return ;
}

void DCU_MiddlePack( unsigned char keyType,
	                      unsigned int storedSenderCounter)
{
	PACK_status = 1;    // This function is called iff DCU is a router
    return ;
}

void DCU_EndPack( unsigned char keyType )
{

    // increase sender counter, which is DCU counter
	// *storedSenderCounter = *storedSenderCounter + 1;
	
	//if( 0 == PACK_status) // DCU is a sender
	//{
	//	if(keyType & 0x0F0) senderCounter4NMS++;
	//	else if(keyType & 0x0F) senderCounter4NotNMS++;
	//}
	
    return ;
}




// handling DCU  unpack --> pack process
void DCU_BeginUnpack( unsigned char keyType )
{
    UNPACK_status = 0; // for DCU
    SenderCounterInUse = 0;

    return ;
}


// called only when DCU as a router
void DCU_MiddleUnpack( unsigned char keyType,
	                        unsigned int  receivedSenderCounter )
{
    // assert:  DCU as router

    PACK_status = 0; // for DCU. Do NOT setting UNPACK_status here
    SenderCounterInUse = 0;

    UNPACK_status = 1;  // which is used to indicate that DCU as a router.
                         // otherwise, its default value is 0 from last step
}


int DCU_EndUnpack( unsigned char keyType,
	                     unsigned int  storedSenderCounter,
	                     unsigned int  receivedSenderCounter,
	                     unsigned int  localTime)
{
    int status;
    int DCU_as_router = UNPACK_status;

	if ( !DCU_as_router ) {   // DCU as destination
	
	   // check on sender counter then 
   	   status = CheckSenderCounter( storedSenderCounter, receivedSenderCounter, localTime);
	   if ( !status ) {
	   
		   return -1;  // fail
	   }

	}

    // if DCU as router, no check on sender counter


    //
    // update received sender counter externally
    //
    // storedSenderCounter = receivedSenderCounter; 

    return 1; // OK
}




