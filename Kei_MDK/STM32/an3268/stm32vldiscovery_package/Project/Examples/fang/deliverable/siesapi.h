/*++
  ******************************************************************************
  * @file         sies.h 
  * @version      V1.0.0
  * @date         2011/01/27
  * @copyright    2011 A*star of Singapore
  * @author       Fang Hui  
  * @brief        This file contains the headers of the encryption module.  
  ******************************************************************************  
--*/ 

#ifndef __I2R_CRYPTO_H__
#define __I2R_CRYPTO_H__

#ifdef  __cplusplus
   extern "C" {
#endif

	   
/////////////////////////////////////////////////////////////////////////// Encryption API


void initSecurityPack(int Detect_REPLAY);

int packData( unsigned char keyType,
	             unsigned char *key,
				 unsigned char *inBlock,
  	             unsigned int   totalBytes,
				 unsigned char *outBuf,
				 unsigned int  *outBufLen,
				 unsigned int  *offset);


int unpackData( unsigned char keyType,
	             unsigned char *key,
				 unsigned char *inBlock,
  	             unsigned int   totalBytes,
				 unsigned char *outBuf,
				 unsigned int  *outBufLen,
				 unsigned int  *offset);


int MCU_updateUK4NMS( unsigned char *receivedBK,
			 unsigned char *R,
			 unsigned char *storedBK,
             unsigned char *storedFK,   
             unsigned char *newSK,
             unsigned int   receivedCounter);



int CalcKey( unsigned char *receivedBK,
			 unsigned char *R,
			 unsigned char *storedBK,
             unsigned char *storedFK,   
             unsigned char *newFK,
             unsigned char *newSK,
             unsigned int   receivedCounter);


int DCU_updateUK4NMS( unsigned char *receivedUK,
	                          unsigned char *storedUK,
	                          unsigned int   receivedCounter);




void hash(       unsigned char       *inData, 
                   unsigned int         inLen, 
				   unsigned char       *outBlock);


int MCU_BeginPack( unsigned char keyType, 
                   unsigned int  MCUcounterOffset,
                   unsigned int *MCU2NMS_dataLen);


void MCU_MiddlePack( unsigned char keyType, unsigned int storedSenderCounter );

void MCU_EndPack( unsigned char keyType);


void MCU_BeginUnpack( unsigned char keyType );

void MCU_MiddleUnpack( unsigned char keyType,
	                        unsigned int  receivedSenderCounter);

int MCU_EndUnpack( unsigned char keyType,
	                      unsigned int storedSenderCounter,
	                      unsigned int receivedSenderCounter,
	                      unsigned int localTime);



void DCU_BeginPack( unsigned char keyType);

void DCU_MiddlePack( unsigned char keyType,
	                      unsigned int storedSenderCounter);

void DCU_EndPack( unsigned char keyType );


void DCU_BeginUnpack( unsigned char keyType );

void DCU_MiddleUnpack( unsigned char keyType,
	                        unsigned int  receivedSenderCounter );


int DCU_EndUnpack( unsigned char keyType,
	                     unsigned int  storedSenderCounter,
	                     unsigned int  receivedSenderCounter,
	                     unsigned int  localTime);


/////////////////////////////////////////////



#ifdef  __cplusplus
    }
#endif

#endif /* !__I2R_CRYPTO_H__ */
