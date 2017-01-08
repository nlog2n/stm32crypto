/*++
   Created by fanghui on 10 Jan. 2011 
 --*/

#ifndef __CRYPTO_PACK_H__
#define __CRYPTO_PACK_H__


#ifdef  __cplusplus
   extern "C" {
#endif


/////////////////////////////////////////////////////////////////// To Big Endian
//
// added on 20110412
// affected functions:  HMAC_get_current_offset_byte( ..., SenderCounter, dataLen,...), 
//                              AES_get_IV_from_SenderCounter( SenderCounter, ...)
//
// local variable is in little-endian, turn it into big endian
#define SWITCH_ENDIAN(pt) (    ((unsigned int)(pt)[0] << 24)   \
	                         ^ ((unsigned int)(pt)[1] << 16)   \
	                         ^ ((unsigned int)(pt)[2] <<  8)   \
	                         ^ ((unsigned int)(pt)[3])         )

// #define SWITCH_ENDIAN(pt) ((unsigned int)(pt) )
//////////////////////////////////////////////////////////////////



#define MAC_LEN    12   // 96 bits



unsigned int AES_get_pack_len( unsigned int dataLen, unsigned int macLen );

void AES_get_IV_from_SenderCounter(   unsigned int SenderCounter,   unsigned char *IV );

int AuthEncrypt(	const unsigned char* key, 
                        unsigned char* IV,
                        unsigned char* message, 
				        unsigned int msgLen,                        
                        unsigned char* output);


int CheckDecrypt(const unsigned char* key, 
                        unsigned char* IV,
                        unsigned char* message, 
				        unsigned int msgLen,                        
                        unsigned char* output);


int pack( unsigned char *key,
			  unsigned char *inData, 
    		  unsigned int   inDataLen,
			  unsigned char *outData,    		  
	          unsigned int   SenderCounter);


int unpack( unsigned char     *key,
			  unsigned char *inData, 
    		  unsigned int   inDataLen,
			  unsigned char *outData,    		  
	          unsigned int   SenderCounter);


int HMAC_step(unsigned char *key, 
         unsigned int   SenderCounter,
         unsigned int   totalLen,
         unsigned char *inBlock,
         unsigned char *outBuf,
         unsigned int  *outBufLen,
         unsigned int  *offset);


int AES_ENC_MAC_step(			  unsigned char *key, 
								  unsigned int   SenderCounter,  /* for IV */
								  unsigned int   dataLen,   /* exclude MAC */
								  unsigned char *inBlock, 
								  unsigned char *MAC,
								  unsigned int   macLen,
								  unsigned char *outBuf, 
								  unsigned int  *outBufLen,
								  unsigned int  *offset);


int NoEncryption_MAC_step(
								  unsigned int   dataLen,   /* exclude MAC */
								  unsigned char *inBlock, 
								  unsigned char *MAC,
								  unsigned int   macLen,    /* be 0 for decryption step */
								  unsigned char *outBuf, 
								  unsigned int  *outBufLen,
								  unsigned int  *offset);




int pack_step( unsigned char keyMode,
	             unsigned char *key,
				 unsigned char *inBlock,
  	             unsigned int   totalLen,
				 unsigned char *outBuf,
				 unsigned int  *outBufLen,
				 unsigned int  *offset,
				 unsigned int   SenderCounter);



int unpack_step( unsigned char keyMode,
	             unsigned char *key,
				 unsigned char *inBlock,
  	             unsigned int   totalLen,
				 unsigned char *outBuf,
				 unsigned int  *outBufLen,
				 unsigned int  *offset,
				 unsigned int   SenderCounter);




// DeviceFlag, not in use any more
#define DEVICE_FLAG_NMS2DCU   0
#define DEVICE_FLAG_NMS2MCU   1
#define DEVICE_FLAG_DCU2MCU   2
#define DEVICE_FLAG_DCU2NMS   3
#define DEVICE_FLAG_MCU2DCU   4
#define DEVICE_FLAG_MCU2NMS   5




#ifdef  __cplusplus
    }
#endif


#endif // __CRYPTO_PACK_H__

