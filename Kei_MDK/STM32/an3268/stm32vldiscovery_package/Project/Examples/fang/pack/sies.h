/*++
   created by fanghui on 10 Jan. 2011 
   revisions: use const char* for message
            add keyUpdate() on 11 Jan.
			use unsigned char* instead char*

 --*/

#ifndef __CRYPTO_SIES_H__
#define __CRYPTO_SIES_H__

#ifdef  __cplusplus
   extern "C" {
#endif




typedef struct {
	unsigned int SessionCount;    // session count
	unsigned char FK[16];          // forward key (n-i+1)
	unsigned char BK[16];          // backward key i
	unsigned char SK[16];          // session key i
	unsigned char MCU_MK[16];      // MCU master key, fixed
	unsigned char DCU_MCU_K[16];   // DCU MCU key, fixed
	unsigned char MCU_ID[16];      // MCU serial number
	unsigned int NMS_SenderCount; // for inner encryption
	unsigned int MCU_SenderCount; // for inner encryption
} MCU_CRYPTO_DATA, *PMCU_CRYPTO_DATA;



//bool keyUpdate(unsigned char *MCUid,unsigned char *MCUkey, int term,unsigned char *newMCUkey);

int keyUpdate(unsigned char* FK, unsigned char* BK, unsigned char* R, PMCU_CRYPTO_DATA pMCU );



void GenerateMAC_step(const unsigned char *key,
				  unsigned char       *inTempBuf,
				  unsigned int         inDataTotalLen,
				  unsigned char       *outTempBuf,
				  unsigned int        *outTempBufLen,
				  unsigned int        *inDataOffset);

int CheckMAC_step(const unsigned char *key,
			  unsigned char       *inTempBuf,
			  unsigned int         inDataTotalLen,
			  unsigned int        *inDataOffset);


int AES_cbc_enc_step( unsigned char    *inTempBuf, 
							   unsigned char *outTempBuf, 
							   unsigned int  inDataTotalLen, 
							   unsigned int  *outTempBufLen,
							   unsigned int  *inDataOffset,
							   unsigned char *key, 
							   unsigned char *ivec);


int AES_cbc_dec_step( unsigned char *inTempBuf, 
							   unsigned char *outTempBuf, 
							   unsigned int  inDataTotalLen, 
							   unsigned int  *outTempBufLen,
							   unsigned int  *inDataOffset,
							   unsigned char *key, 
							   unsigned char *ivec);



#ifdef  __cplusplus
    }
#endif


#endif // __CRYPTO_SIES_H__
