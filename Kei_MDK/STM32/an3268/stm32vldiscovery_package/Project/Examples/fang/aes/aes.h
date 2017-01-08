/*++ 
******************************************************************************  
* @file         aes.h   
* @version      V1.0.0  
* @date         2011/01/27  
* @copyright    2011 A*star of Singapore  
* @author       Fang Hui    
* @brief        This file contains the headers of the AES encryption module.    
******************************************************************************  
--*/ 





#ifndef __CRYPTO_AES_H__
#define __CRYPTO_AES_H__

#ifdef  __cplusplus
   extern "C" {
#endif


/////////////////////////////////////////////////////////////////////////////////////////  AES Block


/* Because array size can't be a const in C, the following two are macros. Both sizes are in bytes. */
#define AES_Nr_MAX     14
#define AES_BLOCK_SIZE 16

////////////////////////////////////////// AES Round Key


/* This should be a hidden type, but EVP requires that the size be known */
struct aes_key_st {
    unsigned int rd_key[4 *(AES_Nr_MAX + 1)];
    int rounds;
};
typedef struct aes_key_st AES_KEY;


int AES_set_encrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);

void Cipher(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void InvCipher(const unsigned char *in, unsigned char *out, const AES_KEY *key);


void AES_encrypt_block( const unsigned char* inBlock, unsigned char* outBlock, const unsigned char* key128);
void AES_decrypt_block( const unsigned char* inBlock, unsigned char* outBlock, const unsigned char* key128);



/////////////////////////////////////////////////////////////////////////////////////////  AES CBC

void memxor(unsigned char* in, unsigned char *out, int n);

unsigned int AES_get_enc_len( unsigned int msgLen );


unsigned int AES_get_dec_len( unsigned char* message,
                               unsigned int  msgLen,
						       unsigned char* key,
                               unsigned char* IV);


unsigned int AES_cbc_encrypt( unsigned char *in, 
							   unsigned char *out, 
							   unsigned int  length, 
							   const AES_KEY *key, 
							   unsigned char *ivec);

unsigned int AES_cbc_decrypt( unsigned char *in, 
							   unsigned char *out, 
							   unsigned int  length, 
							   const AES_KEY *key, 
							   unsigned char *ivec);




/////////////////////////////////////////////////////////////////////////////////////// API wrapper


// note: the order of paramters is different from AES_cbc_encrypt
unsigned int encrypt(        const unsigned char* key, 
	                          unsigned char* IV,
 	                          unsigned char* inData, 
                              unsigned int   inLen, 
	                          unsigned char* outData);

unsigned int decrypt(        const unsigned char* key, 
	                          unsigned char* IV,
 	                          unsigned char* inData, 
                              unsigned int   inLen, 
	                          unsigned char* outData);


/////////////////////////////////////////////////////////////////////////////////////// 



#ifdef  __cplusplus
    }
#endif

#endif /* !__CRYPTO_AES_H__ */
