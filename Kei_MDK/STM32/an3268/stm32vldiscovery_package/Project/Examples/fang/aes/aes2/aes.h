

#ifndef __CRYPTO_AES_H__
#define __CRYPTO_AES_H__

#ifdef  __cplusplus
   extern "C" {
#endif


/////////////////////////////////////////////////////////////////////////////////////////  AES Block




// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define AES_Nb 4
#define AES_BLOCK_SIZE 16

////////////////////////////////////////// AES Round Key


// bits =             128, 192, 256
// Nk = bits /32 = 4,  6,     8         // The number of 32 bit words in the key. 
// Nr = Nk + 6   =10, 12,   14       //  only for Nb=4
struct aes_key_st {
	unsigned char RoundKey[240];  	// The array that stores the round keys.
	int AES_Nr;                     // The number of rounds in AES Cipher. 
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


#endif // __CRYPTO_AES_H__


