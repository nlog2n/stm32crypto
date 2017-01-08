/*++
   Created by fanghui on 10 Jan. 2011 
 --*/


#ifndef __CRYPTO_HASH_H__
#define __CRYPTO_HASH_H__

#ifdef  __cplusplus
   extern "C" {
#endif


/*

unsigned int crc32( const void* message, int len ); // CRC32
void hash(unsigned char *message, int msgSize, unsigned char *hashValue); // 32-bit CRC hash

*/


void hash(       unsigned char       *in, 
                   unsigned int         inLen, 
				   unsigned char       *outBlock);




void GenerateMAC( const unsigned char *key128,
                      unsigned char *message, 
				      unsigned int msgLen, 
				      unsigned char *outBlock);




#ifdef  __cplusplus
    }
#endif


#endif // __CRYPTO_HASH_H__


