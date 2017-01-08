/* created by: fanghui  on 10 Jan. 2011 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//#include "bsp/flash.h"
#include "config.h"
#include "aes/aes.h"
#include "hash/hash.h"
#include "pack/pack.h"
#include "pack/sies.h"


//#include "stm32f10x.h"
//#include "deliverable/sies.h"




////////////////////////////////////////////////////////////////////////////////////////////////// testing
//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

/*
int test_CRC()
{
	char*  m = "ABCEE";  // ----> CRC : 0x6bc82b94
	char*  m2 = "0";         // ----> CRC : 0xf4dbdf21
    char*  m3 = "123456789"; // ----> CRC : 0xcbf43926
	unsigned char m4[4] = {0};  // 32-bit zero ---> CRC: 0x2144df1c
	unsigned int h;
	hash( (unsigned char*) m, 5, (unsigned char*) &h); // CRC32
	memPrint( "CRC32 on string ABCEE", (unsigned char*) &h, 4 );

	hash( (unsigned char*) m2, 1, (unsigned char*) &h); // CRC32
	memPrint( "CRC32 on string 0", (unsigned char*) &h, 4 );

	hash( (unsigned char*) m3, 9, (unsigned char*) &h); // CRC32
	memPrint( "CRC32 on string 123456789", (unsigned char*) &h, 4 );

	hash( (unsigned char*) m4, 4, (unsigned char*) &h); // CRC32
	memPrint( "CRC32 on 32-bit zero", (unsigned char*) &h, 4 );

	return 1;
}
*/

/*

int test_Flash()
{
#ifdef __STM32F10x_H
   int succeed = 1;

   unsigned int addr =  0x08008000;
   unsigned char inBlock[16] = {0};
   unsigned char outBlock[16]={0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

   dbgPrint("testing flash read and write...\r\n");

   succeed = writeFlash( outBlock, addr, 16 );
   if ( !succeed ) {
      dbgPrint("flash write error!\r\n");
	  return 0;
   }
   dbgPrint("flash write success.\r\n");

   readFlash( inBlock, addr, 16 );
   if ( memcmp( inBlock, outBlock, 16 ) != 0 ) {
      dbgPrint("flash read/write mismatch!\r\n");
	  return 0;
   } 
   dbgPrint("tested done.\r\n\r\n");
#endif

   return 1;
}

*/











void test_AES_Block()
{
	unsigned char key128[16]     = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    unsigned char plaintxt[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	unsigned char correctciphertxt[16]= { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
	unsigned char ciphertxt[16] = {0};
	unsigned char decryptedtxt[16] = {0};

	dbgPrint("\r\ntesting AES 128-bit one block...\r\n");
	memPrint("key128 ", key128, 16);
	memPrint("plaintxt", plaintxt, 16);

    AES_encrypt_block( plaintxt, ciphertxt, key128 );
	memPrint("cipherxt", ciphertxt, 16);

    AES_decrypt_block( ciphertxt, decryptedtxt, key128 );
	memPrint("decrypted", decryptedtxt, 16);

    if ( !memcmp( ciphertxt, correctciphertxt, 16 ) ) {
	   dbgPrint("cipher successfully.\r\n");
    } else {
	   dbgPrint("<--------------------------------------------------cipher failed!\r\n");
    }

    if ( !memcmp( decryptedtxt, plaintxt, 16 ) ) {
	   dbgPrint("decryption successfully.\r\n");
    } else {
	   dbgPrint("<--------------------------------------------------decryption failed!\r\n");
    }

}


unsigned char KEY1[16]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
unsigned char IV1[16] = {0};
unsigned char ZeroIV[16] = {0};

unsigned char plaintxt10[10] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
unsigned char plaintxt16[16] =        { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
unsigned char plaintxt17[17] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
                                   ,0x00 };
unsigned char plaintxt32[32] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
                                   ,0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

unsigned char plaintxt33[33] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
                                   ,0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
                                   ,0x00};




unsigned char KEY2[16] = { 0x64, 0x5D, 0xFB, 0x2D, 0x8A, 0xB7, 0x1C, 0x88, 0x4C, 0xEE, 0xF5, 0x59, 0xAF, 0xC8, 0x82, 0x34 };
unsigned char IV2[16] ={ 0x8E, 0x31, 0x8D, 0x69, 0xFA, 0xDA, 0x4A, 0x20, 0xAA, 0xE6, 0x1B, 0xA1, 0xAF, 0xCC, 0x82, 0xFA };

unsigned char plaintxt70[71] = "The sun rose slowly, as if it wasn't sure it was worth all the effort.";
// for reference: the string in bytes
// the number of input bytes, which does not include the last char '\0' of the string.
// if user wants to, can set input length as 71
unsigned char correctciphertxt80[80] =
{ 0x83, 0x33, 0xE4, 0x9F, 0xF2, 0x5C, 0x9D, 0xED, 0x13, 0x34, 0x1A, 0xED, 0x3A, 0x93, 0x2A, 0x08
 ,0x80, 0xFA, 0xF3, 0x74, 0x4E, 0x55, 0x45, 0x10, 0xB4, 0x04, 0xDB, 0xB4, 0xCB, 0x49, 0xA7, 0x22
 ,0x1C, 0xE6, 0x2A, 0x7C, 0x30, 0x06, 0xDE, 0x46, 0xBC, 0x44, 0x51, 0xA6, 0xFA, 0xC6, 0xE2, 0xE9
 ,0xED, 0x64, 0x06, 0x55, 0xAA, 0x1A, 0xC1, 0x28, 0xB2, 0xFE, 0x3F, 0xD2, 0x88, 0x97, 0x29, 0x3D 
 ,0x14, 0xFE, 0x12, 0x8C, 0xB9, 0x7A, 0xA3, 0x6C, 0xFB, 0x04, 0x1B, 0x87, 0xD6, 0xE9, 0x98, 0xA1 };

unsigned char correctdecryptedtxt70[70] = 
{ 0x54, 0x68, 0x65, 0x20, 0x73, 0x75, 0x6E, 0x20, 0x72, 0x6F, 0x73, 0x65, 0x20, 0x73, 0x6C, 0x6F
 ,0x77, 0x6C, 0x79, 0x2C, 0x20, 0x61, 0x73, 0x20, 0x69, 0x66, 0x20, 0x69, 0x74, 0x20, 0x77, 0x61
 ,0x73, 0x6E, 0x27, 0x74, 0x20, 0x73, 0x75, 0x72, 0x65, 0x20, 0x69, 0x74, 0x20, 0x77, 0x61, 0x73
 ,0x20, 0x77, 0x6F, 0x72, 0x74, 0x68, 0x20, 0x61, 0x6C, 0x6C, 0x20, 0x74, 0x68, 0x65, 0x20, 0x65
 ,0x66, 0x66, 0x6F, 0x72, 0x74, 0x2E };






//Mode: AES/CBC/PKCS5Padding
int test_AES(unsigned char* plaintxt, 
				 unsigned int  len,
				 unsigned char* key128,
				 unsigned char* IV,
				 unsigned char* correctciphertxt,
				 unsigned int  correctcipherlen
				 )
{
   int outLen;
   int succeed = 0;				  

   // The key and plaintext are given in the program itself.
   unsigned char ciphertxt[80] = {0};
   unsigned char decryptedtxt[80] = {0};

   dbgPrint("\r\ntesting AES 128-bit CBC mode...\r\n");
   memPrint("key128  ", key128, 16);
   memPrint("IV  ", IV, 16);
   memPrint("plaintxt", plaintxt, len);
   strPrint("plaintxt", plaintxt, len);

   //
   // encrypt the string, and return the length of ciphered text
   //
   outLen = encrypt( key128, IV, plaintxt, len, ciphertxt);

   if ( correctciphertxt ) {
   if ( (outLen == correctcipherlen) && !memcmp( ciphertxt, correctciphertxt, outLen ) ) {
	   dbgPrint("cipher successfully.\r\n");
   } else {
	   dbgPrint("<--------------------------------------------------cipher failed!\r\n");
       memPrint("ciphertxt", ciphertxt, outLen );
	   return 0;
   }
   }

   memPrint("ciphertxt", ciphertxt, outLen );

   //
   // decrypt the ciphered text, and return the length of decrypted data
   //
   outLen = decrypt( key128, IV, ciphertxt, outLen, decryptedtxt);


   // check if the decrypted data is the same as the original
   if ( (outLen == len) && !memcmp( decryptedtxt, plaintxt, outLen ) ) {
       succeed = 1; // decryption successfully   	
	   dbgPrint("decryption successfully.\r\n");
   } else {
	   dbgPrint("<--------------------------------------------------decryption failed!\r\n");
       memPrint("decryptedtxt", decryptedtxt, outLen );
	   return 0; // fail
   }

   memPrint("decryptedtxt", decryptedtxt, outLen );
   strPrint("decryptedtxt", decryptedtxt, outLen );
   return succeed;
}


/*

int test_AES_Flash()
{
#ifdef __STM32F10x_H

   unsigned int AddressIn = 	 0x08008000 ;
   unsigned int AddressOut = 	 AddressIn; //0x08008000 + 0x400 ;
   unsigned int AddressOut2 = 	 AddressIn; //0x08008000 + (0x400) *2 ;

   //test_AES( plaintxt70, 70, KEY2, IV2, correctciphertxt80, 80 );

   int len = 70;
   unsigned char * key128 = KEY2;
   unsigned char * IV = IV2;
   int outLen;
   int succeed = 0;			
   
   unsigned char * ciphertxt = (unsigned char*) AddressOut;	  
   unsigned char * decryptedtxt = (unsigned char*) AddressOut2;	  
   int correctcipherlen = 80;

   writeFlash( plaintxt70, AddressIn, 70 );

   //
   // encrypt the string, and return the length of ciphered text
   //
   outLen = encrypt( key128, IV, (unsigned char*)AddressIn, len, (unsigned char*)AddressOut);

   if ( (outLen == correctcipherlen) && !memcmp( ciphertxt, correctciphertxt80, outLen ) ) {
	   dbgPrint("cipher successfully.\r\n");
   } else {
	   dbgPrint("<--------------------------------------------------cipher failed!\r\n");
       memPrint("ciphertxt", ciphertxt, outLen );
	   return 0;
   }

   //
   // decrypt the ciphered text, and return the length of decrypted data
   //
   outLen = decrypt( key128, IV, (unsigned char*)AddressOut, outLen, (unsigned char*)AddressOut2);

   // check if the decrypted data is the same as the original
   if ( (outLen == len) && !memcmp( decryptedtxt, plaintxt70, outLen ) ) {
       succeed = 1; // decryption successfully   	
	   dbgPrint("decryption successfully.\r\n");
   } else {
	   dbgPrint("<--------------------------------------------------decryption failed!\r\n");
	   return 0; // fail
   }

   succeed = succeed; // for debug

   return succeed;

#else

   return 1;

#endif

}

*/



int test_MAC(unsigned char* plaintxt, 
				 unsigned int  len,
				 unsigned char* key128,
				 unsigned char* correctMACtxt,
				 unsigned int  correctMAClen
				 )
{
	int outLen =16;
	int succeed = 1;

	unsigned char outMAC[16] = {0};

	dbgPrint("\r\ntesting MAC code...\r\n");
    memPrint("key128  ", key128, 16);
    memPrint("plaintxt", plaintxt, len);
    strPrint("plaintxt", plaintxt, len);


    //
    // compute the MAC for plaintxt
    //
	GenerateMAC(key128, plaintxt, len, outMAC);

   if ( correctMACtxt ) {
	   if ( !memcmp( outMAC, correctMACtxt, correctMAClen ) ) {
		   dbgPrint("get MAC successfully.\r\n");
	   } else {
		   dbgPrint("<--------------------------------------------------MAC failed!\r\n");
		   succeed = 0;
       }
   }

   memPrint("MAC", outMAC, outLen );
   return succeed;
}




int test_AES_MAC(unsigned char* plaintxt, 
				 unsigned int  len,
				 unsigned char* key128,
				 unsigned char* IV,
				 unsigned char* correctciphertxt,
				 unsigned int  correctcipherlen
				 )
{
   int outLen;
   int succeed = 0;				  

	// The key and plaintext are given in the program itself.
   unsigned char ciphertxt[96] = {0};
   unsigned char decryptedtxt[96] = {0};

   dbgPrint("\r\ntesting AES with MAC code...\r\n");
   memPrint("key128  ", key128, 16);
   memPrint("IV  ", IV, 16);
   memPrint("plaintxt", plaintxt, len);
   strPrint("plaintxt", plaintxt, len);

   //
   // encrypt the string, and return the length of ciphered text
   //
   outLen = AuthEncrypt( key128, IV, plaintxt, len, ciphertxt);

   if ( correctciphertxt ) {
   if ( (outLen == correctcipherlen) && !memcmp( ciphertxt, correctciphertxt, outLen ) ) {
	   dbgPrint("cipher successfully.\r\n");
   } else {
	   dbgPrint("<--------------------------------------------------cipher failed!\r\n");
       memPrint("ciphertxt", ciphertxt, outLen );
	   return 0;
   }
   }

   memPrint("ciphertxt", ciphertxt, outLen );

   //
   // decrypt the ciphered text, and return the length of decrypted data
   //
   outLen = CheckDecrypt( key128, IV, ciphertxt, outLen, decryptedtxt);


   // check if the decrypted data is the same as the original
   if ( (outLen == len) && !memcmp( decryptedtxt, plaintxt, outLen ) ) {
       succeed = 1; // decryption successfully   	
	   dbgPrint("decryption successfully.\r\n");
   } else {
	   dbgPrint("<--------------------------------------------------decryption failed!\r\n");
       memPrint("decryptedtxt", decryptedtxt, outLen );
	   return 0; // fail
   }

   memPrint("decryptedtxt", decryptedtxt, outLen );
   strPrint("decryptedtxt", decryptedtxt, outLen );
   return succeed;
}








int test_Pack(unsigned char * key, unsigned int SenderCounter)

{
   // The plaintext is given in the program itself.
   unsigned char plaintxt70[128] = "The sun rose slowly, as if it wasn't sure it was worth all the effort.";
   int dataLen = 70;
   int outLen;

   dbgPrint("\r\ntesting previous Packing with AES and MAC...\r\n");
   memPrint("key128  ", key, 16);
   memPrint("plaintxt", plaintxt70, dataLen);
   strPrint("plaintxt", plaintxt70,dataLen);
   memPrint("SenderCounter", (unsigned char*)&SenderCounter, 4 );
   

   outLen = pack( key, 
	            plaintxt70, dataLen, 
				plaintxt70, 
				SenderCounter);
   
   memPrint("packedtxt", plaintxt70, outLen );

   
   dataLen = unpack( key, 
   	            plaintxt70, outLen, 
   	            plaintxt70, 
   	            SenderCounter);
   if ( dataLen == -1 ) {
	   dbgPrint("unpack failed!\r\n");   	
	   return 0;
   }
   
   memPrint("unpackedtxt", plaintxt70, dataLen );
   strPrint("unpackedtxt", plaintxt70, dataLen );
   return 1;
}



///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////
//
//  block by block style
//
///////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////



// Tested functions:  GenerateMAC_step(), CheckMAC_step()
int test_new_MAC(void )
{
	int status;
	// length = 70 + 1 ending char + 16
	unsigned char plaintxt70[87] = "The sun rose slowly, as if it wasn't sure it was worth all the effort.";
	unsigned char key128[16] = { 0x64, 0x5D, 0xFB, 0x2D, 0x8A, 0xB7, 0x1C, 0x88, 0x4C, 0xEE, 0xF5, 0x59, 0xAF, 0xC8, 0x82, 0x34 };
	unsigned char *inTempBuf;
	unsigned int inDataTotalLen = 70;
	unsigned char *outTempBuf;
	unsigned int outTempBufLen = 16;
	unsigned int inDataOffset;
	

	dbgPrint("\r\ntesting new MAC generation and check...\r\n");
    memPrint("key128  ", key128, 16);
    memPrint("plaintxt", plaintxt70, inDataTotalLen);
    strPrint("plaintxt", plaintxt70, inDataTotalLen);


    //
    // compute the MAC for plaintxt
    //
   outTempBuf = plaintxt70 + inDataTotalLen;
   for ( inDataOffset = 0; inDataOffset < inDataTotalLen ; ) {
   	
   	     //  read inTempBuf
   	     inTempBuf = plaintxt70 + inDataOffset;

         // block by block		 
		 GenerateMAC_step( key128, inTempBuf, inDataTotalLen, outTempBuf, &outTempBufLen, &inDataOffset);
   }

    memPrint("plaintxt with MAC", plaintxt70, inDataTotalLen + outTempBufLen);

	//
	// double-check the MAC
	// 
	GenerateMAC( key128, plaintxt70, inDataTotalLen, plaintxt70 + inDataTotalLen );
	memPrint("double check MAC", plaintxt70 + inDataTotalLen, outTempBufLen);


   //
   // check the MAC for [ plaintxt || MAC ]
   //
   inDataTotalLen += outTempBufLen;
   for ( inDataOffset = 0; inDataOffset < inDataTotalLen ; ) {

	    // read inTempBuf
	    inTempBuf = plaintxt70 + inDataOffset;

		// block by block
		status = CheckMAC_step( key128, inTempBuf, inDataTotalLen, &inDataOffset);
		if ( 0 != status )
			break;
		// Otherwise, continue
   }

   if ( 1 == status ) {
		   dbgPrint("check MAC successfully.\r\n");
   } else {
		   dbgPrint("<--------------------------------------------------check MAC failed!\r\n");
		   status = 0;
   }

   return status;
}




// Tested functions:  AES_cbc_enc_step(), AES_cbc_dec_step()
int test_new_AES(void )
{
	// length = 70 + 1 ending char + 32
	unsigned char plaintxt70[103] = "The sun rose slowly, as if it wasn't sure it was worth all the effort.";
	unsigned char key128[16] = { 0x64, 0x5D, 0xFB, 0x2D, 0x8A, 0xB7, 0x1C, 0x88, 0x4C, 0xEE, 0xF5, 0x59, 0xAF, 0xC8, 0x82, 0x34 };
	unsigned char IV[16] ={ 0x8E, 0x31, 0x8D, 0x69, 0xFA, 0xDA, 0x4A, 0x20, 0xAA, 0xE6, 0x1B, 0xA1, 0xAF, 0xCC, 0x82, 0xFA };

	unsigned int inDataTotalLen = 70;
	unsigned char *inTempBuf;
	unsigned char *outTempBuf;
	unsigned int outTempBufLen;
	unsigned int inDataOffset;
	unsigned int outDataTotalLen;

	int status=0;

	dbgPrint("\r\ntesting new AES_CBC_encrypt block by block...\r\n");
    memPrint("key128  ", key128, 16);
	memPrint("IV      ", IV, 16);
    memPrint("plaintxt", plaintxt70, inDataTotalLen);
    strPrint("plaintxt", plaintxt70, inDataTotalLen);


    //
    // encrypt plaintxt block by block
    //
	outDataTotalLen = 0;
   for ( inDataOffset = 0; inDataOffset < inDataTotalLen; ) {
   	
   	     //  read inTempBuf
   	     inTempBuf = plaintxt70 + inDataOffset;

		 outTempBuf = inTempBuf;

         // block by block		 
		 status = AES_cbc_enc_step( inTempBuf, outTempBuf, inDataTotalLen, &outTempBufLen, &inDataOffset, key128, IV );
		 memPrint("cipherblock", outTempBuf, outTempBufLen);
		 outDataTotalLen += outTempBufLen;

		 if ( 0 !=status ) break;
   }

    memPrint("ciphertxt", plaintxt70, outDataTotalLen);

   if ( 1 == status ) {
		   dbgPrint("new AES_CBC_enc successfully.\r\n\r\n");
   } else {
		   dbgPrint("<-------------------------------------------------- new AES_CBC_enc failed!\r\n");
		   status = 0;
		   return status;
   }


   //
   // decrypt ciphertxt block by block
   //
   inDataTotalLen  = outDataTotalLen;
   outDataTotalLen = 0;
   for ( inDataOffset = 0; inDataOffset < inDataTotalLen; ) {
   	
   	     //  read inTempBuf
   	     inTempBuf = plaintxt70 + inDataOffset;

		 outTempBuf = inTempBuf;

         // block by block		 
		 status = AES_cbc_dec_step( inTempBuf, outTempBuf, inDataTotalLen, &outTempBufLen, &inDataOffset, key128, IV );
		 memPrint("decryptedblock", outTempBuf, outTempBufLen);
		 strPrint("decryptedblock", outTempBuf, outTempBufLen);
		 outDataTotalLen += outTempBufLen;

		 if ( 0 !=status ) break;
   }

    memPrint("decryptedtxt", plaintxt70, outDataTotalLen);
    strPrint("decryptedtxt", plaintxt70, outDataTotalLen);
   if ( 1 == status ) {
		   dbgPrint("new AES_CBC_dec successfully.\r\n");
   } else {
		   dbgPrint("<-------------------------------------------------- new AES_CBC_dec failed!\r\n");
		   status = 0;
		   return status;
   }

   return status;
}






// Tested functions: HMAC_step()
int test_new_Pack_MAC_step( void )
{
	int status;

	unsigned char key128[16] = { 0x64, 0x5D, 0xFB, 0x2D, 0x8A, 0xB7, 0x1C, 0x88, 0x4C, 0xEE, 0xF5, 0x59, 0xAF, 0xC8, 0x82, 0x34 };

	unsigned int SenderCounter = 0x0000;
	int inDataTotalLen = 70;
	unsigned char plaintxt70[87] = "The sun rose slowly, as if it wasn't sure it was worth all the effort.";

	
	unsigned char *inBlock;
	unsigned char *outBuf;
	
	unsigned int outBufLen = 16;
	unsigned int offset;

	unsigned char outMAC[16];
	unsigned char XXX[87] ={0};
	
	dbgPrint("\r\ntesting new Pack MAC ...\r\n");
    memPrint("key128  ", key128, 16);
    memPrint("plaintxt", plaintxt70, inDataTotalLen);
    strPrint("plaintxt", plaintxt70, inDataTotalLen);
	memPrint("SenderCounter", (unsigned char*)&SenderCounter, 4 );


    //
    // compute the MAC for plaintxt
    //
   inDataTotalLen = 70;
   outBuf = plaintxt70 + inDataTotalLen;
   for ( offset = 0; ; ) {
   	
   	     //  read inTempBuf
   	     inBlock = plaintxt70 + offset;

         // block by block		 
		 status = HMAC_step( key128, 
		                     SenderCounter, inDataTotalLen, 
		                     inBlock, outBuf, &outBufLen,
		                     &offset );
		 if ( 0 != status )
		 	break;
		 // Otherwise, continue
   }

   memPrint("plaintxt with MAC", plaintxt70, inDataTotalLen + outBufLen);

   memcpy( XXX,   (unsigned char*)&SenderCounter, 4 );
   memcpy( XXX+4, (unsigned char*)&inDataTotalLen, 4 );
   memcpy( XXX+8,  plaintxt70, inDataTotalLen );
   GenerateMAC( key128, XXX, 8 + inDataTotalLen , outMAC);

   memPrint("correct MAC", outMAC, MAC_LEN );


   if ( 1 == status ) {
		   dbgPrint("Pack MAC successfully.\r\n");
   } else {
		   dbgPrint("<--------------------------------------------------Pack MAC failed!\r\n");
		   status = 0;
   }

   return status;
}




// Tested functions: AES_ENC_MAC_step()
int test_new_Pack_AES_Enc_with_MAC( void )
{
	int status;
	unsigned char key128[16] = { 0x64, 0x5D, 0xFB, 0x2D, 0x8A, 0xB7, 0x1C, 0x88, 0x4C, 0xEE, 0xF5, 0x59, 0xAF, 0xC8, 0x82, 0x34 };
	unsigned char plaintxt70[128] = "The sun rose slowly, as if it wasn't sure it was worth all the effort.";
	unsigned int dataLen = 70;

	unsigned char *inBlock;
	unsigned char *outBlock;

	unsigned char *MAC;
	
	unsigned int offset;
	unsigned int outBufLen;
	unsigned int outLen;

	unsigned int SenderCounter = 0x0000;

	dbgPrint("\r\ntesting new Pack_AES_Enc_with_MAC ...\r\n");
    memPrint("key128  ", key128, 16);
    memPrint("plaintxt", plaintxt70, dataLen);
    strPrint("plaintxt", plaintxt70, dataLen);

    // append MAC
    GenerateMAC( key128, plaintxt70, 70, plaintxt70 + 70 );
	memPrint("plaintxt with MAC", plaintxt70, 70+ MAC_LEN );
	MAC = plaintxt70 + 70;


    //
    // encrypt plaintxt with MAC
    //
   dataLen = 70;
   outLen = 0;
   for ( offset = 0; ; ) {
   	
   	     //  read inBlock
   	     inBlock = plaintxt70 + offset;
		 outBlock = inBlock;

         // block by block		 
		 status = AES_ENC_MAC_step( key128, 
		           SenderCounter, dataLen, inBlock, MAC, MAC_LEN, outBlock, &outBufLen,
		           &offset);

		 outLen += outBufLen;
		 
		 if ( 0 != status )
		 	break;
		 // Otherwise, continue
   }

   memPrint("ciphertxt", plaintxt70, outLen);

   if ( 1 == status ) {
		   dbgPrint("new Pack_AES_Enc_with_MAC successfully.\r\n");
   } else {
		   dbgPrint("<--------------------------------------------------new Pack_AES_Enc_with_MAC failed!\r\n");
		   status = 0;
   }

   return status;
}




// Tested functions: pack_step(), unpack_step()
int test_new_Pack(unsigned char * key,  unsigned int SenderCounter)
{
	int status;
	unsigned char P70[128] = "The sun rose slowly, as if it wasn't sure it was worth all the effort.";
	unsigned int dataLen = 70;

	unsigned char *inBlock;
	unsigned char *outBlock;

	unsigned int offset;
	unsigned int outBufLen;
	unsigned int outLen;

    unsigned char keyType = 0x80;

	dbgPrint("\r\ntesting new Pack...\r\n");
    memPrint("key128  ", key, 16);
    memPrint("plaintxt", P70, dataLen);
    strPrint("plaintxt", P70, dataLen);

   memPrint("SenderCounter", (unsigned char*)&SenderCounter, 4 );


    //
    // pack data in block-by-block style 
    //
   dataLen = 70;
   outLen = 0;
   for ( offset = 0; ; ) {
   	
   	     //  read inBlock
   	     inBlock = P70 + offset;
		 outBlock = P70 + outLen;

         // block by block		 
		 status = pack_step( keyType, key, inBlock, dataLen, outBlock, &outBufLen,
		                   &offset, SenderCounter);

		 outLen += outBufLen;
		 
		 if ( 0 != status )
		 	break;
		 // Otherwise, continue
   }

   memPrint("packedtxt", P70, outLen);

   if ( 1 == status ) {
		   dbgPrint("new Pack successfully.\r\n");
   } else {
		   dbgPrint("<--------------------------------------------------new Pack failed!\r\n");
		   status = 0;
   }


    //
    // unpack data in block-by-block style 
    //
    dataLen = outLen;
	outLen = 0;
   for ( offset = 0; ; ) {
   	
   	     //  read inBlock
   	     inBlock = P70 + offset;
		 outBlock = P70 + outLen;

         // block by block		 
		 status = unpack_step( keyType, key, inBlock, dataLen, outBlock, &outBufLen,
		                   &offset, SenderCounter);

		 outLen += outBufLen;
		 
		 if ( 0 != status )
		 	break;
		 // Otherwise, continue
   }

   memPrint("unpackedtxt", P70, outLen);
   strPrint("unpackedtxt", P70, outLen);   

   if ( 1 == status ) {
		   dbgPrint("new unPack successfully.\r\n");
   } else {
		   dbgPrint("<--------------------------------------------------new unPack failed!\r\n");
		   status = 0;
   }

   return status;
}




////////////////////////////////////////////////////////////////////////////////////////////////// testing
//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////


int test_MCU_workflow_pack(unsigned char  keyType, 
					  unsigned char *key4NMS,
					  unsigned char *key4DCU,
					  unsigned char *data4NMS,
					  unsigned int   data4NMS_LEN,
					  unsigned char *data4DCU,
					  unsigned int   data4DCU_LEN,
					  unsigned int   MCUcounter,
					  unsigned int   MCUcounteroffset,
					  unsigned char *outdata4NMS,
					  unsigned int  *outdata4NMS_LEN,
					  unsigned char *outdata4DCU,
					  unsigned int  *outdata4DCU_LEN)
{
	int status;
	unsigned char *inBlock;
	unsigned char *outBlock;
	unsigned int offset;
	unsigned int outBufLen;
	unsigned int outLen;

   dbgPrint("\r\ntest MCU work flow, pack.\r\n");
   dbgPrint("SenderCounter=%d\n", MCUcounter);
   memPrint("SenderCounter in mem=", (unsigned char*) &MCUcounter, 4 );

   *outdata4NMS_LEN = data4NMS_LEN;
   status = MCU_BeginPack(keyType, MCUcounteroffset, outdata4NMS_LEN);
   if ( status != 1 ) 
	   return 0;  // failure


    //
    // pack data in block-by-block style 
    //
   outLen = 0;
   for ( offset = 0; ; ) {
   	
   	     //  read inBlock
   	     inBlock = data4DCU + offset;
		 outBlock = outdata4DCU + outLen;

         // block by block		 
		 status = packData( keyType, key4DCU, inBlock, data4DCU_LEN, outBlock, &outBufLen,
		                   &offset);

		 outLen += outBufLen;
		 
		 if ( 0 != status )
		 	break;
		 // Otherwise, continue
   }

   if ( 1 == status ) {
		   //dbgPrint("new Pack successfully.\r\n");
   } else {
		   //dbgPrint("<--------------------------------------------------new Pack failed!\r\n");
		   return 0; 
   }

   *outdata4DCU_LEN = outLen;
   memPrint("packedtxt4DCU", outdata4DCU, *outdata4DCU_LEN);

   MCU_MiddlePack(keyType, MCUcounter);

    // Pack_AllData() for NMS, similarly...
   outLen = 0;
   for ( offset = 0; ; ) {
   	
   	     //  read inBlock
   	     inBlock = data4NMS + offset;
		 outBlock = outdata4NMS + outLen;

         // block by block		 
		 status = packData( keyType, key4NMS, inBlock, data4NMS_LEN, outBlock, &outBufLen,
		                   &offset);

		 outLen += outBufLen;
		 
		 if ( 0 != status )
		 	break;
		 // Otherwise, continue
   }

   if ( 1 == status ) {
		   //dbgPrint("new Pack successfully.\r\n");
   } else {
		   //dbgPrint("<--------------------------------------------------new Pack failed!\r\n");
		   return 0; 
   }

   *outdata4NMS_LEN = outLen;
   memPrint("packedtxt4NMS", outdata4NMS, *outdata4NMS_LEN);

   MCU_EndPack( keyType );

   return 1;
}



int test_MCU_workflow_unpack(unsigned char  keyType, 
					  unsigned char *key4NMS,
					  unsigned char *key4DCU,
					  unsigned char *data4NMS,
					  unsigned int   data4NMS_LEN,
					  unsigned char *data4DCU,
					  unsigned int   data4DCU_LEN,
					  unsigned int   storedCounter,
					  unsigned int   localTime,
					  unsigned char *outdata4NMS,
					  unsigned int  *outdata4NMS_LEN,
					  unsigned char *outdata4DCU,
					  unsigned int  *outdata4DCU_LEN)
{
	int status;
	unsigned char *inBlock;
	unsigned char *outBlock;
	unsigned int offset;
	unsigned int outBufLen;
	unsigned int outLen;

    unsigned int recvCounter; 

   dbgPrint("\r\ntest MCU work flow, unpack.\r\n");
   dbgPrint("SenderCounter=%d\n", storedCounter);
   memPrint("SenderCounter in mem=", (unsigned char*) &storedCounter, 4 );

   memPrint("ciphertxt4DCU", data4DCU, data4DCU_LEN);
   memPrint("ciphertxt4NMS", data4NMS, data4NMS_LEN);

    MCU_BeginUnpack(keyType);


    //
    // unpack data in block-by-block style 
    //
	outLen = 0;
   for ( offset = 0; ; ) {
   	
   	     //  read inBlock
   	     inBlock = data4DCU + offset;
		 outBlock = outdata4DCU + outLen;

         // block by block		 
		 status = unpackData( keyType, key4DCU, inBlock, data4DCU_LEN, outBlock, &outBufLen,
		                   &offset);

		 outLen += outBufLen;
		 
		 if ( 0 != status )
		 	break;
		 // Otherwise, continue
   }

   if ( 1 == status ) {
		   //dbgPrint("new unPack successfully.\r\n");
   } else {
		   //dbgPrint("<--------------------------------------------------new unPack failed!\r\n");
		   return 0; 
   }

   *outdata4DCU_LEN = outLen;
   memPrint("unpackedtxt4DCU", outdata4DCU, *outdata4DCU_LEN);
   strPrint("unpackedtxt4DCU", outdata4DCU, *outdata4DCU_LEN);   

   recvCounter   =  0x04030201;   // from DCU message

   MCU_MiddleUnpack(keyType,recvCounter);

   //
   //
   // Unpack_AllData() for NMS, similarly...
   //
   outLen = 0;
   for ( offset = 0; ; ) {
   	
   	     //  read inBlock
   	     inBlock = data4NMS + offset;
		 outBlock = outdata4NMS + outLen;

         // block by block		 
		 status = unpackData( keyType, key4NMS, inBlock, data4NMS_LEN, outBlock, &outBufLen,
		                   &offset);

		 outLen += outBufLen;
		 
		 if ( 0 != status )
		 	break;
		 // Otherwise, continue
   }

   if ( 1 == status ) {
		   //dbgPrint("new unPack successfully.\r\n");
   } else {
		   //dbgPrint("<--------------------------------------------------new unPack failed!\r\n");
		   return 0; 
   }

   *outdata4NMS_LEN = outLen;
   memPrint("unpackedtxt4NMS", outdata4NMS, *outdata4NMS_LEN);
   strPrint("unpackedtxt4NMS", outdata4NMS, *outdata4NMS_LEN);   


   status = MCU_EndUnpack(keyType, storedCounter, recvCounter, localTime);
   if ( -1 == status ) {
        // report replay attack 
		return 0;
   }

   return status;
}




// Tested functions: pack_step(), unpack_step()
int test_MCU_workflow( void )
{
	int status;

unsigned char K4NMS[16] = { 0x64, 0x5D, 0xFB, 0x2D, 0x8A, 0xB7, 0x1C, 0x88, 0x4C, 0xEE, 0xF5, 0x59, 0xAF, 0xC8, 0x82, 0x34 };
unsigned char K4DCU[16] = { 0x64, 0x5D, 0xFB, 0x2D, 0x8A, 0xB7, 0x1C, 0x88, 0x4C, 0xEE, 0xF5, 0x59, 0xAF, 0xC8, 0x82, 0x34 };
unsigned char keyType = 0x99;    //keyType = 0x99; //0x99,0x11, 0x0;
unsigned char data4NMS[128] = "The sun rose slowly, as if it wasn't sure it was worth all the effort.";
unsigned char data4DCU[128] = "The sun rose slowly, as if it wasn't sure it was worth all the effort.";
unsigned int data4NMS_LEN=70;
unsigned int data4DCU_LEN=70;
unsigned int cipher4NMS_LEN;
unsigned int cipher4DCU_LEN;

unsigned int MCUcounter = 0x04030201; //4, 0x04030201;
unsigned int MCUcounteroffset = 4;
unsigned int storedCounter = 0x04030201; //4, 0x04030201;
unsigned int localTime = 2;


   status = test_MCU_workflow_pack( keyType, K4NMS,K4DCU, 
	                       data4NMS, data4NMS_LEN,
						   data4DCU, data4DCU_LEN,
						   MCUcounter, MCUcounteroffset,
						   data4NMS, &cipher4NMS_LEN,
						   data4DCU, &cipher4DCU_LEN);


   status = test_MCU_workflow_unpack(keyType, K4NMS,K4DCU, 
	                       data4NMS, cipher4NMS_LEN,
						   data4DCU, cipher4DCU_LEN,
						   storedCounter, localTime,
						   data4NMS, &data4NMS_LEN,
						   data4DCU, &data4DCU_LEN);


   return status;
}






int test_DCU_workflow_1(void)
{
	int status;

	unsigned char keyType;
	unsigned int receivedCounter;
	unsigned int storedCounter;
	unsigned int localTime;

   dbgPrint("\r\ntest DCU work flow, unpack->pack.\r\n");

   keyType = 0x99;

   DCU_BeginUnpack(keyType);


    //
    // TODO: Unpack_AllData() for DCU, in block-by-block style...
    //


   receivedCounter = 0; // from unpacked message

   if ( 1 /* DCU acts as a router */ ){
	   
	   
	   DCU_MiddleUnpack(keyType, receivedCounter);

       //
       // TODO: Pack_AllData() for End (NMS/MCU) node, similarly...
	   //
   }

    storedCounter = 0;  // coresponds to message sender
	localTime = 0;

	status = DCU_EndUnpack( keyType, storedCounter, receivedCounter, localTime );
    if ( -1 == status ) {
        // report replay attack 
		return 0;
    }

   return status;
}


int test_DCU_workflow_2(void)
{
	int status;
	unsigned char keyType;
	unsigned int storedCounter;

   dbgPrint("\r\ntest DCU work flow, originated pack.\r\n");

   status = 1;
   keyType = 0x99;
   storedCounter = 0;

   DCU_BeginPack(keyType);

    //
    // Pack_AllData() in block-by-block style 
    //

   DCU_MiddlePack(keyType, storedCounter);

    //
    // Pack_AllData() in block-by-block style 
    //

   DCU_EndPack( keyType );

   return status;
}









int main(int argc, char* const argv[])
{

  /*!< At this stage the microcontroller clock setting is already configured, 
       this is done through SystemInit() function which is called from startup
       file (startup_stm32f10x_xx.s) before to branch to application main.
       To reconfigure the default setting of SystemInit() function, refer to
       system_stm32f10x.c file
     */     

    int succeed = 1;

	if (0) {
    //test_CRC();
	}

	if (0) {
    //succeed = test_Flash();
    //succeed = test_AES_Flash();
	}


	if (0) {
    test_AES_Block();
	}

	if (0) {
    succeed = test_AES( plaintxt10, 10, KEY1, IV1, 0, 0);
    succeed = test_AES( plaintxt16, 16, KEY1, IV1, 0, 0);
    succeed = test_AES( plaintxt17, 17, KEY1, IV1, 0, 0 );
    succeed = test_AES( plaintxt32, 32, KEY1, IV1, 0, 0 );
    succeed = test_AES( plaintxt33, 33, KEY1, IV1, 0, 0 );
    succeed = test_AES( plaintxt70, 70, KEY2, IV2, correctciphertxt80, 80 );
	}

	if (0) {
    succeed = test_MAC( plaintxt10, 10, KEY1, 0, 0);
    succeed = test_MAC( plaintxt16, 16, KEY1, 0, 0);
    succeed = test_MAC( plaintxt17, 17, KEY1, 0, 0);
    succeed = test_MAC( plaintxt32, 32, KEY1, 0, 0);
    succeed = test_MAC( plaintxt33, 33, KEY1, 0, 0);
    succeed = test_MAC( plaintxt70, 70, KEY2, 0, 0);
	}

	///////////////////////////  NOT in USE start, because: MAC_LEN, hash changed
	if (0) {  
	succeed = test_new_MAC();
	//succeed = test_new_MAC();
	}

	if (0) {  
    succeed = test_new_AES();
	}

	if (0) {
    succeed = test_AES_MAC( plaintxt70, 70, KEY2, ZeroIV/*IV2*/, 0, 0 );
	}

    /////////////////////////// NOT in USE end


	if (0) {
	//succeed = test_new_Pack_MAC_step(); 
	//succeed = test_new_Pack_AES_Enc_with_MAC();

	// input: key, SenderCounter
	succeed = test_new_Pack( KEY2, 0x00000000);
	succeed = test_Pack(     KEY2, 0x00000000);
	}

    if (1) {
	succeed = test_MCU_workflow();
	succeed = test_DCU_workflow_1();
	succeed = test_DCU_workflow_2();
    }

	if (0) {
		// test hash
		unsigned char outBlock[16];
		memPrint("plaintxt70", plaintxt70,70);
		hash(plaintxt70, 70,outBlock);
		memPrint("hash", outBlock,16);
	}
	
	if (0) {
		// test MCU key update
		unsigned char outBlock[16];
		unsigned char *receivedBK;
		unsigned char R[16];
		unsigned char storedBK[16]={0};
		unsigned char storedFK[16]={0};
		unsigned char newSK[16];
		unsigned char newFK[16];

    
		hash(plaintxt70, 70,outBlock);

		receivedBK = outBlock;

		hash( receivedBK, AES_BLOCK_SIZE , storedBK );

	    getNewForwardKey( storedFK, newFK);  // or newFK = hash(storedFK)
        getNewSessionKey( newFK, receivedBK, R, newSK);

		dbgPrint("input\r\n");
		memPrint("receivedBK", receivedBK,16);
		memPrint("R", R,16);
		memPrint("storedBK", storedBK,16);
		memPrint("storedFK", storedFK,16);

		succeed = MCU_updateUK4NMS( receivedBK, R, storedBK, storedFK, newSK, 0);
		dbgPrint("output\r\n");
		memPrint("storedFK", storedFK,16);
		memPrint("newSK", newSK,16);
		dbgPrint("status=%d", succeed);
	}



	return succeed;
}


