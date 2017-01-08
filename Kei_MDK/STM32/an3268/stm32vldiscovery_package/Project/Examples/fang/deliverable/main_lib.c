/* created by: fanghui  on 10 Jan. 2011 */

#include <stdio.h>
#include <stdlib.h>

//#include "stm32f10x.h"
#include "siesapi.h"



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

	
    if (1) {
	succeed = test_MCU_workflow();
	succeed = test_DCU_workflow_1();
	succeed = test_DCU_workflow_2();
    }


	return succeed;
}





