#ifndef _HMAC_H_
#define _HMAC_H_

#include <emp-tool/emp-tool.h>

#include <stdint.h>
#include <stdio.h>
#include <ctype.h>

#include "sha-256.h"

using namespace emp;
using namespace std; 

typedef struct EMP_HMAC_Context {
EMP_SHA256_CONTEXT shaContext;

Integer k_opad[SHA256_Message_Block_Size];
// unsigned char k_opad[USHA_Max_Message_Block_Size];
                        /* outer padding - key XORd with opad */
 // int 
  Integer Computed;
  // int 
  Integer Corrupted;
  int hashSize;
  int blockSize;

} EMP_HMAC_Context;



static int ALL = 0;
static int Msg_Block = 1;
static int Msg_Block_Index = 2;
static int Msg_Intermediate_Hash = 4;
void printInteger(Integer intToPrint, int bitSize) {
  for (int i = bitSize -1; i >= 0; i--) {
    cout << intToPrint[i].reveal();
  }
  return;
}

void printIntegerArray(Integer* intToPrint, int arraySize, int bitSize) {
  for(int i = 0; i < arraySize; i++) {
    printInteger(intToPrint[i], bitSize);
    cout << ", ";
  }
  cout << endl;
  return;
}
void printContext(EMP_HMAC_Context *context, int flag, string debugMsg) {
  cout << debugMsg << endl;
  EMP_SHA256_CONTEXT shaContext = context->shaContext;
  if (flag == ALL || flag == Msg_Intermediate_Hash) {
    cout << "Interemdiate Hash " << endl;
    printIntegerArray(shaContext.Intermediate_Hash, INTERMEDIATE_HASH_LEN, 32);
  }
  if (flag == ALL) {
    cout << "Length high " << endl;
    printInteger(shaContext.Length_High, LENGTH_BITS);
    cout << endl;
  }
  if (flag == ALL) {
    cout << "Length low " << endl;
    printInteger(shaContext.Length_Low, LENGTH_BITS);
    cout << endl;
  }  
  if (flag == ALL || flag == Msg_Block_Index) { 
    cout << "Message block index " << endl;
    printInteger(shaContext.Message_Block_Index, MESSAGE_BLOCK_INDEX_BITS);
    cout << endl;
  }
  if (flag == ALL || flag == Msg_Block) {
    cout << "Message block contents " << endl;
    printIntegerArray(shaContext.Message_Block, SHA256_Message_Block_Size, MESSAGE_BLOCK_BITS);
  }
}

// void printContext(EMP_SHA256_CONTEXT *context, int flag, string debugMsg) {
//   cout << debugMsg << endl;
//   if (flag == ALL || flag == Msg_Intermediate_Hash) {
//     cout << "Interemdiate Hash " << endl;
//     printIntegerArray(context->Intermediate_Hash, INTERMEDIATE_HASH_LEN, 32);
//   }
//   if (flag == ALL) {
//     cout << "Length high " << endl;
//     printInteger(context->Length_High, LENGTH_BITS);
//     cout << endl;
//   }
//   if (flag == ALL) {
//     cout << "Length low " << endl;
//     printInteger(context->Length_Low, LENGTH_BITS);
//     cout << endl;
//   }  
//   if (flag == ALL || flag == Msg_Block_Index) { 
//     cout << "Message block index " << endl;
//     printInteger(context->Message_Block_Index, MESSAGE_BLOCK_INDEX_BITS);
//     cout << endl;
//   }
//   if (flag == ALL || flag == Msg_Block) {
//     cout << "Message block contents " << endl;
//     printIntegerArray(context->Message_Block, SHA256_Message_Block_Size, MESSAGE_BLOCK_BITS);
//   }
// }


Integer HMAC_Reset(EMP_HMAC_Context *context, Integer* key, int key_len)
{
  /* inner padding - key XORd with ipad */
  Integer k_ipad[SHA256_Message_Block_Size];
  initIntegerArray(k_ipad, SHA256_Message_Block_Size, BYTE_BITS);
  /* temporary buffer when keylen > blocksize */
  Integer tempKey[SHA256HashSize];
  initIntegerArray(tempKey, SHA256HashSize, BYTE_BITS);

  initIntegerArray(context->k_opad, SHA256_Message_Block_Size, BYTE_BITS);
  // if (!context) return shaNull;
  context->Computed = Integer(INT_BITS, 0, PUBLIC);
  context->Corrupted = Integer(INT_BITS, shaSuccess, PUBLIC);


  EMP_SHA256_CONTEXT shaContext;
  SHA256_Reset(&shaContext);

  /*
   * If key is longer than the hash blocksize,
   * reset it to key = HASH(key).
   */
  if (key_len > SHA256_Message_Block_Size) {
    SHA256_Input(&shaContext, key, key_len);
    SHA256_Result(&shaContext, tempKey);
    // if (err != shaSuccess) return err;

    key = tempKey;
    key_len = SHA256HashSize;
  }

  context->shaContext = shaContext;
  int i;
  for (i = 0; i < key_len; i++) {
    k_ipad[i] = key[i] ^ Integer(BYTE_BITS, 0x36, PUBLIC);
    context->k_opad[i] = key[i] ^ Integer(BYTE_BITS, 0x5c, PUBLIC);
  }
  /* remaining pad bytes are '\0' XOR'd with ipad and opad values */
  for ( ; i < SHA256_Message_Block_Size; i++) {
    k_ipad[i] = Integer(BYTE_BITS, 0x36, PUBLIC);
    context->k_opad[i] = Integer(BYTE_BITS, 0x5c, PUBLIC);
  }

  /* perform inner hash */
  /* init context for 1st pass */
  // ret = SHA256Reset((SHA256Context*)&context->shaContext)
  SHA256_Reset(&context->shaContext);
  SHA256_Input(&context->shaContext, k_ipad, SHA256_Message_Block_Size);
  return context->Corrupted = Integer(INT_BITS, shaSuccess, PUBLIC);
}



Integer HMAC_Input(EMP_HMAC_Context *context, Integer* text, int text_len)
{
  // if (!context) return shaNull;
  // if (context->Corrupted) return context->Corrupted;
  // if (context->Computed) return context->Corrupted = shaStateError;
  /* then text of datagram */
  return context->Corrupted =
    SHA256_Input(&context->shaContext, text, text_len);
}

Integer HMAC_Result(EMP_HMAC_Context *context, Integer* digest)
{
  // if (!context) return shaNull;
  // if (context->Corrupted) return context->Corrupted;
  // if (context->Computed) return context->Corrupted = shaStateError;

  /* finish up 1st pass */
  /* (Use digest here as a temporary buffer.) */
  // Integer ret =
  SHA256_Result(&context->shaContext, digest);
  /* perform outer SHA */
  /* init context for 2nd pass */
  SHA256_Reset(&context->shaContext);


  /* start with outer pad */
  SHA256_Input(&context->shaContext, context->k_opad, SHA256_Message_Block_Size);

  /* then results of 1st hash */
  SHA256_Input(&context->shaContext, digest, SHA256HashSize);
  /* finish up 2nd pass */
  SHA256_Result(&context->shaContext, digest);

  context->Computed = Integer(INT_BITS, 1, PUBLIC);
  return context->Corrupted = context->Computed;
}


#endif /* _HMAC_H_ */