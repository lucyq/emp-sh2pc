#include <emp-tool/emp-tool.h>
#include "emp-tool/utils/hash.h"
#include "emp-sh2pc/emp-sh2pc.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <ctype.h>

#include "hmac.h"

using namespace emp;
using namespace std; 

enum {
  SN_LENGTH = 12, CID_LENGTH = 4, DATA_LENGTH = 16, // data = sn + cid
  KEY_LENGTH = 32, RANDOM_LENGTH = 96, RPRIME_LENGTH = 32, TOKEN_LENGTH = 1
};

/* * * * * * * * * * * * 
 *  D E B U G G I N G  *
 * * * * * * * * * * * */
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

void printarray(char* array, int ARRAY_LENGTH) {
    for (int i = 0; i <ARRAY_LENGTH; i ++) {
      for (int j = 0; j < 8; j++) {
        printf("%d", !!((array[i] << j) & 0x80));
      }
      printf(", ");
    }
  cout << endl;
}

static int ALL = 0;
static int Msg_Block = 1;
static int Msg_Block_Index = 2;
static int Msg_Intermediate_Hash = 4;

void printContext(EMP_SHA256_CONTEXT *context, int flag, string debugMsg) {
  cout << debugMsg << endl;
  if (flag == ALL || flag == Msg_Intermediate_Hash) {
    cout << "Interemdiate Hash " << endl;
    printIntegerArray(context->Intermediate_Hash, INTERMEDIATE_HASH_LEN, 32);
  }
  if (flag == ALL) {
    cout << "Length high " << endl;
    printInteger(context->Length_High, LENGTH_BITS);
    cout << endl;
  }
  if (flag == ALL) {
    cout << "Length low " << endl;
    printInteger(context->Length_Low, LENGTH_BITS);
    cout << endl;
  }  
  if (flag == ALL || flag == Msg_Block_Index) { 
    cout << "Message block index " << endl;
    printInteger(context->Message_Block_Index, MESSAGE_BLOCK_INDEX_BITS);
    cout << endl;
  }
  if (flag == ALL || flag == Msg_Block) {
    cout << "Message block contents " << endl;
    printIntegerArray(context->Message_Block, SHA256_Message_Block_Size, MESSAGE_BLOCK_BITS);
  }
}

/* * * * * * * * * *
 *  T E S T I N G  *
 * * * * * * * * * */
void printHash(Integer* Message_Digest) {
  cout << "Printing output hash: " << endl;
  for (int i =0; i < SHA256HashSize; i++) {
    for (int j =7; j >= 0; j--) {
      cout << Message_Digest[i][j].reveal();
    }
  }
  cout << endl;
}

void print_uint8_t(uint8_t n) {
  bitset<8> x(n);
  cout << x;
}

void printSSLHash(uint8_t* sslHash, int arraySize) {
  for(int i = 0; i < arraySize; i++) {
    print_uint8_t(sslHash[i]);
    cout << ", ";
  }
  cout << endl;
  return;
}
bool compareHash(uint8_t* sslHash, Integer* empHash) {
  for (int i =0; i < 32; i++) {
    bitset<8> sslBitset(sslHash[i]);
    for (int j = 7; j >= 0; j--) {
      if(empHash[i][j].reveal() != sslBitset[j]) {
        return false;
      }
    }
    cout <<  sslBitset << ", ";
  }
  cout << endl << "TRUE?" << endl;
  return true;
}

void runHmac(char* message, int message_length, char* key, int key_length) {
  /* HMAC test */
  Integer intMsg[message_length];
  for (int i = 0; i < message_length; i++) {
    intMsg[i] = Integer(8, message[i], ALICE);
  }
  Integer intKey[key_length];
  for (int i = 0; i < key_length; i++) {
    intKey[i] = Integer(8, key[i], BOB);
  }
  Integer digest_buf[SHA256HashSize];
  Integer* digest = digest_buf;
  EMP_HMAC_Context context;
  HMAC_Reset(&context, intKey, key_length);
  HMAC_Input(&context, intMsg, message_length);
  HMAC_Result(&context, digest);
  printHash(digest);
  // printIntegerArray(digest, SHA256HashSize, 8);

  cout << "KEY: " << key << endl;
  cout << "MSG: " << message << endl;
  uint8_t result[SHA256HashSize];
  
  HMAC(EVP_sha256(), key, key_length, (const unsigned char*)message, message_length, result, NULL);
  compareHash(result, digest);
}


int main(int argc, char** argv) {

  int port, party;
  parse_party_and_port(argv, &party, &port);

  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  runHmac((char*) "72d68d8c2f6ecea8c6b058afe4e02a7a", 32, (char*) "a16807475cbdbea195e61de194c154da", 32);

  delete io;
  return 0;
}
