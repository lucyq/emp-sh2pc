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


void printarray(char* array, int ARRAY_LENGTH) {
    for (int i = 0; i <ARRAY_LENGTH; i ++) {
      for (int j = 0; j < 8; j++) {
        printf("%d", !!((array[i] << j) & 0x80));
      }
      printf(", ");
    }
  cout << endl;
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
        cout << endl << "False" << endl;
        return false;
      }
    }
    cout <<  sslBitset << ", ";
  }
  cout << endl << "True" << endl;
  return true;
}

void runHmac(char* key, int key_length, char* message, int message_length) {
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


  uint8_t input[32] = {160,63,168,3,24,196,213,57,219,176,234,228,150,246,213,122,155,8,235,64,87,68,165,27,236,231,97,40,168,61,140,81};
  uint8_t key[32] = {213,16,44,134,80,192,163,23,109,217,5,219,93,168,89,198,62,236,212,183,126,180,44,84,228,165,196,238,109,58,61,10};

  runHmac((char*)(key), 32, (char*)(input), 32);

  delete io;
  return 0;
}


