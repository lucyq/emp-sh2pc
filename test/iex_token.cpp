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
  SN_LENGTH = 12, CID_LENGTH = 4, DATA_LENGTH = 16, WORD_LENGTH = 32,// data = sn + cid
  KEY_LENGTH = 32, RANDOM_LENGTH = 96, RPRIME_LENGTH = 32, TOKEN_LENGTH = 1
};

void printarray(char* array, int ARRAY_LENGTH) {
    for (int i = 0; i <ARRAY_LENGTH; i ++) {
      for (int j = 0; j < 8; j++) {
        printf("%d", !!((array[i] << j) & 0x80));
      }
      printf(", ");
    }
  cout << endl;
}

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
  for (int i =0; i < SHA256HashSize; i++) {
    bitset<8> sslBitset(sslHash[i]);
    for (int j = 7; j >= 0; j--) {
      if(empHash[i][j].reveal() != sslBitset[j]) {
        cout << endl << "FALSE" << endl;
        return false;
      }
    }
  }
  cout << endl << "TRUE" << endl;
  return true;
}

Integer* runHmac(Integer* key, int key_length,Integer* message, int message_length) {
  Integer tmp[message_length + 1]; 
  tmp[0] = Integer('1',8,BOB);
  for (int i = 0; i < message_length; i++) {
  	tmp[i+1] = message[i];
  }
  Integer* ptr = tmp;
  static Integer digest_buf[SHA256HashSize];
  Integer* digest = digest_buf;
  EMP_HMAC_Context context;
  HMAC_Reset(&context, key, key_length);
  HMAC_Input(&context, ptr, message_length + 1);
  HMAC_Result(&context, digest);

  return digest;
}

void reveal(Integer* output, int LENGTH, string val) {
  cout << val << endl;
  for (int i = 0; i < LENGTH; i++) {
    for (int j = 7; j >= 0; j--) {
      cout << output[i][j].reveal(BOB);
    }
    cout << ",";
  }
  cout << endl;
}

void reconstruct(char* input, int input_length, Integer* output, int PARTY) {
  for (int i = 0; i < input_length; i++) {
    output[i] = Integer(8,input[i], PARTY); 
  }
  return;
}

Integer* convertStringtoIntegerArray(char* s, int S_LENGTH) {
  Integer output[S_LENGTH];
  for (int i =0; i < S_LENGTH; i++) {
    output[i] = Integer(8,s[i],PUBLIC);
  }
  //static Integer temp = output;
  static Integer* output_ptr = output; 
  return output_ptr;
}

bool compareUtk(char* expected, Integer* actual) {
  for (int i = 0; i < 96; i++) {
    for (int j = 0; j < 8; j++) {
      if ((int)!!((expected[i] << (7-j)) & 0x80) != (int)actual[i][j].reveal(PUBLIC)) {
        return false;
      }
    }
  }
  return true; 
}

int main(int argc, char** argv) {

  int port, party;
  parse_party_and_port(argv, &party, &port);

  char* key1 = "";
  char* key2 = "";
  char* word1 = "";
  char* word2 = ""; 
  if (party == ALICE) {
  	key1 = argv[3];
  	key2 = argv[4];
  } else {
  	word1 = argv[3];
  	word2 = argv[4];
  }

//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.116.70.95", port);
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.38.26.99", port); // Andrew
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "192.168.0.153", port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  cout << "GETS HERE" << endl;
  cout << strlen(word1) << endl;
  cout << strlen(word2) << endl;

  Integer global_key[KEY_LENGTH];
  Integer local_key[KEY_LENGTH];
  Integer word1_int[WORD_LENGTH];
  Integer word2_int[WORD_LENGTH];

  reconstruct(key1,KEY_LENGTH,global_key,ALICE);
  reconstruct(key2,KEY_LENGTH,local_key,ALICE);
  reconstruct(word1,WORD_LENGTH,word1_int,BOB);
  reconstruct(word2,WORD_LENGTH,word2_int,BOB);

  Integer* global_key_ptr = global_key;
  Integer* local_key_ptr = local_key;
  Integer* word1_int_ptr = word1_int;
  Integer* word2_int_ptr = word2_int;

  Integer* keys[] = {global_key_ptr,local_key_ptr};
  Integer* keywords[] = {word1_int_ptr,word2_int_ptr};

// needs to be ln of keywords
  int numwords = 2;
  for (int i = 0; i < numwords - 1; i++) {
  	Integer* gtk = runHmac(keys[0],KEY_LENGTH,keywords[i],WORD_LENGTH);
  	reveal(gtk,32,"gtk");
  	Integer* dtk = runHmac(keys[1],KEY_LENGTH,keywords[i],WORD_LENGTH);
  	reveal(dtk,32,"dtk");
  	for (int j = i+1; j < numwords; j++) {
  		Integer* tmp_key = runHmac(keys[0],KEY_LENGTH,keywords[i],WORD_LENGTH);
  		Integer* ltk = runHmac(tmp_key,KEY_LENGTH,keywords[j],WORD_LENGTH);
  		reveal(ltk,32,"ltk");
  	}
  }
  Integer* gtk_q = runHmac(keys[0],KEY_LENGTH,keywords[numwords-1],WORD_LENGTH);
  reveal(gtk_q,32,"gtk");

  delete io;
  return 0;
}

