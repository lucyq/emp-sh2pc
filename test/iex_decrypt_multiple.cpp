#include <emp-tool/emp-tool.h>
#include "emp-tool/utils/hash.h"
#include "emp-sh2pc/emp-sh2pc.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <ctype.h>
#include <vector>
#include "hmac.h"
#include "hmac_optimized.h"
#include <sstream>
#include <string>
#include <iostream>


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

void convertHexToChar(char* hexChar, char* output) { 
    // initialize the ASCII code string as empty. 
    string hex(hexChar);

    //static char tmp[96];
    //char* tmp2 = tmp; 
    for (size_t i = 0; i < hex.length(); i += 2) 
    { 
        // extract two characters from hex string 
        string part = hex.substr(i, 2); 
  
        // change it into base 16 and  
        // typecast as the character 
        char ch = stoul(part, nullptr, 16); 
  
        // add this char to final ASCII string 
        output[i/2] = ch;
    } 
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

void reconstruct(char* input, int input_length, Integer* output, int PARTY) {
  char* temp = input;
  convertHexToChar(input,temp);
  for (int i = 0; i < input_length; i++) {
    output[i] = Integer(8,temp[i], PARTY); 
  }
  return;
}

int main(int argc, char** argv) {

  int port, party;
  parse_party_and_port(argv, &party, &port);

  char* key = ""; // in hex
  char* record_id = ""; // in hex
  char* ciphertext = ""; // in hex, 

  int num_ciphertexts = atoi(argv[4]); // num updates 
  if (party == ALICE) {
    key = argv[3];
  }
  cout << "KEY: " << key << endl;


  const char* record_ids[num_ciphertexts];
  const char* ciphertexts[num_ciphertexts];

 for (int ct_count = 0; ct_count < num_ciphertexts; ct_count++) {
  if (party == BOB) {   
   
    record_ids[ct_count] = argv[ct_count+5];
    ciphertexts[ct_count] = argv[ct_count+6];
    
  } else {
    record_ids[ct_count] = "";
    ciphertexts[ct_count] = "";
  }
 }


  for (int ct_count = 0; ct_count < num_ciphertexts; ct_count++) {
    cout << record_ids[ct_count] << endl;
    cout << ciphertexts[ct_count] << endl;
  }
  

//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.116.70.95", port);
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.38.26.99", port); // Andrew
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "192.168.0.153", port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);
  int ciphertextlength = 192; // length in characters
  // convert key to Integer 
  Integer key_int[KEY_LENGTH];
  reconstruct(key,32,key_int,ALICE);


  Integer record_int[32];
  Integer ciphertext_int[ciphertextlength];

  for (int ct_count = 0; ct_count < num_ciphertexts; ct_count++) {

    cout << ct_count << endl;
    reconstruct((char*)record_ids[ct_count],32,record_int,BOB);
    printIntegerArray(record_int, 32, 8);
  //   // // TODO account for different lengths of ciphertext (i.e. phase 2)

    reconstruct((char*)ciphertexts[ct_count],ciphertextlength,ciphertext_int,BOB);
    Integer* decrypt_key = run_secure_hmac(key_int,32,record_int,32);
    printIntegerArray(decrypt_key, 32, 8);

    // NOTE: Only works up to 32 * 256 character ciphertext 
    Integer output[ciphertextlength];
    Integer random_counter[ciphertextlength/32][32];
    for (int i = 0; i < ciphertextlength/32; i++) {
      for (int j = 0; j < 31; j++) {
        random_counter[i][j] = Integer(8, 0, ALICE);
      }
      random_counter[i][31] = Integer(8, i + 1, ALICE);
      Integer* decrypt_key = run_secure_hmac(key_int,32,record_int,32);
      Integer* tmp_key = run_secure_hmac(decrypt_key,32,random_counter[i],32);

      for (int k = 0; k < 32; k++) {
        output[(32*i) + k] = tmp_key[k] ^ ciphertext_int[(32*i) + k]; 
      }
    }
    reveal(output,ciphertextlength,"output");
  }



  return 0;
}

