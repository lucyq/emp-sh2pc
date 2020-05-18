#include <emp-tool/emp-tool.h>
#include "emp-tool/utils/hash.h"
#include "emp-sh2pc/emp-sh2pc.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <ctype.h>

#include "hmac.h"
#include "hmac_optimized.h"

using namespace emp;
using namespace std; 

enum {
  SN_LENGTH = 12, CID_LENGTH = 4, DATA_LENGTH = 16, // data = sn + cid
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
  static Integer digest_buf[SHA256HashSize];
  Integer* digest = digest_buf;
  EMP_HMAC_Context context;
  HMAC_Reset(&context, key, key_length);
  HMAC_Input(&context, message, message_length);
  HMAC_Result(&context, digest);

  return digest;
}


void xor_reconstruct(uint int1[1][16], uint int2[1][16], int output_length, Integer output[16]) {
  Integer intMsg1[output_length];
  for (int i = 0; i < output_length; i++) {
    intMsg1[i] = Integer(32, int1[0][i], ALICE);
  }
  Integer intMsg2[output_length];
  for (int i = 0; i < output_length; i++) {
    intMsg2[i] = Integer(32, int2[0][i], BOB);
  }

  for (int i = 0; i < output_length; i++) {
    output[i] = intMsg1[i] ^ intMsg2[i]; 
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
// 16 16 16 16 
char* find_utk(char* k_reconstruct, char* p_reconstruct, char* r_reconstruct, char* rprime_reconstruct) {

    char sn1[SN_LENGTH + 1];
    char sn2[SN_LENGTH + 1];
    char cid[32];
    char token[TOKEN_LENGTH]; 

    for (int i = 0; i < SN_LENGTH; i++) {
      sn1[i] = p_reconstruct[i];
      sn2[i] = p_reconstruct[i];
    //sn[i] = Integer(8,'1',PUBLIC);
    }
    sn1[SN_LENGTH] = '1';
    sn2[SN_LENGTH] = '2';
    for (int i = SN_LENGTH; i < DATA_LENGTH; i++) {
      cid[i - SN_LENGTH] = p_reconstruct[i];
    }
    for (int i = CID_LENGTH; i < 32; i++) {
      cid[i] = '\0';
    }
    token[0] = '1';
    uint8_t temp1[SHA256HashSize];
    HMAC(EVP_sha256(), k_reconstruct, KEY_LENGTH, (const unsigned char*)sn1, SN_LENGTH + 1, temp1, NULL);
    //printSSLHash(temp1, 32);
    char* label_key = (char*) temp1;
    uint8_t temp2[SHA256HashSize];
    HMAC(EVP_sha256(), label_key, KEY_LENGTH, (const unsigned char*)token, TOKEN_LENGTH, temp2, NULL);
    //cout << "printing label" << endl;
    //printSSLHash(temp2, 32);
    char* label = (char*) temp2;
    cout << "printing label from char" << endl; 
    //printarray(label,32);
    uint8_t temp3[SHA256HashSize];
    HMAC(EVP_sha256(), k_reconstruct, KEY_LENGTH, (const unsigned char*)sn2, SN_LENGTH + 1, temp3, NULL);
    //printSSLHash(temp3, 32);
    char* value_key = (char*) temp3;
    uint8_t temp4[SHA256HashSize];
    HMAC(EVP_sha256(), value_key, KEY_LENGTH, (const unsigned char*)rprime_reconstruct, RPRIME_LENGTH, temp4, NULL);
    //printSSLHash(temp4, 32);
    char* hmac_key = (char*) temp4;
    char ciphertext[32]; 
    for (int i = 0; i < 32; i++) {
      ciphertext[i] = (char)(hmac_key[i] ^ cid[i]); 
    }
    static char utk[96]; 
    for (int i = 0; i < 32; i++) {
      utk[i] = label[i];
    }
    for (int i = 0; i < 32; i++) {
      utk[32 + i] = ciphertext[i];
    }
    for (int i = 0; i < 32; i++) {
      utk[64 + i] = rprime_reconstruct[i];
    }

    char* output = utk;
    return output;
}

// 16 16 16 16 
void find_secure_utk(Integer k_reconstruct[16], Integer p_reconstruct[16], Integer* r_reconstruct[16], Integer* rprime_reconstruct[16]) {
  //Integer sn1[SN_LENGTH + 1];
  //Integer sn2[SN_LENGTH + 1];
  Integer sn1[16];
  Integer sn2[16];
  Integer cid[32];
  Integer token[TOKEN_LENGTH];

  for (int i = 0; i < SN_LENGTH; i++) {
    sn1[i] = p_reconstruct[i];
    sn2[i] = p_reconstruct[i];
  }
  sn1[SN_LENGTH] = Integer(8,'1',PUBLIC);
  sn2[SN_LENGTH] = Integer(8,'2',PUBLIC);

  for (int i = SN_LENGTH; i < DATA_LENGTH; i++) {
    cid[i - SN_LENGTH] = p_reconstruct[i];
  }
  for (int i = CID_LENGTH; i < 32; i++) {
    cid[i] = Integer(8,'\0',PUBLIC);
  }

  token[0] = Integer(8,'1',PUBLIC);


  Integer label_key2[8];
  run_hmac(k_reconstruct, sn1, SN_LENGTH+1, label_key2);
  cout << "LABEL KEY!!!\n";
  printIntegerArray(label_key2, 8, 32);

  Integer* label_key = runHmac(k_reconstruct,KEY_LENGTH,sn1,SN_LENGTH + 1);

  static Integer utk[96];
  for (int i = 0; i < 32; i++) {
    utk[i] = label_key[i];
  }

  Integer* value_key = runHmac(k_reconstruct,KEY_LENGTH,sn2,SN_LENGTH + 1);
  Integer tmp[KEY_LENGTH]; 
  for (int i = 0;  i < KEY_LENGTH ; i++) {
    tmp[i] = value_key[i]; 
  }
  Integer* hmac_key = runHmac(tmp,KEY_LENGTH,rprime_reconstruct,RPRIME_LENGTH);

  Integer ciphertext[32];
  for (int i = 0; i < 32; i++) {
    ciphertext[i] = hmac_key[i] ^ cid[i];
  }

  for (int i = 0; i < 32; i++) {
    utk[32 + i] = ciphertext[i];
  }
  for (int i = 0; i < 32; i++) {
    utk[64 + i] = rprime_reconstruct[i];
  }

  Integer* output = utk;
  return output;
}

void testUpdate1() {
  char* key = (char*)"NVxmjsCqBGkdRYd59AfCtaDCTMGqJ58B"; 
  char* data = (char*)"KKEyW9gWPnA7XvT3";
  char* random = (char*)"nXnqtkTMXn2dUnpjtxw6FAd57W2PUqzbKb87mu5hqYj8CWnkw7d2kEasP6fp8BC3Dgn28YBGdU3bMWpVACBc6TavzM8CZtVQ";
  char* rprimes = (char*)"WWmAfsr3ZKSA7u9JgSfcW3MGyfJEHEsq";
 
   static Integer k[KEY_LENGTH];
  static Integer p[DATA_LENGTH]; 
  static Integer r[RANDOM_LENGTH];
  static Integer rprime[RPRIME_LENGTH];

  for (int i = 0; i < KEY_LENGTH; i++) {
    k[i] = Integer(8, key[i], PUBLIC);
  }
  for (int i = 0; i < DATA_LENGTH; i++) {
    p[i] = Integer(8, data[i], PUBLIC);
  }
  for (int i = 0; i < RANDOM_LENGTH; i++) {
    r[i] = Integer(8, random[i], PUBLIC);
  }
  for (int i = 0; i < RPRIME_LENGTH; i++) {
    rprime[i] = Integer(8, rprimes[i], PUBLIC);
  }

  char* utk1 = find_utk(key,data,random,rprimes);

  Integer* utk2 = find_secure_utk(k,p,r,rprime); 

  cout << "UTK\n";
  printIntegerArray(utk2, 96, 8);
  // print utk2
  // assert(utk2, "");
  assert(compareUtk(utk1,utk2) == true);
}

void testUpdate2() {
  char* key = (char*)"dZ5uwfQBNHTTmWfLY6dje3BtYfgYnQca"; 
  char* data = (char*)"JtUJnhbF7wk7LRge";
  char* random = (char*)"X6skaVtAQMB8qBV7HV5pbh9f926WKKPd9aWwc9FAwrsV7ed8gsqwDpG7uVYp5pwrL7yDDfNyAJJmEfFaKC3AGLCACEZ4gYRw";
  char* rprimes = (char*)"JpVwaSp24MFRLdvReF3y7D5YRFsWXxdh";
 
  static Integer k[KEY_LENGTH];
  static Integer p[DATA_LENGTH]; 
  static Integer r[RANDOM_LENGTH];
  static Integer rprime[RPRIME_LENGTH];

  for (int i = 0; i < KEY_LENGTH; i++) {
    k[i] = Integer(8, key[i], PUBLIC);
  }
  for (int i = 0; i < DATA_LENGTH; i++) {
    p[i] = Integer(8, data[i], PUBLIC);
  }
  for (int i = 0; i < RANDOM_LENGTH; i++) {
    r[i] = Integer(8, random[i], PUBLIC);
  }
  for (int i = 0; i < RPRIME_LENGTH; i++) {
    rprime[i] = Integer(8, rprimes[i], PUBLIC);
  }

  char* utk1 = find_utk(key,data,random,rprimes);

  Integer* utk2 = find_secure_utk(k,p,r,rprime); 

  assert(compareUtk(utk1,utk2) == true);
}

void convertHexToChar(char* hexChar, char* output, int ARRAY_LENGTH) { 
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


int main(int argc, char** argv) {

  int port, party;
  parse_party_and_port(argv, &party, &port);

  char* k_share = argv[3];
  char* p_share = argv[4];
  char* r_share = argv[5];
  char* rprime_share = argv[6];

  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  int blocks = 1;
  uint k_share_blocks[blocks][16];
  memset(k_share_blocks, 0, blocks*16*sizeof(uint) );
  uint p_share_blocks[blocks][16];
  memset(p_share_blocks, 0, blocks*16*sizeof(uint) );
  uint r_share_blocks[blocks][16];
  memset(r_share_blocks, 0, blocks*16*sizeof(uint) );
  uint rprime_share_blocks[blocks][16];
  memset(rprime_share_blocks, 0, blocks*16*sizeof(uint) );

  strToBlocks((string)k_share,k_share_blocks,64);
  strToBlocks((string)p_share,p_share_blocks,32);
  strToBlocks((string)r_share,r_share_blocks,64);
  strToBlocks((string)rprime_share,rprime_share_blocks,64); // TODO 

  static Integer k_reconstruct[16];
  static Integer p_reconstruct[16];
  static Integer r_reconstruct[16];
  static Integer rprime_reconstruct[16];

  // for (int i = 0; i < 16; i++) {
  //   k_reconstruct[i] = Integer(32, k_share_blocks[0][i], PUBLIC);
  // }
  // for (int i = 0; i < 16; i++) {
  //   p_reconstruct[i] = Integer(32, p_share_blocks[0][i], PUBLIC);
  // }
  // for (int i = 0; i < 16; i++) {
  //   r_reconstruct[i] = Integer(32, r_share_blocks[0][i], PUBLIC);
  // }
  // for (int i = 0; i < 16; i++) {
  //   rprime_reconstruct[i] = Integer(32, rprime_share_blocks[0][i], PUBLIC);
  // }

  // reconstructing everything between Alice and Bob 
  xor_reconstruct(k_share_blocks,k_share_blocks,16, k_reconstruct); 
  xor_reconstruct(p_share_blocks,p_share_blocks,16, p_reconstruct); 
  xor_reconstruct(r_share_blocks,r_share_blocks,16, r_reconstruct);
  xor_reconstruct(rprime_share_blocks,rprime_share_blocks,16, rprime_reconstruct);

  // cout << "P SHARE" << endl;
  printIntegerArray(k_reconstruct,16,32);
  printIntegerArray(p_reconstruct,16,32);
  printIntegerArray(r_reconstruct,16,32);
  printIntegerArray(rprime_reconstruct,16,32);

  Integer* k_reconstruct_ptr = k_reconstruct; 
  Integer* p_reconstruct_ptr = p_reconstruct; 
  Integer* r_reconstruct_ptr = r_reconstruct; 
  Integer* rprime_reconstruct_ptr = rprime_reconstruct; 

  Integer* utk = find_secure_utk(k_reconstruct_ptr,p_reconstruct_ptr,r_reconstruct_ptr,rprime_reconstruct_ptr);

  // shard it in half 
  Integer o1[96]; 
  // o2 is just r_reconstruct; 
  for (int i = 0; i < 96; i++) {
    o1[i] = utk[i] ^ r_reconstruct[i];
  }

  //revealing the output 

  cout << "Party 1 Output:";
  for (int i = 0; i < 96; i++) {
    for (int j = BYTE_BITS-1; j >= 0; j--) {
      cout << o1[i][j].reveal(ALICE);
    }
    cout << ",";
  }
  cout << endl;
  cout << "End of Party 1 Output" << endl;

  cout << "Party 2 Output: ";
  for (int i = 0; i < 96; i++) {
    for (int j = BYTE_BITS-1; j >= 0; j--) {
      cout << r_reconstruct[i][j].reveal(BOB);
    }
    cout << ",";
  }
  cout << "End of Party 2 Output" << endl;

  delete io;
  return 0;
}
