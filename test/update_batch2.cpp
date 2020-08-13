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


void xor_reconstruct(char* int1, char* int2, int output_length, Integer* output) {
  Integer intMsg1[output_length];
  for (int i = 0; i < output_length; i++) {
    intMsg1[i] = Integer(8, int1[i], ALICE);
  }
  Integer intMsg2[output_length];
  for (int i = 0; i < output_length; i++) {
    intMsg2[i] = Integer(8, int2[i], BOB);
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

Integer* find_secure_utk(Integer* k_reconstruct, Integer* p_reconstruct, Integer* r_reconstruct, Integer* rprime_reconstruct) {
  Integer sn1[SN_LENGTH + 1];
  Integer sn2[SN_LENGTH + 1];
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

  Integer* label_key = run_secure_hmac(k_reconstruct,KEY_LENGTH,sn1,SN_LENGTH + 1);
  // second HMAC in clusion
  // Integer* label = run_secure_hmac(label_key,KEY_LENGTH,token,TOKEN_LENGTH);

  static Integer utk[96];
  for (int i = 0; i < 32; i++) {
    utk[i] = label_key[i];
  }

  Integer* value_key = run_secure_hmac(k_reconstruct,KEY_LENGTH,sn2,SN_LENGTH + 1); 
  Integer* hmac_key = run_secure_hmac(value_key,KEY_LENGTH,rprime_reconstruct,RPRIME_LENGTH);

  //xor padded cid with hmac_key 
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

  // check if utk matches update-test 

  //cout << "PRINT UTK ARRAY" << endl;
  //printIntegerArray(utk,96,8);
  Integer* output = utk;
  return output;
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

  char* k_share_hex = argv[3];
  int num_updates = atoi(argv[4]); 


  // char* p_hex = argv[4];
  // char* r_hex = argv[5];
  // char* rprime_hex = argv[6];

//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.116.70.95", port);
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.38.26.99", port); // Andrew
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "192.168.0.153", port);
 // NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "172.31.40.42", port);

  setup_semi_honest(io, party);

  cout << "begin actual 2pc" << endl;
  cout << num_updates << endl;


  auto t1 = clock_start();

  char* p_hex;
  char* r_hex;
  char* rprime_hex;
  static Integer k_reconstruct[KEY_LENGTH];
  static Integer p_reconstruct[DATA_LENGTH];
  static Integer r_reconstruct[RANDOM_LENGTH];
  static Integer rprime_reconstruct[RPRIME_LENGTH];
  char* k_share;
  Integer* k_reconstruct_ptr;
  k_share = k_share_hex;
  convertHexToChar(k_share_hex,k_share,KEY_LENGTH);
  for (int i = 0; i < KEY_LENGTH; i++) {
    k_reconstruct[i] = Integer(8, k_share[i], PUBLIC);
      //k_reconstruct[i] = Integer(8, '1', PUBLIC);
  }
  xor_reconstruct(k_share,k_share,KEY_LENGTH, k_reconstruct); 

  for (int i = 0; i < num_updates; i++) {
    char* p;
    char* r;
    char* rprime;
    Integer* p_reconstruct_ptr;
    Integer* r_reconstruct_ptr;
    Integer* rprime_reconstruct_ptr;


    p_hex = argv[5 + (3*i)];
    r_hex = argv[6 + (3*i)];
    rprime_hex = argv[7 + (3*i)];

    p = p_hex;
    r = r_hex;
    rprime = rprime_hex;

    //cout << p << endl;
    //cout << r << endl;
    //cout << rprime << endl;

    convertHexToChar(p_hex,p,DATA_LENGTH);
    //cout << 'p' << endl; 

    convertHexToChar(r_hex,r,RANDOM_LENGTH);
    //cout << 'r' << endl; 

    convertHexToChar(rprime_hex,rprime,RPRIME_LENGTH);
    //cout << "rprime" << endl; 

    // convertHexToChar(k_share_hex,k_share,KEY_LENGTH);

    // cout << 'k' << endl; 

    //cout << "GETS HERE" << endl;


    // for (int i = 0; i < KEY_LENGTH; i++) {
    //   k_reconstruct[i] = Integer(8, k_share[i], PUBLIC);
    //   //k_reconstruct[i] = Integer(8, '1', PUBLIC);
    // }
    for (int i = 0; i < DATA_LENGTH; i++) {
      p_reconstruct[i] = Integer(8, p[i], PUBLIC);
    }
    for (int i = 0; i < RANDOM_LENGTH; i++) {
      r_reconstruct[i] = Integer(8, r[i], PUBLIC);
    }
    for (int i = 0; i < RPRIME_LENGTH; i++) {
      rprime_reconstruct[i] = Integer(8, r[i], PUBLIC);
    }

    //cout << "GETS HERE2" << endl;

    // reconstructing everything between Alice and Bob 
    // xor_reconstruct(k_share,k_share,KEY_LENGTH, k_reconstruct); 
    xor_reconstruct(p,p,DATA_LENGTH, p_reconstruct); 
    xor_reconstruct(r,r,RANDOM_LENGTH, r_reconstruct);
    xor_reconstruct(rprime,rprime,RPRIME_LENGTH, rprime_reconstruct);

    k_reconstruct_ptr = k_reconstruct; 
    p_reconstruct_ptr = p_reconstruct; 
    r_reconstruct_ptr = r_reconstruct; 
    rprime_reconstruct_ptr = rprime_reconstruct; 

    // Calculate the token

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
      for (int j = 7; j > -1; j--) {
        cout << o1[i][j].reveal(ALICE);
      }
      cout << ",";
    }
    cout << endl;
    cout << "End of Party 1 Output" << endl;

    cout << "Party 2 Output:";
    for (int i = 0; i < 96; i++) {
      for (int j = 7; j > -1; j--) {
        cout << r_reconstruct[i][j].reveal(BOB);
      }
      cout << ",";
    }
    cout << "End of Party 2 Output" << endl;


  }
  cout << "2PC Time: " << time_from(t1) << endl;

  delete io;
  return 0;
}
