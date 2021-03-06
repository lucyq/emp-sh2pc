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
  SN_LENGTH = 12, KEY_LENGTH = 32, RANDOM_LENGTH = 32, RPRIME_LENGTH = 32, TOKEN_LENGTH = 1
};

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

void printarray(char* array, int ARRAY_LENGTH) {
    for (int i = 0; i <ARRAY_LENGTH; i ++) {
      for (int j = 0; j < 8; j++) {
        printf("%d", !!((array[i] << j) & 0x80));
      }
      printf(", ");
    }
  cout << endl;
}

bool compareTokens(char* expected, Integer* actual) {
  for (int i = 0; i < 2*KEY_LENGTH; i++) {
    for (int j = 0; j < 8; j++) {
      if ((int)!!((expected[i] << (7-j)) & 0x80) != (int)actual[i][j].reveal(PUBLIC)) {
        return false;
      }
    }
  }
  return true; 
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

Integer* runHmac(Integer* key, int key_length,Integer* message, int message_length) {
  static Integer digest_buf[SHA256HashSize];
  Integer* digest = digest_buf;
  EMP_HMAC_Context context;
  HMAC_Reset(&context, key, key_length);
  HMAC_Input(&context, message, message_length);
  HMAC_Result(&context, digest);

  Integer* digest_ptr = digest;

  return digest_ptr;
}

char* find_tokens(char* k_reconstruct, char* q_reconstruct, char* r_reconstruct, char* rprime_reconstruct) {
    static char tokens[2 * KEY_LENGTH]; 
    char sn1[SN_LENGTH + 1];
    char sn2[SN_LENGTH + 1];
    char ctr[TOKEN_LENGTH]; 

    for (int i = 0; i < SN_LENGTH; i++) {
      sn1[i] = q_reconstruct[i];
      sn2[i] = q_reconstruct[i];
    }
    sn1[SN_LENGTH] = '1';
    sn2[SN_LENGTH] = '2';

    ctr[0] = '1';

    uint8_t temp1[SHA256HashSize];
    HMAC(EVP_sha256(), k_reconstruct, KEY_LENGTH, (const unsigned char*)sn1, SN_LENGTH + 1, temp1, NULL);
    char* label_key = (char*) temp1;
    uint8_t temp2[SHA256HashSize];
    HMAC(EVP_sha256(), label_key, KEY_LENGTH, (const unsigned char*)ctr, TOKEN_LENGTH, temp2, NULL);
    char* tk1 = (char*) temp2;
    uint8_t temp3[SHA256HashSize];
    HMAC(EVP_sha256(), k_reconstruct, KEY_LENGTH, (const unsigned char*)sn2, SN_LENGTH + 1, temp3, NULL);
    char* tk2 = (char*) temp3;

    for (int i = 0; i < KEY_LENGTH; i++) {
        tokens[i] = tk1[i];
    }
    for (int i = 0; i < KEY_LENGTH; i++) {
        tokens[KEY_LENGTH + i] = tk2[i];
    }

    char* output = tokens;
    return output;
}

Integer* generate_secure_tokens(Integer* k_reconstruct, Integer* q_reconstruct, Integer* r_reconstruct, Integer* rprime_reconstruct) {
  static Integer tokens[2 * KEY_LENGTH];

  Integer sn1[SN_LENGTH + 1];
  Integer sn2[SN_LENGTH + 1];
  Integer ctr[TOKEN_LENGTH];

  for (int i = 0; i < SN_LENGTH; i++) {
    sn1[i] = q_reconstruct[i];
    sn2[i] = q_reconstruct[i];
  }
  sn1[SN_LENGTH] = Integer(8,'1',PUBLIC);
  sn2[SN_LENGTH] = Integer(8,'2',PUBLIC);

  ctr[0] = Integer(8,'1',PUBLIC);

  Integer* label_key = run_secure_hmac(k_reconstruct,KEY_LENGTH,sn1,SN_LENGTH + 1);
  //Integer* tk1 = runHmac(label_key,KEY_LENGTH,ctr,TOKEN_LENGTH);
  for (int i = 0; i < KEY_LENGTH; i++) {
  	tokens[i] = label_key[i];
  }

  Integer* tk2 = run_secure_hmac(k_reconstruct,KEY_LENGTH ,sn2, SN_LENGTH+1); 

  for (int i = 0; i < KEY_LENGTH; i++) {
  	tokens[KEY_LENGTH + i] = tk2[i];
  }
  Integer* output = tokens;
  return output;
}

void testQuery1() {
  char* key = (char*)"NVxmjsCqBGkdRYd59AfCtaDCTMGqJ58B"; 
  char* data = (char*)"KKEyW9gWPnA7";
  char* random = (char*)"nXnqtkTMXn2dUnpjtxw6FAd57W2PUqzb";
  char* rprimes = (char*)"WWmAfsr3ZKSA7u9JgSfcW3MGyfJEHEsq";

  static Integer k[KEY_LENGTH];
  static Integer q[SN_LENGTH]; 
  static Integer r[RANDOM_LENGTH];
  static Integer rprime[RPRIME_LENGTH];

  for (int i = 0; i < KEY_LENGTH; i++) {
    k[i] = Integer(8, key[i], PUBLIC);
  }
  for (int i = 0; i < SN_LENGTH; i++) {
    q[i] = Integer(8, data[i], PUBLIC);
  }
  for (int i = 0; i < RANDOM_LENGTH; i++) {
    r[i] = Integer(8, random[i], PUBLIC);
  }
  for (int i = 0; i < RPRIME_LENGTH; i++) {
    rprime[i] = Integer(8, rprimes[i], PUBLIC);
  }

  char* tokens1 = find_tokens(key,data,random,rprimes);
  Integer* tokens2 = generate_secure_tokens(k,q,r,rprime); 

  assert(compareTokens(tokens1,tokens2) == true);
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
  char* q_hex = argv[4];
  char* r_hex = argv[5];
  char* rprime_hex = argv[6];

// NetIO * io = new NetIO(party==ALICE ? nullptr : "18.221.224.217", port); // aws
// NetIO * io = new NetIO(party==ALICE ? nullptr : "34.70.234.217", port); // gcloud
 NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  cout << "begin query 2pc" << endl;

  char* k_share = k_share_hex;
  char* q = q_hex;
  char* r = r_hex;
  char* rprime = rprime_hex;
  convertHexToChar(k_share_hex,k_share,KEY_LENGTH);
  convertHexToChar(q_hex,q,SN_LENGTH);
  convertHexToChar(r_hex,r,RANDOM_LENGTH);
  convertHexToChar(rprime_hex,rprime,RPRIME_LENGTH);
  
  auto t1 = clock_start();

  static Integer k_reconstruct[KEY_LENGTH];
  static Integer q_reconstruct[SN_LENGTH];
  static Integer r_reconstruct[RANDOM_LENGTH];
  static Integer rprime_reconstruct[RPRIME_LENGTH];

  for (int i = 0; i < KEY_LENGTH; i++) {
    k_reconstruct[i] = Integer(8, k_share[i], PUBLIC);
  }

  for (int i = 0; i < SN_LENGTH; i++) {
    q_reconstruct[i] = Integer(8, q[i], PUBLIC);
  }

  for (int i = 0; i < RANDOM_LENGTH; i++) {
    r_reconstruct[i] = Integer(8, r[i], PUBLIC);
  }

  for (int i = 0; i < RPRIME_LENGTH; i++) {
    rprime_reconstruct[i] = Integer(8, rprime[i], PUBLIC);
  }

  // reconstructing everything between Alice and Bob 
  xor_reconstruct(k_share,k_share,KEY_LENGTH, k_reconstruct); 
  xor_reconstruct(q,q,SN_LENGTH, q_reconstruct); 
  xor_reconstruct(r,r,RANDOM_LENGTH, r_reconstruct);
  xor_reconstruct(rprime,rprime,RPRIME_LENGTH, rprime_reconstruct);

  Integer* k_reconstruct_ptr = k_reconstruct; 
  Integer* q_reconstruct_ptr = q_reconstruct; 
  Integer* r_reconstruct_ptr = r_reconstruct; 
  Integer* rprime_reconstruct_ptr = rprime_reconstruct; 

  // Calculate the token

  Integer* tokens = generate_secure_tokens(k_reconstruct_ptr,q_reconstruct_ptr,r_reconstruct_ptr,rprime_reconstruct_ptr);
  Integer tokensA[KEY_LENGTH * 2];
  Integer tokensB[KEY_LENGTH * 2];
  
  for (int i = 0; i < KEY_LENGTH; i++) {
    tokensA[i] = tokens[i] ^ r_reconstruct[i];
  }
  for (int i = 0; i < KEY_LENGTH; i++) {
    tokensA[i + KEY_LENGTH] = tokens[i + KEY_LENGTH] ^ rprime_reconstruct[i];
  }

  for (int i = 0; i < KEY_LENGTH; i++) {
    tokensB[i] = r_reconstruct[i];
  }
  for (int i = 0; i < KEY_LENGTH; i++) {
    tokensB[i + KEY_LENGTH] = rprime_reconstruct[i];
  }

  cout << "Party 1 Output:";
  for (int i = 0; i < KEY_LENGTH * 2; i++) {
    for (int j = BYTE_BITS-1; j >= 0; j--) {
      cout << tokensA[i][j].reveal(ALICE);
    }
    cout << ",";
  }
  cout << "End of Party 1 Output" << endl;

  cout << "Party 2 Output:";
  for (int i = 0; i < KEY_LENGTH * 2; i++) {
    for (int j = BYTE_BITS-1; j >= 0; j--) {
      cout << tokensB[i][j].reveal(BOB);
    }
    cout << ",";
  }
  cout << "End of Party 2 Output" << endl;


  cout << "2PC Time (ms): " << (time_from(t1) * 0.001) << endl;

  delete io;
  return 0;
}
