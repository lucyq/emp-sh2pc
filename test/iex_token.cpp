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

void reconstruct(char* input, int input_length, Integer* output, int PARTY) {
  char* temp = input;
  convertHexToChar(input,temp,input_length);
  for (int i = 0; i < input_length; i++) {
    output[i] = Integer(8,temp[i], PARTY); 
  }
  for (int i = input_length; i < 32; i++) {
    output[i] = Integer(8,0,PARTY);
  }
  return;
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

vector<string> split_words(char* words) {
  string my_str = words;
  vector<string> result;
  stringstream s_stream(my_str); //create string stream from the string
  while(s_stream.good()) {
    string substr;
    getline(s_stream, substr, ','); //get first string delimited by comma
    //cout << substr << endl;
    //result.push_back((char*)substr.c_str());
    result.push_back(substr);
  }
  // for(int i = 0; i<result.size(); i++) {    //print all splitted strings
  //   cout << result.at(i) << endl;
  // }
  return result;
}

void iex_token(Integer* key1, Integer* key2, Integer* key3, vector<string> words, int numwords) {
  Integer keywords[numwords][WORD_LENGTH]; 
  for (int i = 0; i < numwords; i++) {
    string curr = words.at(i);
    //static Integer currword[WORD_LENGTH];
    reconstruct((char*)curr.c_str(),curr.length()/2,keywords[i],BOB);
    //Integer* currword_ptr = currword;
    //Integer* tmp = new Integer[WORD_LENGTH];
    //tmp = currword;
    //keywords[i] = tmp;
    //printIntegerArray(keywords[i],32,8);
  }
  // cout << "CHECK KEYWORDS" << endl;
  // for (int i =0 ; i < numwords; i ++) {
  //   printIntegerArray(keywords[i],32,8);
  // }

  Integer* global_key_ptr = key1;
  Integer* local_key_ptr = key2;
  // Integer* word1_int_ptr = word1_int;
  // Integer* word2_int_ptr = word2_int;

  Integer* keys[] = {global_key_ptr,local_key_ptr};

  for (int i = 0; i < numwords; i++) {
    cout << "TOKEN: " << endl; // note: do not delete. needed in JS parsing
      Integer gtk_tmp1[WORD_LENGTH + 1];
      Integer gtk_tmp2[WORD_LENGTH + 1];
      gtk_tmp1[0] = Integer(8,'1',BOB);
      gtk_tmp2[0] = Integer(8,'2',BOB);
      for (int a = 1; a < WORD_LENGTH + 1; a++) {
        gtk_tmp1[a] = keywords[i][a-1];
        gtk_tmp2[a] = keywords[i][a-1];
      }

      Integer* gtk1 = run_secure_hmac(key1,KEY_LENGTH,gtk_tmp1,WORD_LENGTH + 1);
      reveal(gtk1,32,"gtk1");

      Integer* gtk2 = run_secure_hmac(key1,KEY_LENGTH,gtk_tmp2,WORD_LENGTH + 1);
      reveal(gtk2,32,"gtk2");

      Integer dtk_tmp[WORD_LENGTH + 1];
      dtk_tmp[0] = Integer(8,'3',BOB);
      for (int a = 1; a < WORD_LENGTH + 1; a++) {
        dtk_tmp[a] = keywords[i][a-1];
      }
    // cout << "HELLO" << endl;
    // printIntegerArray(dtk_tmp,WORD_LENGTH+1,8);

      Integer* dtk = run_secure_hmac(key2,KEY_LENGTH,dtk_tmp,WORD_LENGTH+1);
      reveal(dtk,32,"dtk");
    //}

    for (int j = i+1; j < numwords; j++) {

      Integer ltk_tmp1[WORD_LENGTH + 1];
      Integer ltk_tmp2[WORD_LENGTH + 1];
      ltk_tmp1[0] = Integer(8,'1',BOB);
      ltk_tmp2[0] = Integer(8,'2',BOB);
      for (int k = 1; k < WORD_LENGTH + 1; k++) {
        ltk_tmp1[k] = keywords[j][k-1];
        ltk_tmp2[k] = keywords[j][k-1];
      }
      //cout << "HELLO" << endl;
      //printIntegerArray(ltk_tmp1,WORD_LENGTH+1,8);
      //printIntegerArray(ltk_tmp2,WORD_LENGTH+1,8);

      Integer* tmp_key = run_secure_hmac(key1,KEY_LENGTH,keywords[i],WORD_LENGTH);
      Integer tmp_key2[32]; 
      for (int a = 0; a < 32; a++) {
        tmp_key2[a] = tmp_key[a];
      }
      //printIntegerArray(tmp_key,WORD_LENGTH,8);
      //printIntegerArray(ltk_tmp1,WORD_LENGTH+1,8);
      Integer* ltk1 = run_secure_hmac(tmp_key,KEY_LENGTH,ltk_tmp1,WORD_LENGTH+1);
      reveal(ltk1,32,"ltk1");
      //printIntegerArray(tmp_key2,WORD_LENGTH,8);
      //printIntegerArray(ltk_tmp2,WORD_LENGTH+1,8);
      Integer* ltk2 = run_secure_hmac(tmp_key2,KEY_LENGTH,ltk_tmp2,WORD_LENGTH+1);
      reveal(ltk2,32,"ltk2");
    //}
  }
}
}

int main(int argc, char** argv) {

  int port, party;
  parse_party_and_port(argv, &party, &port);

  char* master = "";
  vector<vector<string> > queries;
  vector<string> wordlengths = split_words(argv[4]);
  int numqueries = wordlengths.size();
  if (party == ALICE) {
    master = argv[3];
    for (int i = 0; i < numqueries; i++) {
      vector<string> keywords;
      for (int j = 0; j < stoi(wordlengths.at(i)); j++) {
        keywords.push_back("");
      }
      queries.push_back(keywords);
    }
  } else {
    master = argv[3];
    for (int i = 0; i < numqueries; i++) {
      vector<string> tmp = split_words(argv[5+i]);
      queries.push_back(tmp);
    }
  }

//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.116.70.95", port);
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "10.38.26.99", port); // Andrew
//  NetIO * io = new NetIO(party==ALICE ? nullptr : "192.168.0.153", port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  char* k_share = master;
  convertHexToChar(master,k_share,KEY_LENGTH);

  static Integer master_key[KEY_LENGTH];

  for (int i = 0; i < KEY_LENGTH; i++) {
    master_key[i] = Integer(8, k_share[i], PUBLIC);
    //k_reconstruct[i] = Integer(8, '1', PUBLIC);
  }

  xor_reconstruct(k_share,k_share,KEY_LENGTH,master_key);
  printIntegerArray(master_key,KEY_LENGTH,8);
  Integer key1[KEY_LENGTH];
  Integer key2[KEY_LENGTH];
  Integer key3[KEY_LENGTH];
  Integer token1[1];

  token1[0] = Integer(8,'1',PUBLIC);
  Integer* key1_tmp = run_secure_hmac(master_key,KEY_LENGTH,token1,1);
  for (int i =0 ; i < KEY_LENGTH; i++) {
    key1[i] = key1_tmp[i];
  }

  Integer token2[1];
  token2[0] = Integer(8,'2',PUBLIC);
  Integer* key2_tmp = run_secure_hmac(master_key,KEY_LENGTH,token2,1);
  for (int i =0 ; i < KEY_LENGTH; i++) {
    key2[i] = key2_tmp[i];
  }

  Integer token3[1];
  token3[0] = Integer(8,'3',PUBLIC);
  Integer* key3_tmp = run_secure_hmac(master_key,KEY_LENGTH,token3,1);
  for (int i =0 ; i < KEY_LENGTH; i++) {
    key3[i] = key3_tmp[i];
  }

  // Step 4:
  //cout << "BEG OF STEP 4" << endl;
  for (int i = 1; i < numqueries; i++) {
    for (int k = 0; k < queries.at(0).size(); k++) {
      vector<string> searchTMP;
      searchTMP.push_back(queries.at(0).at(k));
      // cout << "INSIDE LOOP" << endl;
      // cout << queries.at(i).size() << endl;

      for (int r = 0; r < queries.at(i).size(); r++) {
        searchTMP.push_back(queries.at(i).at(r));
      }

      // note: do not change. needed in JS for parsing
      cout << "LABEL: " << i << " " << k << " $" << endl;
      iex_token(key1,key2,key3,searchTMP,searchTMP.size());
    }
  }

  // Step 3: 
  // note: do not change. needed in JS for parsing
  cout << "LABEL: " << queries.size() << " " << queries.at(0).size() << " $" << endl;
  iex_token(key1,key2,key3,queries.at(0),queries.at(0).size());

  delete io;
  return 0;
}

