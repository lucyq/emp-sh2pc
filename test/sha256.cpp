/*
 * This runs end-to-end tests on the sha256 functionality
 * and unit tests on the individual components
 * (in build_tokens/sha256.*)
 *
 * Unit tests verify that the component funtions produce the same output
 * on normal integers and secret Integers.
 *
 * End-to-end tests are run on vectors from Briston (TODO: add link)
 * and on vectors generated at random. Currently not using a seeded rand function (TODO)
 * The reference implementation is CryptoPP.
 * Padding is always executed in the clear; padding implementation is from some guy on stackoverflow
 *
 */
#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
#include "sha256.h"
using namespace emp;
using namespace std;

// crypto++ headers
#include "cryptopp/files.h"
#include "cryptopp/filters.h"
#include "cryptopp/hex.h"
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"
#define byte unsigned char

// boost header to compare strings
#include <boost/algorithm/string.hpp>

enum Version { INSEC2, SEC1, SEC2, SEC3 };


/* implementation of SHA256 from FIPS PUB 180-4 
 * with the following modifications
 * - processes only a fixed length input (BLOCKS)
 * - assumes padding already exists
 */

Integer ROR32(Integer x, Integer n) {
  Integer thirtytwo(BITS, 32, PUBLIC);
  return (x >> n) | (x << (thirtytwo - n));
}
Integer ROR32(Integer x, uint n) {
  int shiftamt = 32 - n;
  return (x >> n) | (x << shiftamt);
}
uint ROR32(uint x, uint n) {
  return ((x >> n) | (x << (32 - n)));
}


void initSHA256(Integer k[64], Integer H[8]) {
  for(int i=0; i<64; i++) {
    k[i] = Integer(BITS, k_clear[i], PUBLIC);
  }
  for(int i=0; i<8; i++) {
    H[i] = Integer(BITS, IV_clear[i], PUBLIC);
  }
}

string get_bitstring(Integer x) {
  string s = "";
  for(int i=0; i<x.size(); i++) {
    s = (x[i].reveal<bool>(PUBLIC) ? "1" : "0") + s;
  }
  return s;
}

// result is 8 32-bit integers
// hash   is 1 256-bit integer
// hash = result[0] || result[1] || ... || result[7]
Integer composeSHA256result(Integer result[8]) {
  Integer thirtytwo(256, 32, PUBLIC);
  result[0].resize(256, false);
  Integer hash = result[0];
  for(int i=1; i<8; i++) {
    result[i].resize(256, false);
    hash = (hash << thirtytwo) | result[i];
  }
  return hash;
}

void computeInnerHashBlock( Integer k[64], Integer H[8], Integer w[64]) {
  Integer a,b,c,d,e,f,g,h;
  // prepare message schedule

  // 1. Prepare the message schedule, {Wt} (0-15 initialized from message)
  for(size_t t = 16 ; t <= 63 ; t++) {
    w[t] = SIGMA_LOWER_1(w[t-2]) + w[t-7] + SIGMA_LOWER_0(w[t-15]) + w[t-16];
  }

  // 2. Initialize working variables
  a = H[0];
  b = H[1];
  c = H[2];
  d = H[3];
  e = H[4];
  f = H[5];
  g = H[6];
  h = H[7];

  // 3. Compress: update working variables
  for (int t=0; t < 64; t++) {
    Integer temp1 = h + SIGMA_UPPER_1(e) + CH(e, f, g) + k[t] + w[t];
    Integer temp2 = SIGMA_UPPER_0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  // 4. Set new hash values
  H[0] = H[0] + a;
  H[1] = H[1] + b;
  H[2] = H[2] + c;
  H[3] = H[3] + d;
  H[4] = H[4] + e;
  H[5] = H[5] + f;
  H[6] = H[6] + g;
  H[7] = H[7] + h;
}

/* computes sha256 for a 2-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256_2l(uint message[2][16], Integer result[8]) {
  // initialize constants and initial hash digest value
  const int BLOCKS = 2;
  Integer k[64];
  Integer H[8];
  Integer w[BLOCKS][64];
  // initialize message schedule
  for (int i=0; i<BLOCKS; i++) {
    for(size_t t=0; t<16; t++) {
      // todo: figure out who the message belongs to
      w[i][t] = Integer(BITS, message[i][t], CUST);
    }
  }

  initSHA256(k, H);

  for (int i=0; i<BLOCKS; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}


/* computes sha256 for 1-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256_1d(Integer message[1][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[64];
  // initialize message schedule
  for(size_t t=0; t<16; t++) {
    w[t] = message[0][t];
  }

  initSHA256(k, H);
  computeInnerHashBlock(k, H, w);

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}


/* computes sha256 for a 2-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256_2d(Integer message[2][16], Integer result[8]) {
  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[2][64];
  // initialize message schedule
  for (int i=0; i<2; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<2; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}


/* computes sha256 for 3-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256_3d(Integer message[3][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[3][64];
  // initialize message schedule
  for (int i=0; i<3; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<3; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}

void computeSHA256_4d(Integer message[4][16], Integer result[8]) {
  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[4][64];
  // initialize message schedule
  for (int i=0; i<4; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<4; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}

void computeSHA256_5d(Integer message[5][16], Integer result[8]) {
  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[5][64];
  // initialize message schedule
  for (int i=0; i<5; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<5; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  for(int i=0; i<8; i++) {
    result[i] = H[i];
  }
}



void computeDoubleSHA256_3d(Integer message[3][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[3][64];
  // initialize message schedule
  for (int i=0; i<3; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<3; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  // for(int i=0; i<8; i++) {
  //   result[i] = H[i];
  // }

  // make a new buffer for the itterated hash

  Integer newmessage[1][16];

  for(int i=0; i<8; i++) {
    newmessage[0][i] = H[i];
  }

  newmessage[0][8] = Integer(32, 2147483648/*0x80000000*/, PUBLIC);
  for(int i=9; i<15; i++) {
    newmessage[0][i] = Integer(32, 0/*0x00000000*/, PUBLIC);
  }
  newmessage[0][15] = Integer(32, 256, PUBLIC);

  computeSHA256_1d(newmessage, result);
}


void computeDoubleSHA256_4d(Integer message[4][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[4][64];
  // initialize message schedule
  for (int i=0; i<4; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<4; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  // make a new buffer for the itterated hash

  Integer newmessage[1][16];

  for(int i=0; i<8; i++) {
    newmessage[0][i] = H[i];
  }

  newmessage[0][8] = Integer(32, 2147483648/*0x80000000*/, PUBLIC);
  for(int i=9; i<15; i++) {
    newmessage[0][i] = Integer(32, 0/*0x00000000*/, PUBLIC);
  }
  newmessage[0][15] = Integer(32, 256, PUBLIC);

  computeSHA256_1d(newmessage, result);
}

void computeDoubleSHA256_5d(Integer message[5][16], Integer result[8]) {

  // initialize constants and initial hash digest value
  Integer k[64];
  Integer H[8];
  Integer w[5][64];
  // initialize message schedule
  for (int i=0; i<5; i++) {
    for(size_t t=0; t<16; t++) {
      w[i][t] = message[i][t];
    }
  }

  initSHA256(k, H);

  for (int i=0; i<5; i++) {
    computeInnerHashBlock(k, H, w[i]);
  }

  // make a new buffer for the itterated hash

  Integer newmessage[1][16];

  for(int i=0; i<8; i++) {
    newmessage[0][i] = H[i];
  }

  newmessage[0][8] = Integer(32, 2147483648/*0x80000000*/, PUBLIC);
  for(int i=9; i<15; i++) {
    newmessage[0][i] = Integer(32, 0/*0x00000000*/, PUBLIC);
  }
  newmessage[0][15] = Integer(32, 256, PUBLIC);

  computeSHA256_1d(newmessage, result);
}

void printInteger(Integer intToPrint, int bitSize) {

  for (int i = bitSize - 1; i >= 0; i--) {
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

string SHA256HashString(string msg);
// string run_secure_sha256(string msg, uint blocks, Version test_type);

void run_secure_hmac(Integer sec_blocks[1][16], Integer final[8]);
string test_output(Integer result[8]);


// this is not actually random because I don't seed rand().
// so it produces the same output every time it's compiled.
// would be cool to get something that the same for both parties, but different
// per compilation
// It's also not uniform because of our sketchy modding.
string gen_random(const int len) {
  static const char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";

  string s = "";
  for (int i = 0; i < len; ++i) {
    s += alphanum[rand() % (sizeof(alphanum) - 1)];
  }
  return s;
}


// reference sha256 implementation by CryptoPP
string SHA256HashString(string msg){
  string digest;
  CryptoPP::SHA256 hash;

  CryptoPP::StringSource foo(msg, true,
      new CryptoPP::HashFilter(hash,
        new CryptoPP::HexEncoder (
          new CryptoPP::StringSink(digest))));

  return digest;
}

// Pad the input to a multiple of 512 bits, and add the length
// in binary to the end.
// This was implemented by Jerry Coffin from StackExchange
string padSHA256(string const &input) {
  static const size_t block_bits = 512;
  uint64_t length = input.size() * 8 + 1;
  size_t remainder = length % block_bits;
  size_t k = (remainder <= 448) ? 448 - remainder : 960 - remainder;
  std::string padding("\x80");
  padding.append(std::string(k/8, '\0'));
  --length;

  for (int i=sizeof(length)-1; i>-1; i--) {
    unsigned char bc = length >> (i*8) & 0xff;
    padding.push_back(bc);
  }
  std::string ret(input+padding);
  return ret;
}

// Integer composeSHA256result(Integer result[8]) {
//   Integer thirtytwo(256, 32, PUBLIC);
//   result[0].resize(256, false);
//   Integer hash = result[0];
//   for(int i=1; i<8; i++) {
//     result[i].resize(256, false);
//     hash = (hash << thirtytwo) | result[i];
//   }
//   return hash;
// }

void resize_blocks(Integer input[64], Integer resized[16]) {
  for (int i = 0; i < 16; i++) {
    Integer temp = input[i * 4].resize(32, false);
    resized[i] = temp;
  
    for (int j = 1; j < 4; j++) {
      input[(4*i) + j].resize(32,false);
      resized[i] = (resized[i] << 8) | input[(4*i)+j];
    }
  }
}

// test sha256 implementation 
void run_secure_hmac(Integer key_blocks[16], Integer sec_blocks[2][16], Integer final[8]) {
  Integer pad1[64]; 
  Integer pad2[64];
  Integer pad1_resized[16];
  Integer pad2_resized[16];

  for (int i = 0; i < 64; i++) {
    pad1[i] = Integer(8, 0x36, PUBLIC);
    pad2[i] = Integer(8, 0x5c, PUBLIC);
  }

  for (int i =0 ; i < 16; i ++) {
    pad1_resized[i] = Integer(32,0,PUBLIC);
    pad2_resized[i] = Integer(32,0,PUBLIC);
  }

  resize_blocks(pad1, pad1_resized);
  resize_blocks(pad2, pad2_resized);

  Integer opad[16];
  Integer ipad[16];  

  for (int i = 0; i < 16; i++) {
    ipad[i] = key_blocks[i] ^ pad1_resized[i];
    opad[i] = key_blocks[i] ^ pad2_resized[i];
  }

  for (int i = 0; i < 16; i++) {
    sec_blocks[0][i] = ipad[i];
  }
  sec_blocks[1][8] = Integer(32,0x80000000,PUBLIC);
  sec_blocks[1][15] = Integer(32,0x300,PUBLIC);

  Integer innerSHA[8];    
  for (int i =0 ; i < 8; i ++) {
    innerSHA[i] = Integer(32,0,PUBLIC);
  }
  computeSHA256_2d(sec_blocks, innerSHA);

  Integer sec_blocks_2[2][16];

  for (int t=0; t < 16; t++) {
    sec_blocks_2[0][t] = opad[t];
  }

  for (int t=0; t < 8; t++) {
    sec_blocks_2[1][t] = innerSHA[t];
    sec_blocks_2[1][t+8] = Integer(32,0,PUBLIC);
  }
  sec_blocks_2[1][8] = Integer(32,0x80000000,PUBLIC);
  sec_blocks_2[1][15] = Integer(32,0x300,PUBLIC);

  computeSHA256_2d(sec_blocks_2, final);

}


void strToBlocks(string msg, uint msg_blocks[1][16]) {
  int blocks = 1;


  // pad message using insecure scheme
  string padded_msg = padSHA256(msg);
  string padded_msg_hex;

  // encode message in hex using cryptopp tools
  CryptoPP::StringSource foo(padded_msg, true,
      new CryptoPP::HexEncoder (
        new CryptoPP::StringSink(padded_msg_hex)));

  // parse padded message into blocks
  assert (padded_msg_hex.length() == blocks * 128);
  string blk;
  for (uint b=0; b<blocks; b++) {
    for (int i=0; i<16; i++) {
      blk = padded_msg_hex.substr((b*128) + (i*8), 8);
      msg_blocks[b][i] = (uint) strtoul(blk.c_str(), NULL,16);
    }
  }
}

void test_known_vector2() {
  // known test vector from di-mgt.com.au
  int blocks = 2;
  string msg = "abcdefghabcdefghabcdefghabcdefgh";
  string key_str = "12345678123456781234567812345678";

  Integer key[32];
  for (int i = 0; i < 32; i++) {
    key[i] = Integer(8, key_str[i], ALICE);
  }
  
  uint msg_blocks[blocks][16];
   memset( msg_blocks, 0, blocks*16*sizeof(uint) );
  uint key_blocks[blocks][16];
   memset( key_blocks, 0, blocks*16*sizeof(uint) );

  strToBlocks(msg, msg_blocks);
  strToBlocks(key_str, key_blocks);

  Integer sec_blocks[blocks][16];
  Integer key_blocks_int[16];

  for (int t=0; t < 16; t++) {
    //sec_blocks[0][t] = Integer(BITS, key_blocks[0][t], ALICE); // key
    sec_blocks[0][t] = Integer(BITS, 0, PUBLIC);
    sec_blocks[1][t] = Integer(BITS, msg_blocks[0][t], BOB); // message 
  }

  for (int t=0; t < 8; t++) {
    //sec_blocks[0][t] = Integer(BITS, key_blocks[0][t], ALICE); // key
    key_blocks_int[t] = Integer(BITS, key_blocks[0][t], ALICE); // message 
    key_blocks_int[t+8] = Integer(BITS,0,ALICE);
  }

  Integer final[8];
  run_secure_hmac(key_blocks_int, sec_blocks, final);

cout << "HELLO>\n";

  printIntegerArray(final, 8, 32);
}

int main(int argc, char** argv) {
  // run in semihonest library
  int port, party;
  if (argc != 3) {
    cerr << "ERROR: not enough args" << endl;
    return 1;
  }
  parse_party_and_port(argv, &party, &port);
  NetIO * io = new NetIO(party==ALICE ? nullptr : "127.0.0.1", port);

  setup_semi_honest(io, party);

  // // run unit tests
  // test_components(party);
  // test_sigmas(party);
  // test_compose();

  // // run end-to-end tests
  // test_end_to_end();  
  // string msg = "abcdbcdecdefdefgefghfghighijhijk";
  // string actual = run_secure_sha256(msg, 1, SEC1);


  test_known_vector2();
// finalize_plain_prot();  

  delete io;
  return 0;
}
