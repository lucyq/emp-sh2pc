#include <typeinfo>
#include "emp-sh2pc/emp-sh2pc.h"
using namespace emp;
using namespace std;

const int BITS = 32;

/* implementation of SHA256 from FIPS PUB 180-4 
 * with the following modifications
 * - processes only a fixed length input. We've hardcoded it for 1, 2, or 3 blocks
 * - assumes padding already exists
 */

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHR32(x, n) ((x) >> (n))

#define SIGMA_UPPER_0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SIGMA_UPPER_1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIGMA_LOWER_0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ SHR32(x, 3))
#define SIGMA_LOWER_1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ SHR32(x, 10))

Integer ROR32(Integer x, Integer n);
Integer ROR32(Integer x, uint n);
uint ROR32(uint x, uint n);

/* FIPS PUB 180-4 -- 4.2.2
 *
 * "These words represent the first thirty-two bits of the fractional parts of
 *  the cube roots of the first sixty-four prime numbers"
 */
static const uint32_t k_clear[64] = {
  0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
  0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
  0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
  0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
  0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
  0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
  0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
  0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};


/* FIPS PUB 180-4 -- 5.3.3
 *
 * Initial hash value
 * "These words were obtained by taking the first thirty-two bits of the fractional parts of the 
 *  square roots of the first eight prime numbers"
 */
static const uint32_t IV_clear[8] = {
  0x6A09E667 , 0xBB67AE85 , 0x3C6EF372 , 0xA54FF53A , 
  0x510E527F , 0x9B05688C , 0x1F83D9AB , 0x5BE0CD19
};


void initSHA256(Integer k[64], Integer H[8]); 
string get_bitstring(Integer x);
Integer composeSHA256result(Integer result[8]);


/* computes sha256 for a 2-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 */
void computeSHA256_2l(uint message[2][16], Integer result[8]);

/* computes sha256 for a 2-block message
 * output is stored in result
 * composed of 8 32-bit Integers such that
 * sha256(message) = result[0] || result[1] || ... || result[7]
 * this takes already distributed variables.
 */
void computeSHA256_1d(Integer message[1][16], Integer result[8]);
void computeSHA256_2d(Integer message[2][16], Integer result[8]);
void computeSHA256_3d(Integer message[3][16], Integer result[8]);



////////////



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

// void printInteger(Integer intToPrint, int bitSize) {

//   for (int i = bitSize - 1; i >= 0; i--) {
//     cout << intToPrint[i].reveal();
//   }
//   return;
// }

// void printIntegerArray(Integer* intToPrint, int arraySize, int bitSize) {
//   for(int i = 0; i < arraySize; i++) {
//     printInteger(intToPrint[i], bitSize);
//     cout << ", ";
//   }
//   cout << endl;
//   return;
// }



string SHA256HashString(string msg);
// string run_secure_sha256(string msg, uint blocks, Version test_type);

//void run_secure_hmac(Integer sec_blocks[1][16], Integer final[8]);
string test_output(Integer result[8]);

//8 bit to 32 bit resize 
void resize_blocks(Integer* input, Integer* output) {
  // cout << "RESIZE BLOCKS" << endl;
  // printIntegerArray(input,128,8);
  for (int i = 0; i < 32; i++) {
    // cout << "TEMP VALUES" << endl;
    Integer temp = (input[i * 4].resize(32,0) << 24) >> 24;
    Integer temp2 = (input[4 * i + 1].resize(32,0) << 24) >> 24;
    Integer temp3 = (input[4 * i + 2].resize(32,0) << 24) >> 24;
    Integer temp4 = (input[4 * i + 3].resize(32,0) << 24) >> 24;
    // printInteger(temp,32);
    // cout << endl;
    // printInteger(temp2,32);
    // cout << endl;
    // printInteger(temp3,32);
    // cout << endl;
    // printInteger(temp4,32);
    // cout << endl;

    Integer newint = (temp << 24) | (temp2 << 16) | (temp3 << 8) | (temp4);
    output[i] = newint;
    // printInteger(output[i],32);
    // cout << endl; 
  }
  // cout << "RESIZE BLOCKS" << endl;
  // printIntegerArray(output,32,32);
}

//32 bit to 8 bit resize
void resize_blocks2(Integer* input, int input_len, Integer* resized) {
  for (int i = 0; i < input_len; i++) {
    Integer CP1 = (input[i] & Integer(32,0xff000000,PUBLIC)) >> 24;
    Integer CP2 = (input[i] & Integer(32,0x00ff0000,PUBLIC)) >> 16;
    Integer CP3 = (input[i] & Integer(32,0x0000ff00,PUBLIC)) >>  8;
    Integer CP4 = (input[i] & Integer(32,0x000000ff,PUBLIC));

    resized[4*i] = CP1;
    resized[4*i+1] = CP2;
    resized[4*i+2] = CP3;
    resized[4*i+3] = CP4;
  }
}

// Pad the input to a multiple of 512 bits, and add the length
// in binary to the end.
// This was implemented by Jerry Coffin from StackExchange
void padSHA256_int(Integer* input, int input_len, Integer output[2][16]) { // 8 bit Integers
  // cout << "INSIDE PAD" << endl;
  // printIntegerArray(input,input_len,8);
  static const size_t block_bits = 512;
  uint64_t length = input_len * 8 + 1; // input_len is bits
  size_t remainder = length % block_bits;
  size_t k = (remainder <= 448) ? 448 - remainder : 960 - remainder;
  Integer temp[128]; // 128 * 8 = 1024 
  for (int i =0 ; i < input_len; i ++) {
    temp[i] = input[i];
  }
  temp[input_len] = Integer(8,0x80,PUBLIC);
  for (int i= input_len + 1; i < 128; i++) {
    temp[i] = Integer(8,0,PUBLIC);
  }
  int a = (input_len*8)%256;
  int b = (input_len*8 - a)/256;
  // cout << a << "," << b << endl;
  temp[127] = Integer(8,a,PUBLIC);
  temp[126] = Integer(8,b,PUBLIC);
  Integer temp2[32];
  for (int i= 0; i < 32; i++) {
    temp2[i] = Integer(32,0,PUBLIC);
  }
  // cout << "TEMP " << endl;
  // printIntegerArray(temp,128,8);
  resize_blocks(temp,temp2);
  // cout << "TEMP2" << endl;
  // printIntegerArray(temp2,32,32);

  for (int i = 0; i < 2; i++) {
    for (int j = 0; j < 16; j++) {
      output[i][j] = temp2[16*i + j];
    }
  }

}

// test sha256 implementation 
Integer* run_secure_hmac(Integer* key, int key_length, Integer* msg, int msg_length) {
  static Integer final[32];
  Integer key_resized[64]; 
  for (int i = 0; i < key_length; i++) {
    key_resized[i] = key[i];
  }
  for (int i = key_length; i < 64; i++) {
    key_resized[i] = Integer(8,0,PUBLIC);
  }

  Integer pad1[64]; 
  Integer pad2[64];

  for (int i = 0; i < 64; i++) {
    pad1[i] = Integer(8, 0x36, PUBLIC);
    pad2[i] = Integer(8, 0x5c, PUBLIC);
  }
  Integer opad[64];
  Integer ipad[64];  

  for (int i = 0; i < 64; i++) {
    ipad[i] = key_resized[i] ^ pad1[i];
    opad[i] = key_resized[i] ^ pad2[i];
  }

  Integer innerhash[64+msg_length];
  Integer innerPadOutput[2][16];
  for (int i = 0; i < 64; i++) {
    innerhash[i] = ipad[i];
  }
  for (int i = 64; i < 64 + msg_length; i++) {
    innerhash[i] = msg[i-64];
  }

  // cout << "PAD1" << endl;
  padSHA256_int(innerhash,64+msg_length,innerPadOutput);

  Integer innerSHA[8]; // 32 * 8    
  for (int i =0 ; i < 8; i ++) {
    innerSHA[i] = Integer(32,0,PUBLIC);
  }
  computeSHA256_2d(innerPadOutput, innerSHA);

  Integer innerSHAresized[32];
  for (int i = 0; i < 32; i ++) {
    innerSHAresized[i] = Integer(8,0,PUBLIC);
  }
  resize_blocks2(innerSHA,8,innerSHAresized);

  Integer outerhash[64+32];
  Integer outerPadOutput[2][16];

  for (int i = 0; i < 64; i++) {
    outerhash[i] = opad[i];
  }
  for (int i = 64; i < 64 + 32; i++) {
    outerhash[i] = innerSHAresized[i-64];
  }
  // cout << "PAD2" << endl;
  padSHA256_int(outerhash,64+32,outerPadOutput);

  Integer outerSHA[8]; // 32 * 8    
  for (int i =0 ; i < 8; i ++) {
    outerSHA[i] = Integer(32,0,PUBLIC);
  }
  computeSHA256_2d(outerPadOutput, outerSHA);

  resize_blocks2(outerSHA,8,final);
  return final;
}

void strToBlocks(string padded_msg_hex, uint msg_blocks[1][16], int msg_length) { // 16 or 32 
  string blk;
  for (int i=0; i< (msg_length/4); i++) {
    blk = padded_msg_hex.substr((0) + (i*8), 8);
    msg_blocks[0][i] = (uint) strtoul(blk.c_str(), NULL,16);
  }
  for (int i= (msg_length/4); i < 16; i++) {
    msg_blocks[0][i] = (uint)00000000;
  }
}

void run_hmac(Integer* key, int key_length, Integer* msg, int msg_length) {
  int blocks = 2;
  cout << msg_length << endl;
  run_secure_hmac(key,key_length,msg, msg_length);
}
