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
void run_secure_hmac(Integer key_blocks[16], Integer msg[2][16], int msg_length, Integer final[8]) {
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

// Pad the input to a multiple of 512 bits, and add the length
// in binary to the end.
// This was implemented by Jerry Coffin from StackExchange
void padSHA256(Integer[16] input, int input_len, Integer[2][16] output) {
  static const size_t block_bits = 512;
  uint64_t length = (uint64_t)input_len;
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

void run_hmac(Integer key[16], Integer msg, int msg_length, Integer final[8]) {
  int blocks = 2;
  
  // Integer sec_blocks[blocks][16];
  // Integer key_blocks_int[16];

  // for (int t=0; t < 16; t++) {
  //   //sec_blocks[0][t] = Integer(BITS, key_blocks[0][t], ALICE); // key
  //   sec_blocks[0][t] = Integer(BITS, 0, PUBLIC);
  //   sec_blocks[1][t] = Integer(BITS, msg_blocks[0][t], BOB); // message 
  // }

  // for (int t=0; t < 8; t++) {
  //   //sec_blocks[0][t] = Integer(BITS, key_blocks[0][t], ALICE); // key
  //   key_blocks_int[t] = Integer(BITS, key_blocks[0][t], ALICE); // message 
  //   key_blocks_int[t+8] = Integer(BITS,0,ALICE);
  // }
  // run_secure_hmac(key_blocks_int, sec_blocks, final);
  cout << msg_length << endl;
  run_secure_hmac(key,msg, msg_length, final);
}
