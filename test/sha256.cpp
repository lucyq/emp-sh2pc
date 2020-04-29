#include "hmac_optimized.h"


// #include <typeinfo>
// #include "emp-sh2pc/emp-sh2pc.h"
// #include "hmac_optimized.h"
// using namespace emp;
// using namespace std;



// /* computes sha256 for 3-block message
//  * output is stored in result
//  * composed of 8 32-bit Integers such that
//  * sha256(message) = result[0] || result[1] || ... || result[7]
//  */
// void computeSHA256_3d(Integer message[3][16], Integer result[8]) {

//   // initialize constants and initial hash digest value
//   Integer k[64];
//   Integer H[8];
//   Integer w[3][64];
//   // initialize message schedule
//   for (int i=0; i<3; i++) {
//     for(size_t t=0; t<16; t++) {
//       w[i][t] = message[i][t];
//     }
//   }

//   initSHA256(k, H);

//   for (int i=0; i<3; i++) {
//     computeInnerHashBlock(k, H, w[i]);
//   }

//   for(int i=0; i<8; i++) {
//     result[i] = H[i];
//   }
// }

// void computeSHA256_4d(Integer message[4][16], Integer result[8]) {
//   // initialize constants and initial hash digest value
//   Integer k[64];
//   Integer H[8];
//   Integer w[4][64];
//   // initialize message schedule
//   for (int i=0; i<4; i++) {
//     for(size_t t=0; t<16; t++) {
//       w[i][t] = message[i][t];
//     }
//   }

//   initSHA256(k, H);

//   for (int i=0; i<4; i++) {
//     computeInnerHashBlock(k, H, w[i]);
//   }

//   for(int i=0; i<8; i++) {
//     result[i] = H[i];
//   }
// }

// void computeSHA256_5d(Integer message[5][16], Integer result[8]) {
//   // initialize constants and initial hash digest value
//   Integer k[64];
//   Integer H[8];
//   Integer w[5][64];
//   // initialize message schedule
//   for (int i=0; i<5; i++) {
//     for(size_t t=0; t<16; t++) {
//       w[i][t] = message[i][t];
//     }
//   }

//   initSHA256(k, H);

//   for (int i=0; i<5; i++) {
//     computeInnerHashBlock(k, H, w[i]);
//   }

//   for(int i=0; i<8; i++) {
//     result[i] = H[i];
//   }
// }



// void computeDoubleSHA256_3d(Integer message[3][16], Integer result[8]) {

//   // initialize constants and initial hash digest value
//   Integer k[64];
//   Integer H[8];
//   Integer w[3][64];
//   // initialize message schedule
//   for (int i=0; i<3; i++) {
//     for(size_t t=0; t<16; t++) {
//       w[i][t] = message[i][t];
//     }
//   }

//   initSHA256(k, H);

//   for (int i=0; i<3; i++) {
//     computeInnerHashBlock(k, H, w[i]);
//   }

//   // for(int i=0; i<8; i++) {
//   //   result[i] = H[i];
//   // }

//   // make a new buffer for the itterated hash

//   Integer newmessage[1][16];

//   for(int i=0; i<8; i++) {
//     newmessage[0][i] = H[i];
//   }

//   newmessage[0][8] = Integer(32, 2147483648/*0x80000000*/, PUBLIC);
//   for(int i=9; i<15; i++) {
//     newmessage[0][i] = Integer(32, 0/*0x00000000*/, PUBLIC);
//   }
//   newmessage[0][15] = Integer(32, 256, PUBLIC);

//   computeSHA256_1d(newmessage, result);
// }


// void computeDoubleSHA256_4d(Integer message[4][16], Integer result[8]) {

//   // initialize constants and initial hash digest value
//   Integer k[64];
//   Integer H[8];
//   Integer w[4][64];
//   // initialize message schedule
//   for (int i=0; i<4; i++) {
//     for(size_t t=0; t<16; t++) {
//       w[i][t] = message[i][t];
//     }
//   }

//   initSHA256(k, H);

//   for (int i=0; i<4; i++) {
//     computeInnerHashBlock(k, H, w[i]);
//   }

//   // make a new buffer for the itterated hash

//   Integer newmessage[1][16];

//   for(int i=0; i<8; i++) {
//     newmessage[0][i] = H[i];
//   }

//   newmessage[0][8] = Integer(32, 2147483648/*0x80000000*/, PUBLIC);
//   for(int i=9; i<15; i++) {
//     newmessage[0][i] = Integer(32, 0/*0x00000000*/, PUBLIC);
//   }
//   newmessage[0][15] = Integer(32, 256, PUBLIC);

//   computeSHA256_1d(newmessage, result);
// }

// void computeDoubleSHA256_5d(Integer message[5][16], Integer result[8]) {

//   // initialize constants and initial hash digest value
//   Integer k[64];
//   Integer H[8];
//   Integer w[5][64];
//   // initialize message schedule
//   for (int i=0; i<5; i++) {
//     for(size_t t=0; t<16; t++) {
//       w[i][t] = message[i][t];
//     }
//   }

//   initSHA256(k, H);

//   for (int i=0; i<5; i++) {
//     computeInnerHashBlock(k, H, w[i]);
//   }

//   // make a new buffer for the itterated hash

//   Integer newmessage[1][16];

//   for(int i=0; i<8; i++) {
//     newmessage[0][i] = H[i];
//   }

//   newmessage[0][8] = Integer(32, 2147483648/*0x80000000*/, PUBLIC);
//   for(int i=9; i<15; i++) {
//     newmessage[0][i] = Integer(32, 0/*0x00000000*/, PUBLIC);
//   }
//   newmessage[0][15] = Integer(32, 256, PUBLIC);

//   computeSHA256_1d(newmessage, result);
// }

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

  string msg = "3358a33dc1ab0a9f1386124d439f5182";
  string key_str = "ad027ffb7e71c2dfe6019e90ee200fc0e70ffc1e175d793b22b26081dc75a761";

  // run_hmac(msg, key_str);

  delete io;
  return 0;
}
