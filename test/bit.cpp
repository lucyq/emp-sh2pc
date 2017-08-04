#include "emp-sh2pc/emp-sh2pc.h"
NetIO * io;
int party;

template<typename T>
void test_bit() {
	bool b[] = {true, false};
	int p[] = {PUBLIC, ALICE, BOB};

	for(int i = 0; i < 2; ++i)
		for(int j = 0; j < 3; ++j)
			for(int k = 0; k < 2; ++k)
				for (int l= 0; l < 3; ++l)  {
					{
						Bit<T> b1(b[i], p[j]);
						Bit<T> b2(b[k], p[l]);
						bool res = (b1&b2).reveal(PUBLIC);
						if(res != (b[i] and b[k])) {
							cout<<"AND" <<i<<" "<<j<<" "<<k<<" "<<l<<" "<<res<<endl;
							error("test bit error!");
						}
						res = (b1 & b1).reveal(PUBLIC);
						if (res != b[i]) {
							cout<<"AND" <<i<<" "<<j<<res<<endl;
							error("test bit error!");
						}

						res = (b1 & (!b1)).reveal(PUBLIC);
						if (res) {
							cout<<"AND" <<i<<" "<<j<<res<<endl;
							error("test bit error!");
						}

					}
					{
						Bit<T> b1(b[i], p[j]);
						Bit<T> b2(b[k], p[l]);
						bool res = (b1^b2).reveal(PUBLIC);
						if(res != (b[i] xor b[k])) {
							cout <<"XOR"<<i<<" "<<j<<" "<<k<<" "<<l<< " " <<res<<endl;
							error("test bit error!");
						}

						res = (b1 ^ b1).reveal(PUBLIC);
						if (res) {
							cout<<"XOR" <<i<<" "<<j<<res<<endl;
							error("test bit error!");
						}

						res = (b1 ^ (!b1)).reveal(PUBLIC);
						if (!res) {
							cout<<"XOR" <<i<<" "<<j<<res<<endl;
							error("test bit error!");
						}
					}
					{
						Bit<T> b1(b[i], p[j]);
						Bit<T> b2(b[k], p[l]);
						bool res = (b1^b2).reveal(XOR);
						if(party == ALICE) {
							io->send_data(&res, 1);
						} else {
							bool tmp;io->recv_data(&tmp, 1);
							res = res != tmp;
							if(res != (b[i] xor b[k])) {
								cout <<"XOR"<<i<<" "<<j<<" "<<k<<" "<<l<< " " <<res<<endl;
								error("test bit error!");
							}

						}
					}
				}
	io->flush();
	cout <<"success!"<<endl;
}

int main(int argc, char** argv) {
	int port;
	parse_party_and_port(argv, &party, &port);
	io = new NetIO(party==ALICE?nullptr:"127.0.0.1", port);
	setup_semi_honest(io, party);
	if (party == ALICE)
		test_bit< HalfGateGen<NetIO> >();
	else test_bit< HalfGateEva<NetIO> >();
	delete io;
}
