#include "hestd.h"


using namespace std;
using namespace hestd;

int main(int argc, char *argv[]) {

	std::ifstream fin("demoData/cryptocontext0.txt");
	
	HEStdContext context(fin,"profile");

	std::cerr << "\nLoaded profile..." << std::endl;

	context.keyGen();

	std::cerr << "All keys have been generated..." << std::endl;

	std::vector<uint64_t> vectorOfInts1 = {1,2,3,4,5,6,7,8,9,10,11,12};
	Plaintext plaintext1 = context.CreatePlaintext(vectorOfInts1);

	std::vector<uint64_t> vectorOfInts2 = {12,11,10,9,8,7,6,5,4,3,2,1};
	Plaintext plaintext2 = context.CreatePlaintext(vectorOfInts2);

	Ciphertext ct1 = context.CreateCiphertext();
	Ciphertext ct2 = context.CreateCiphertext();

	context.encrypt(plaintext1,ct1);
	context.encrypt(plaintext2,ct2);
	std::cerr << "Encryption is completed..." << std::endl;

	Ciphertext ctAdd = context.CreateCiphertext();
	context.evalAdd(ct1,ct2,ctAdd);
	std::cerr << "Homomorphic addition is done..." << std::endl;

	Plaintext ptAdd = context.CreatePlaintext();
	context.decrypt(ctAdd,ptAdd);
	std::cerr << "Decryption is done..." << std::endl;

	std::cerr << "result = " << *ptAdd << std::endl;

	return 0;
}
