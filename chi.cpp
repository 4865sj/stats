#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <iostream>
#include <math.h>
#include <time.h>
#include "helper_tfhe.h"
#include "HomOper.cpp"

using namespace std;


int main() {
	//generate a keyset
	const int minimum_lambda = 128;
	TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

	//generate a random key
	uint32_t seed[] = {314, 1592, 657};
	tfhe_random_generator_setSeed(seed, 3);
	TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);

	//export the secret key to file for later use
	FILE* secret_key = fopen("secret.key", "wb");
	export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
	fclose(secret_key);

	//export the cloud key to a file (for the cloud)
	FILE* cloud_key = fopen("cloud.key", "wb");
	export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
	fclose(cloud_key);

	//reads the cloud key from file
	FILE* cloud_key2 = fopen("cloud.key", "rb");
	TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key2);
	fclose(cloud_key2);

	//set data properties
	int length = 32;
	int num_data = 10;
	
	cout << "Encoding and Encrypting" << endl;

	//set dataset (observation, expectation)
	double observation[10] = {1.00000, 2.00000, 3.00000, 4.00000, 5.00000, 6.00000, 7.00000, 8.00000, 9.00000, 10.00000};
	double expectation[10] = {10.00000, 9.00000, 8.00000, 7.00000, 6.00000, 5.00000, 4.00000, 3.00000, 2.00000, 1.00000};

	//encode data to plaintexts
	int16_t plaintext1[num_data];
	for(int i = 0; i < num_data; i++) {
		plaintext1[i] = encode_double_t16(length, observation[i]);
	}

	int16_t plaintext2[num_data];
	for(int i = 0; i < num_data; i++) {
		plaintext2[i] = encode_double_t16(length, expectation[i]);
	}

	//plaintexts to ciphertexts: plaintext bit-by-bit encryption to ciphertext
	LweSample* ciphertext1[num_data];
	for(int i = 0; i < num_data; i++) {
		ciphertext1[i] = new_gate_bootstrapping_ciphertext_array(length, params);
	}
	for(int i = 0; i < num_data; i++) {
		for(int j = 0; j < length; j++) {
			bootsSymEncrypt(&ciphertext1[i][j], (plaintext1[i]>>j)&1, key);
		}
	}

        LweSample* ciphertext2[num_data];
        for(int i = 0; i < num_data; i++) {
                ciphertext2[i] = new_gate_bootstrapping_ciphertext_array(length, params);
	}
	for(int i = 0; i < num_data; i++) {
                for(int j = 0; j < length; j++) {
                        bootsSymEncrypt(&ciphertext2[i][j], (plaintext2[i]>>j)&1, key);
		}
	}
	
	cout << "Calculate chi_squared" << endl;

	LweSample* chi = new_gate_bootstrapping_ciphertext_array(length, params);
    
	float time = -clock();

	ChiSquared(chi, ciphertext1, ciphertext2, num_data, length, bk);

	time += clock();
	time = time/(CLOCKS_PER_SEC);
	printf("done in %f seconds...\n", time);

	double double_answer;
	int int_answer = 0;
        for(int j = 0; j < length; j++)
        {
            int ai = bootsSymDecrypt(&chi[j], key);
            int_answer |= (ai<<j);
        }
        double_answer = int_answer * (1.0/(1<<(int)(length/2)));	

	cout << "chi: " << double_answer << endl;
	
	for (int i = 0; i < num_data; i++) {
	delete_gate_bootstrapping_ciphertext_array(length, ciphertext1[i]);
	delete_gate_bootstrapping_ciphertext_array(length, ciphertext2[i]);
	}
	delete_gate_bootstrapping_ciphertext_array(length, chi);

	delete_gate_bootstrapping_secret_keyset(key);
	delete_gate_bootstrapping_parameters(params);

	double chi_origin = 0.00;

	for (int i = 0; i < num_data; i++) {
	chi_origin += pow(observation[i] - expectation[i],2)/expectation[i];
	}

	cout << "chi_orgin: " << chi_origin << endl;
}
