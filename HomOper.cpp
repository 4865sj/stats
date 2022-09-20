#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>


void HomAND(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {   
	// LweSample* temp = new_gate_bootstrapping_ciphertext_array(1, bk->params);	    

	for(int i = 0; i < length; i++){
		bootsAND(&res[i], &a[i], &b[i], bk);}
}


void HomAND2(LweSample* res, const LweSample* a, const int N, const TFheGateBootstrappingCloudKeySet* bk) {   
	// LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
		    
	bootsCOPY(res, &a[0], bk);

	for(int i = 0; i < N-1; i++){
		bootsAND(res, res, &a[i+1], bk);
	}
}


void HomCompG(LweSample* res, LweSample* a, LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	
	bootsCONSTANT(&temp[0], 0, bk);
	
	for(int i = 0; i < length; i++){
		bootsXNOR(&temp[1], &a[i], &b[i], bk);
		bootsMUX(&temp[0], &temp[1], &temp[0], &a[i], bk);
	}

	bootsCOPY(&res[0], &temp[0], bk);
	delete_gate_bootstrapping_ciphertext_array(2, temp);
}


void HomCompG2(LweSample* res, LweSample** a, LweSample** b, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {
	
	for(int i = 0; i < N; i++){
		HomCompG(&res[i], a[i], b[i], length, bk);
	}
}


void HomCompGE(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	
	bootsCONSTANT(&temp[0], 0, bk);
	
	for(int i = 0; i < length; i++){
		bootsXNOR(&temp[1], &a[i], &b[i], bk);
		bootsMUX(&temp[0], &temp[1], &temp[0], &b[i], bk);}

	bootsNOT(&res[0], &temp[0], bk);
	delete_gate_bootstrapping_ciphertext_array(2, temp);
}


void HomCompGE2(LweSample* res, LweSample** a, LweSample** b, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {
	
	for(int i = 0; i < N; i++){
		HomCompGE(&res[i], a[i], b[i], length, bk);
	}
}


void HomCompLE(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) { // a <= b -> 1

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	
	bootsCONSTANT(&temp[0], 0, bk);
	
	for(int i = 0; i < length; i++){
		bootsXNOR(&temp[1], &a[i], &b[i], bk);
		bootsMUX(&temp[0], &temp[1], &temp[0], &a[i], bk);}

	bootsNOT(&res[0], &temp[0], bk);
	delete_gate_bootstrapping_ciphertext_array(2, temp);
}


void HomCompLE2(LweSample* res, LweSample** a, LweSample** b, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {
	
	for(int i = 0; i < N; i++){
		HomCompLE(&res[i], a[i], b[i], length, bk);
	}
}


void HomEqui(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);	    

	bootsCONSTANT(&temp[0], 1, bk);
	for(int i = 0; i < length; i++){		
		bootsXNOR(&temp[1], &a[i], &b[i], bk);
		bootsAND(&temp[0], &temp[0], &temp[1], bk);
		
	}
	bootsCOPY(&res[0], &temp[0], bk);

	delete_gate_bootstrapping_ciphertext_array(2, temp);
}


void HomEqui2(LweSample* res, LweSample** a, LweSample** b, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {
	
	for(int i = 0; i < N; i++){
		HomEqui(&res[i], a[i], b[i], length, bk);
	}
}



void HomAdd(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* c = new_gate_bootstrapping_ciphertext_array(length, bk->params);	    
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);	    

	bootsCONSTANT(&c[0], 0, bk);
    
	for(int i = 0; i < length -1; i++){
		bootsXOR(&temp[0], &a[i], &b[i], bk);
		bootsAND(&temp[1], &a[i], &b[i], bk);
		bootsXOR(&res[i], &temp[0], &c[i], bk);
		bootsAND(&temp[0], &temp[0], &c[i], bk);
		bootsOR(&c[i+1], &temp[0], &temp[1], bk);
	}

	bootsXOR(&temp[0], &a[length-1], &b[length-1], bk);
	bootsXOR(&res[length-1], &temp[0], &c[length-1], bk);

	delete_gate_bootstrapping_ciphertext_array(length, c);    
	delete_gate_bootstrapping_ciphertext_array(2, temp);    
}


void HomSubt(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

    LweSample* c = new_gate_bootstrapping_ciphertext_array(length, bk->params);       
    LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);       

    bootsCONSTANT(&c[0], 0, bk);
    
    for(int i = 0; i < length -1; i++){
        bootsXOR(&temp[0], &a[i], &b[i], bk);
        bootsANDNY(&temp[1], &a[i], &b[i], bk);
        bootsXOR(&res[i], &temp[0], &c[i], bk);
        bootsANDNY(&temp[0], &temp[0], &c[i], bk);
        bootsOR(&c[i+1], &temp[1], &temp[0], bk);}

    bootsXOR(&temp[0], &a[length-1], &b[length-1], bk);
    bootsXOR(&res[length-1], &temp[0], &c[length-1], bk);

    delete_gate_bootstrapping_ciphertext_array(length, c);   
    delete_gate_bootstrapping_ciphertext_array(2, temp);   
} 


void HomLShift(LweSample* res, const LweSample* a, const int length, const int k, const TFheGateBootstrappingCloudKeySet* bk) {

	for(int i = 0; i < length - k; i++){
		bootsCOPY(&res[i], &a[i+k], bk);}
	for(int i = length-k; i < length; i++){
		bootsCOPY(&res[i], &a[length-1], bk);}
}


void HomRShift(LweSample* res, const LweSample* a, const int length, const int k, const TFheGateBootstrappingCloudKeySet* bk) {

    bootsCOPY(&res[length-1], &a[length-1], bk);
    for(int i = length-2; i > k-1; i--){
        bootsCOPY(&res[i], &a[i-k], bk);}
    for(int i = 0; i < k; i++){
        bootsCONSTANT(&res[i], 0, bk);}
} 


void HomTwosComplement(LweSample* res, const LweSample* a, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(1, bk->params);	    
	LweSample* b = new_gate_bootstrapping_ciphertext_array(length, bk->params);	    

	bootsCONSTANT(&b[0], 1, bk);
    

	for(int i = 0; i < length - 2; i++){
		bootsNOT(&temp[0], &a[i], bk);
		bootsXOR(&res[i], &temp[0], &b[i], bk);
		bootsAND(&b[i+1], &temp[0], &b[i], bk);}

	bootsNOT(&temp[0], &a[length-2], bk);
	bootsXOR(&res[length-2], &temp[0], &b[length-2], bk);

	bootsNOT(&res[length-1], &a[length-1], bk);
	

	delete_gate_bootstrapping_ciphertext_array(length, b);    
	delete_gate_bootstrapping_ciphertext_array(1, temp);    
}


void HomAbs(LweSample* res, const LweSample* a, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* na = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	HomTwosComplement(na, a, length, bk);
	
	for(int i = 0; i < length; i++){
		bootsMUX(&res[i], &a[length-1], &na[i], &a[i], bk);}

	delete_gate_bootstrapping_ciphertext_array(length, na);
}


void HomMultiReal(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
	
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* AA = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* B = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* C = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* D = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* E = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* F = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	
	HomAbs(A, a, length, bk);
	HomAbs(B, b, length, bk);
	for(int i = 0; i < length; i++){
		bootsAND(&AA[i], &A[i], &B[0], bk);}
	HomLShift(AA, AA, length, length/2, bk);	


	
	for(int i = 1; i < length-1; i++){
		if(i < length/2){
			HomLShift(C, A, length, length/2-i, bk);

			for(int j = 0; j < length; j++)
				bootsAND(&D[j], &C[j], &B[i], bk);

			HomAdd(AA, AA, D, length, bk);
		}
		else if(i == length/2){
			for(int j = 0; j < length; j++)
				bootsAND(&D[j], &A[j], &B[i], bk);

			HomAdd(AA, AA, D, length, bk);
		}

		else {
			HomRShift(C, A, length, i-length/2, bk);
			for(int j = 0; j < length; j++){
				bootsAND(&D[j], &C[j], &B[i], bk);}

			HomAdd(AA, AA, D, length, bk);
		}

	}
	bootsCONSTANT(&AA[length-1], 0, bk);

	HomTwosComplement(D, AA, length, bk);
	
	bootsXOR(&temp[0], &a[length-1], &b[length-1], bk);
	bootsNOT(&temp[1], &temp[0], bk);

	for(int i = 0; i < length; i++){
		bootsAND(&E[i], &AA[i], &temp[1], bk);
		bootsAND(&F[i], &D[i], &temp[0], bk);}

	HomAdd(res, E, F, length, bk);

	delete_gate_bootstrapping_ciphertext_array(2, temp);
	delete_gate_bootstrapping_ciphertext_array(length, A);
	delete_gate_bootstrapping_ciphertext_array(length, AA);
	delete_gate_bootstrapping_ciphertext_array(length, B);
	delete_gate_bootstrapping_ciphertext_array(length, C);
	delete_gate_bootstrapping_ciphertext_array(length, D);
	delete_gate_bootstrapping_ciphertext_array(length, E);
	delete_gate_bootstrapping_ciphertext_array(length, F);
}


void HomRealDiv(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
	
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(3, bk->params);
	LweSample* A = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* B = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* QR = new_gate_bootstrapping_ciphertext_array(2*length, bk->params);
	LweSample* D = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* C = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* Q = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* DD = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* R = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* E0 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	
	HomAbs(A, a, length, bk);
	HomAbs(B, b, length, bk);
	//printf("absolute value clear\n");

	for(int i = 0; i < length; i++){
		bootsCOPY(&QR[i], &A[i], bk);
		bootsCOPY(&D[i], &B[i], bk);
		bootsCONSTANT(&QR[length + i], 0, bk);}
	

	HomRShift(QR, QR, 2*length, 1, bk);
//	printf("stting clear\n");
	for(int s = 1; s < length; s++){
		HomRShift(QR, QR, 2*length, 1, bk);

		for(int i = 0; i < length; i++){
			bootsCOPY(&R[i], &QR[length+i], bk);}

		HomCompLE(&temp[0], R, D, length, bk);
		bootsNOT(&temp[1], &temp[0], bk);
		bootsCOPY(&QR[0], &temp[1], bk);

		for(int i = 0; i < length; i++){
			bootsAND(&DD[i], &D[i], &temp[1], bk);}

		HomSubt(R, R, DD, length, bk);

		for(int i = 0; i < length; i++){
			bootsCOPY(&QR[length+i], &R[i], bk);}
		
//		printf("%d loop clear\n",s);
	}
	

	for(int s = length; s < length*3/2; s++){
		HomRShift(QR, QR, 2*length, 1, bk);
		HomRShift(R, R, length, 1, bk);

		HomCompLE(&temp[0], R, D, length, bk);
		bootsNOT(&temp[1], &temp[0], bk);
		bootsCOPY(&QR[0], &temp[1], bk);

		for(int i = 0; i < length; i++){
			bootsAND(&DD[i], &D[i], &temp[1], bk);}

		HomSubt(R, R, DD, length, bk);

		
//		printf("%d loop clear\n",s);
	}


	for(int i = 0; i < length; i++){
		bootsCOPY(&Q[i], &QR[i], bk);}
//		bootsCOPY(&res[i], &QR[i], bk);}


	HomTwosComplement(C, Q, length, bk);
	
	bootsXOR(&temp[0], &a[length-1], &b[length-1], bk);
	for (int i = 0; i < length; i++){
		bootsMUX(&res[i], &temp[0], &C[i], &Q[i], bk);
	}
	
	
	delete_gate_bootstrapping_ciphertext_array(3, temp);
	delete_gate_bootstrapping_ciphertext_array(length, A);
	delete_gate_bootstrapping_ciphertext_array(length, B);
	delete_gate_bootstrapping_ciphertext_array(2*length, QR);
	delete_gate_bootstrapping_ciphertext_array(length, D);
	delete_gate_bootstrapping_ciphertext_array(length, DD);
	delete_gate_bootstrapping_ciphertext_array(length, Q);
	delete_gate_bootstrapping_ciphertext_array(length, R);
	delete_gate_bootstrapping_ciphertext_array(length, C);
	delete_gate_bootstrapping_ciphertext_array(length, E0);
}

void HomRealP2C(LweSample* res, const int num, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	int32_t plain = num;

	for(int i = 0; i < (length/2); i++)
		bootsCONSTANT(&res[i], 0, bk);
	for(int i = 0; i < (length/2); i++)
		bootsCONSTANT(&res[i+(length/2)], (plain>>i)&1, bk);

}


void HomMax(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	
	HomCompGE(&temp[0], a, b, length, bk);

	for(int i = 0; i < length; i++){
		bootsMUX(&res[i], &temp[0], &a[i], &b[i], bk);}

	delete_gate_bootstrapping_ciphertext_array(1, temp);
}


void HomMin(LweSample* res, const LweSample* a, const LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk) {

	LweSample* temp = new_gate_bootstrapping_ciphertext_array(1, bk->params);
	
	HomCompLE(&temp[0], a, b, length, bk);

	for(int i = 0; i < length; i++){
		bootsMUX(&res[i], &temp[0], &a[i], &b[i], bk);}

	delete_gate_bootstrapping_ciphertext_array(1, temp);
}


void HomSum(LweSample* res, LweSample** a, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {   

	for (int i = 0; i < length; i++){
		bootsCOPY(&res[i], &a[0][i], bk);
	}

	for(int i = 1; i < N; i++){
		HomAdd(res, res, a[i], length, bk);
	}
	
}


void HomMean(LweSample* res, LweSample** a, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) { 
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* EN = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* E1 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* E1_EN = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	HomRealP2C(EN, N, length, bk);
	HomRealP2C(E1, 1, length, bk);
	HomRealDiv(E1_EN, E1, EN, length, bk);

	for (int i = 0; i < N; i++){
		HomSum(temp, a, length, N, bk);
	}

	HomMultiReal(res, E1_EN, temp, length, bk);

	delete_gate_bootstrapping_ciphertext_array(length, temp);
	delete_gate_bootstrapping_ciphertext_array(length, EN);
	delete_gate_bootstrapping_ciphertext_array(length, E1);
	delete_gate_bootstrapping_ciphertext_array(length, E1_EN);
}


void HomVar(LweSample* res, LweSample** a, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {   

	LweSample* mean = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	//LweSample* temp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* V[N];
	for (int i = 0; i < N; i++){
		V[i] = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	}
	LweSample* var[N];
	for (int i = 0; i < N; i++){
		var[i] = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	}
	LweSample* EN = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* E1 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* E1_EN = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	HomRealP2C(EN, N, length, bk);
	HomRealP2C(E1, 1, length, bk);
	HomRealDiv(E1_EN, E1, EN, length, bk);

	for (int i = 0; i < N; i++){
		HomMean(mean, a, length, N, bk);
	}

	for (int i = 0; i < N; i++){
		HomSubt(V[i], a[i], mean, length, bk);
		HomMultiReal(var[i], V[i], V[i], length, bk);
		// HomSum(temp, V, length, N, bk);
	}
	HomSum(temp2, var, length, N, bk);
    HomMultiReal(res, E1_EN, temp2, length, bk);

	delete_gate_bootstrapping_ciphertext_array(length, mean);
	delete_gate_bootstrapping_ciphertext_array(length, temp2);
	for (int i =0 ; i < N ;i++){
		delete_gate_bootstrapping_ciphertext_array(length, V[i]);
	}

	for (int i =0 ; i < N ;i++){
		delete_gate_bootstrapping_ciphertext_array(length, var[i]);
	}
	delete_gate_bootstrapping_ciphertext_array(length, EN);
	delete_gate_bootstrapping_ciphertext_array(length, E1);
	delete_gate_bootstrapping_ciphertext_array(length, E1_EN);
}


//// larger ciphertext -> res1, smaller ciphertext -> res2
void BootsSort(LweSample* res1, LweSample* res2, LweSample* a, LweSample* b, const int length, const TFheGateBootstrappingCloudKeySet* bk){
	LweSample* temp = new_gate_bootstrapping_ciphertext_array(2, bk->params);

	HomCompGE(&temp[0], a, b, length, bk);
	bootsNOT(&temp[1], &temp[0], bk);

	for (int i =0; i < length; i++) {
		bootsMUX(&res1[i], &temp[0], &a[i], &b[i], bk);
		bootsMUX(&res2[i], &temp[1], &a[i], &b[i], bk);
	}

	delete_gate_bootstrapping_ciphertext_array(2, temp);
	
}


void HomSort(LweSample* res, LweSample** a, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {   
	LweSample* result = new_gate_bootstrapping_ciphertext_array(length, bk->params);

    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N-1; j++) {
            // HomMax(result, a[j], a[j+1], length, bk);
            // HomMin(res, a[j], a[j+1], length, bk);
			BootsSort(result, res, a[j], a[j+1], length, bk);

            for(int k = 0; k < length; k++)
                bootsCOPY(&a[j][k], &res[k], bk);
            for(int k = 0; k < length; k++)
                bootsCOPY(&a[j+1][k], &result[k], bk);
        }
    }
	delete_gate_bootstrapping_ciphertext_array(length, result);
}


void HomMedian(LweSample* res, LweSample** a, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {   
	LweSample* result1 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* result2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* result3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);

    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N-1; j++) {
            // HomMax(result1, a[j], a[j+1], length, bk);
            // HomMin(result2, a[j], a[j+1], length, bk);
			BootsSort(result1, result2, a[j], a[j+1], length, bk);

            for(int k = 0; k < length; k++)
                bootsCOPY(&a[j][k], &result2[k], bk);
            for(int k = 0; k < length; k++)
                bootsCOPY(&a[j+1][k], &result1[k], bk);
        }
    }

	if(N%2 == 0){
		HomAdd(result3, a[N/2], a[(N/2)-1], length, bk);
		HomLShift(res, result3, length, 1, bk);
		// bootsCOPY(&res[i], &res[i], bk);
		}
	else {
		for (int i = 0; i < length; i++){
			bootsCOPY(&res[i], &a[N/2][i], bk);
		}
	}

	delete_gate_bootstrapping_ciphertext_array(length, result1);
	delete_gate_bootstrapping_ciphertext_array(length, result2);
	delete_gate_bootstrapping_ciphertext_array(length, result3);
}


void HomRange(LweSample* res, LweSample** a, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {
	LweSample* result1 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* result2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* result3 = new_gate_bootstrapping_ciphertext_array(length, bk->params); 
	LweSample* result4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);

    for (int i = 0; i < N; i++) {
	    for (int j = 0; j < N-1; j++) {
            // HomMax(result, ciphertext1[j], ciphertext1[j+1], length, bk);
            // HomMin(result2, ciphertext1[j], ciphertext1[j+1], length, bk);
			BootsSort(result1, result2, a[j], a[j+1], length, bk);

            for(int k = 0; k < length; k++)
                bootsCOPY(&a[j][k], &result2[k], bk);
            for(int k = 0; k < length; k++)
                bootsCOPY(&a[j+1][k], &result1[k], bk);
        }
    }


    for (int i = 0; i < length; i++){
        bootsCOPY(&result3[i], &a[N - 1][i], bk);
	}

    for (int i = 0; i < length; i++){
        bootsCOPY(&result4[i], &a[0][i], bk);
	}

    HomSubt(res, result3, result4, length, bk);

    delete_gate_bootstrapping_ciphertext_array(length, result1);
    delete_gate_bootstrapping_ciphertext_array(length, result2);
    delete_gate_bootstrapping_ciphertext_array(length, result3);
    delete_gate_bootstrapping_ciphertext_array(length, result4);
}	


void HomMaxValue(LweSample* res, LweSample** a, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {
	LweSample* result1 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* result2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	
    for (int i = 0; i < N; i++) {
	    for (int j = 0; j < N-1; j++) {
            // HomMax(result, ciphertext1[j], ciphertext1[j+1], length, bk);
            // HomMin(result2, ciphertext1[j], ciphertext1[j+1], length, bk);
			BootsSort(result1, result2, a[j], a[j+1], length, bk);

            for(int k = 0; k < length; k++)
                bootsCOPY(&a[j][k], &result2[k], bk);
            for(int k = 0; k < length; k++)
                bootsCOPY(&a[j+1][k], &result1[k], bk);
        }
    }


    for (int i = 0; i < length; i++)
        bootsCOPY(&res[i], &a[N - 1][i], bk);

	delete_gate_bootstrapping_ciphertext_array(length, result1);
    delete_gate_bootstrapping_ciphertext_array(length, result2);
}	


void HomMinValue(LweSample* res, LweSample** a, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {
	LweSample* result1 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* result2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	
    for (int i = 0; i < N; i++) {
	    for (int j = 0; j < N-1; j++) {
            // HomMax(result, ciphertext1[j], ciphertext1[j+1], length, bk);
            // HomMin(result2, ciphertext1[j], ciphertext1[j+1], length, bk);
			BootsSort(result1, result2, a[j], a[j+1], length, bk);

            for(int k = 0; k < length; k++)
                bootsCOPY(&a[j][k], &result2[k], bk);
            for(int k = 0; k < length; k++)
                bootsCOPY(&a[j+1][k], &result1[k], bk);
        }
    }


    for (int i = 0; i < length; i++)
        bootsCOPY(&res[i], &a[0][i], bk);

	delete_gate_bootstrapping_ciphertext_array(length, result1);
    delete_gate_bootstrapping_ciphertext_array(length, result2);
}	


// To be continued! 
void HomSqroot(LweSample* res, LweSample* a, const int length, const TFheGateBootstrappingCloudKeySet* bk) {  
	
	// 1. For future release, please change RShift and LShift ! :( After the change, PLEASE DELETE THIS LINE :)
	// 2. This algorithm is based on the binary sqaure root computing algorithm. Refer to 
	// https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Binary_estimates

	LweSample* A = new_gate_bootstrapping_ciphertext_array(length+1, bk->params); // length+1 array, to prevent overflow for 0.484375a + 0.484375
	LweSample* At = new_gate_bootstrapping_ciphertext_array(length+1, bk->params);
	LweSample* Ahalf = new_gate_bootstrapping_ciphertext_array(length+1, bk->params);
	LweSample* A64 = new_gate_bootstrapping_ciphertext_array(length+1, bk->params);
	LweSample* B = new_gate_bootstrapping_ciphertext_array(length/2, bk->params);
	LweSample* BB = new_gate_bootstrapping_ciphertext_array(length/2, bk->params);
	LweSample* Bt = new_gate_bootstrapping_ciphertext_array(length/2, bk->params);
	LweSample* rtmp = new_gate_bootstrapping_ciphertext_array(length+1, bk->params);
	LweSample* R = new_gate_bootstrapping_ciphertext_array(length*3/2, bk->params);
	LweSample* Rt = new_gate_bootstrapping_ciphertext_array(length*3/2, bk->params);
	LweSample* tmp = new_gate_bootstrapping_ciphertext(bk->params);
	
	// Initialization
	bootsCONSTANT(&A[length], 0, bk); 
	bootsCONSTANT(&B[0], 1, bk);
	bootsCONSTANT(&rtmp[length], 0, bk);

	for (int i = 0; i < length; i++){
		bootsCOPY(&A[i], &a[i], bk);
		bootsCONSTANT(&rtmp[i], 0, bk);
	}
	for (int i = 0; i < 5; i++){
		bootsCONSTANT(&rtmp[length-4-i], 1, bk); // rtmp -> 0.484375
	}
	// bootsCONSTANT(&rtmp[length-3], 1, bk);
	for (int i = 0; i < length/2 - 1; i++){
		bootsCONSTANT(&B[i+1], 0, bk);
	}

	for (int i = 0; i < length/2; i++){ // Shift A until there is 1 in one of the bit position, A[n-2].(decimal point)A[n-3]. 
		// This procedure is needed to bound the value of A inside 0.5<= a < 2. 
		bootsOR(tmp, &A[length-2], &A[length-3], bk); 
		HomRShift(At, A, length+1, 2, bk); // A is shifted 2
		HomRShift(Bt, B, length/2, 1, bk); // B counts the number of shifts held
		for (int j = 0; j < length+1; j++){
			bootsMUX(&A[j], tmp, &A[j], &At[j], bk); // If tmp = 0 (i.e. There is no 1 in the positions A[n-2], A[n-3], the A is shifted by 2)
		}

		for (int j = 0; j < length/2; j++){
			bootsMUX(&B[j], tmp, &B[j], &Bt[j], bk); // Same :) 
		}
	}
	
	HomLShift(Ahalf, A, length+1, 1, bk); // 0.5a
	HomLShift(A64, A, length+1, 6, bk); // 1/64 * a
	HomSubt(Ahalf, Ahalf, A64, length+1, bk); // 0.484375*a
	HomAdd(rtmp+(length-9), rtmp+(length-9), Ahalf+(length-9), 10, bk); // 0.484375*a + 0.484375

	for (int i = 0; i < length/2 - 1; i++){
		bootsCONSTANT(&R[length+1+i], 0, bk);
	}
	for (int i = 0; i < length + 1; i++){
		bootsCOPY(&R[i], &rtmp[i], bk);
	}

	HomRShift(R, R, length*3/2, length/4 - 1, bk); // Shift the decimal point, *2^(n/4-1)
	for (int i = 0; i < length/2; i++){
		HomLShift(Rt, R, length*3/2, i, bk); // Shift back the number, *2^(-b)
		for (int j = 0; j < length*3/2; j++){
			bootsMUX(&R[j], &B[i], &Rt[j], &R[j], bk); //Select the nuber shifted back "b" positions
		}
	}

	for (int i = 0; i < length; i++){
		bootsCOPY(&res[i], &R[length/2 - 2 + i], bk); // Extract the final value from [n/2-2 : 3/2n - 3] 
	}

	delete_gate_bootstrapping_ciphertext_array(length+1, A);
	delete_gate_bootstrapping_ciphertext_array(length+1, At);
	delete_gate_bootstrapping_ciphertext_array(length+1, Ahalf);
	delete_gate_bootstrapping_ciphertext_array(length+1, rtmp);
	delete_gate_bootstrapping_ciphertext_array(length/2, B);
	delete_gate_bootstrapping_ciphertext_array(length/2, Bt);
	delete_gate_bootstrapping_ciphertext_array(length*3/2, R);
	delete_gate_bootstrapping_ciphertext_array(length*3/2, Rt);
	delete_gate_bootstrapping_ciphertext(tmp);
}


void HomStd(LweSample* res, LweSample** a, const int length, const int N, const TFheGateBootstrappingCloudKeySet* bk) {   

	LweSample* mean = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	//LweSample* temp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* temp2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* V[N];
	for (int i = 0; i < N; i++){
		V[i] = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	}
	LweSample* var[N];
	for (int i = 0; i < N; i++){
		var[i] = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	}
	LweSample* EN = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* E1 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* E1_EN = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* Var = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	HomRealP2C(EN, N, length, bk);
	HomRealP2C(E1, 1, length, bk);
	HomRealDiv(E1_EN, E1, EN, length, bk);

	for (int i = 0; i < N; i++){
		HomMean(mean, a, length, N, bk);
	}

	for (int i = 0; i < N; i++){
		HomSubt(V[i], a[i], mean, length, bk);
		HomMultiReal(var[i], V[i], V[i], length, bk);
		// HomSum(temp, V, length, N, bk);
	}
	HomSum(temp2, var, length, N, bk);
    HomMultiReal(Var, E1_EN, temp2, length, bk);
	HomSqroot(res, Var, length, bk);


	delete_gate_bootstrapping_ciphertext_array(length, mean);
	delete_gate_bootstrapping_ciphertext_array(length, temp2);
	for (int i =0 ; i < N ;i++){
		delete_gate_bootstrapping_ciphertext_array(length, V[i]);
	}

	for (int i =0 ; i < N ;i++){
		delete_gate_bootstrapping_ciphertext_array(length, var[i]);
	}
	delete_gate_bootstrapping_ciphertext_array(length, EN);
	delete_gate_bootstrapping_ciphertext_array(length, E1);
	delete_gate_bootstrapping_ciphertext_array(length, E1_EN);
	delete_gate_bootstrapping_ciphertext_array(length, Var);
}

void encode_double_ciphertext(LweSample* res, const double double_num, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	/*
	
		encode double type plaintext to 8,16,32-bit ciphertext (ex. 8-bit: 3/4/1)

	*/
	
	// encode double to our format (plaintext)
	int32_t plaintext = (int32_t) round(double_num * (1<<(int)(length/2)));
	
	// encrypt plaintext to ciphertext
	LweSample* ciphertext;
    ciphertext = new_gate_bootstrapping_ciphertext_array(length, bk->params);
    for (int i = 0; i < length; i++)
        bootsCONSTANT(&ciphertext[i], (plaintext>>i)&1, bk);

	for (int i = 0; i < length; i++)
		bootsCOPY(&res[i], &ciphertext[i], bk);

    delete_gate_bootstrapping_ciphertext_array(length, ciphertext);

}

void HomConfidenceInterval(LweSample** res, LweSample** a, const int N, const int length, const TFheGateBootstrappingCloudKeySet* bk) {   

	/* 
		
		Suppose we want to calculate confidence interval wtih 95% confidence rate. (For 99% confidence rate, z-score is 2.58.)
		Then, the interval is (X_bar - 1.96 * (s / sqrt(N)), X_bar + 1.96 * (s / sqrt(N)))
		where s is standard deviation of sample, N is number of sample
	
		Thus, our first goal is to calculate sample mean (X_bar) and std (s) of sample.
		Next, it is just the matter of using the above sample mean and std to derive (X_bar - 1.96 * (s / sqrt(N)), X_bar + 1.96 * (s / sqrt(N)))

		Note, 1.96 is actually plaintext, however, in our first attempt, we will only consider ciphertext * ciphertext (not plaintext * ciphertext).
		Therefore, one has to change the code to plaintext * ciphertext for high performance.
		This is just demonstration.

		# Parameter
		a: N number of ciphertexts
		N: number of data
		
	*/

	// #1: X_bar and std
	LweSample* X_bar = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* std = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	
	HomMean(X_bar, a, length, N, bk);
	HomStd(std, a, length, N, bk);

	//// #2: 1.96 * (std / sqrt(N))
	// 1.96 (double) to ciphertext (Note, this step should be changed to 1.96 (plain) in future release)
	double z_score = 1.96;
	LweSample* z_score_ciphertext = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	encode_double_ciphertext(z_score_ciphertext, z_score, length, bk);

	// Note, sqrt(N) is also plaintext; we (server) know number of data (N). Thus, one should change it to plaintext later on.
	// For now, we square root encrypted N: sq_N
	LweSample* sqrt_N = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	HomRealP2C(sqrt_N, N, length, bk);
	HomSqroot(sqrt_N, sqrt_N, length, bk);

	// 1.96 * (std / sqrt(N))
	LweSample* tmp = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	HomRealDiv(tmp, std, sqrt_N, length, bk);
	HomMultiReal(tmp, z_score_ciphertext, tmp, length, bk);

	// res[0] = X_bar - 1.96 * (s / sqrt(N)
	// res[1] = X_bar + 1.96 * (s / sqrt(N)
	HomSubt(res[0], X_bar, tmp, length, bk);
	HomAdd(res[1], X_bar, tmp, length, bk);
	

	delete_gate_bootstrapping_ciphertext_array(length, X_bar);
	delete_gate_bootstrapping_ciphertext_array(length, std);
	delete_gate_bootstrapping_ciphertext_array(length, z_score_ciphertext);
	delete_gate_bootstrapping_ciphertext_array(length, sqrt_N);
	delete_gate_bootstrapping_ciphertext_array(length, tmp);
}

void HomTotalVariance(LweSample* res, LweSample **x1, LweSample **x2, const int N, const int length, const TFheGateBootstrappingCloudKeySet* bk){

	LweSample* var1 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* var2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);

	HomVar(var1, x1, length, N, bk);
	HomVar(var2, x2, length, N, bk);

	HomAdd(res, var1, var2, length, bk);

	delete_gate_bootstrapping_ciphertext_array(length, var1);
	delete_gate_bootstrapping_ciphertext_array(length, var2);

}

void ChiSquared(LweSample* res, LweSample **obs, LweSample **exp, const int N, const int length, const TFheGateBootstrappingCloudKeySet* bk) {
	//Input: return, observation, expectation, num_data, length, bk
	LweSample* x1 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* x2 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* x3 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	LweSample* x4 = new_gate_bootstrapping_ciphertext_array(length, bk->params);
	
	for(int i = 0; i < N; i++) {
		HomSubt(x1, obs[i], exp[i], length, bk); //(O_i - E_i)
		HomMultiReal(x2, x1, x1, length, bk); //(O_i - E_i)**2
		HomRealDiv(x3, x2, exp[i], length, bk); //(O_i - E_i)**2/E_i
		HomAdd(x4, x4, x3, length, bk);
	}
	
	for(int i = 0; i < length; i++)
		bootsCOPY(&res[i], &x4[i], bk);

	delete_gate_bootstrapping_ciphertext_array(length, x1);
	delete_gate_bootstrapping_ciphertext_array(length, x2);
	delete_gate_bootstrapping_ciphertext_array(length, x3);
	delete_gate_bootstrapping_ciphertext_array(length, x4);
}

