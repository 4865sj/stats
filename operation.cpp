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

