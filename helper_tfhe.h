#include <iostream>

/*
Prints the input data (integer).
*/
void print_int16_data(int16_t * plaintext1, int num_data){
    
    std::cout << "( ";
    for(int i=0; i<num_data; i++)
        std::cout << plaintext1[i] << " ";
    std::cout << ")" << std::endl;

}

void print_double_data(double * data_double, int num_data){

    std::cout << "( ";
    for(int i=0; i<num_data; i++)
        std::cout << data_double[i] << " ";
    std::cout << ")" << std::endl;

}

/*
## Encodes double data into plaintext format.
dec_part: length/2 - 1
int_part: length/2
sign_bit: 1

## Example of length=8
(3: dec_part) | (4: int_part) | (1: sign_bit)

*/
int16_t encode_double_t16(int length, double data) {
    int16_t result = (int16_t) round(data * (1<<(int)(length/2)));
    return result;
}
