#ifndef ARR_OPR_H
#define ARR_OPR_H

#include<stdio.h>
#include<string.h>
#include<stddef.h>

typedef struct arr
{
    unsigned char* result;
    int length;
}arr_xor;

// Function to concatenate two byte arrays using Array.Copy method
unsigned char* concatArrays(const unsigned char* array1, int length1, const unsigned char* array2, int length2);

// Function to perform XOR operation on two byte arrays
arr_xor bitwiseXOR(const unsigned char* array1, int length1, const unsigned char* array2, int length2);

arr_xor TrimZeroByte(arr_xor input);
#endif
