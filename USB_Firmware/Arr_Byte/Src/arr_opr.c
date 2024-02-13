#include "arr_opr.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

// Function to concatenate two byte arrays using Array.Copy method
unsigned char* concatArrays(const unsigned char* array1, int length1, const unsigned char* array2, int length2) {
    unsigned char* result = (unsigned char*)malloc(length1 + length2);
    if (!result) {
        // Handle memory allocation failure
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < length1; i++) {
        result[i] = array1[i];
    }

    for (int i = 0; i < length2; i++) {
        result[length1 + i] = array2[i];
    }

    return result;
}

// Function to perform XOR operation on two byte arrays
arr_xor bitwiseXOR(const unsigned char* array1, int length1, const unsigned char* array2, int length2) {
    arr_xor result_xor;
    int maxLength = (length1 > length2) ? length1 : length2;
    int minLength = (length1 < length2) ? length1 : length2;

    int diff = maxLength - minLength;

    unsigned char* addZero = (unsigned char*)calloc(diff, sizeof(unsigned char));
    if (!addZero) {
        // Handle memory allocation failure
        exit(EXIT_FAILURE);
    }

    unsigned char* modifiedArray1;
    unsigned char* modifiedArray2;

    if (length1 < length2) {
        modifiedArray1 = concatArrays(addZero, diff, array1, length1);
        modifiedArray2 = (unsigned char*)array2;
    } else if (length1 > length2) {
        modifiedArray1 = (unsigned char*)array1;
        modifiedArray2 = concatArrays(addZero, diff, array2, length2);
    } else {
        modifiedArray1 = (unsigned char*)array1;
        modifiedArray2 = (unsigned char*)array2;
    }

    free(addZero);

    unsigned char* result = (unsigned char*)malloc(maxLength);
    if (!result) {
        // Handle memory allocation failure
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < maxLength; i++) {
        result[i] = modifiedArray1[i] ^ modifiedArray2[i];
    }

    result_xor.result = result;
    result_xor.length = maxLength;
    return result_xor;
}
arr_xor TrimZeroByte(arr_xor input) {
    int index = 0;
    arr_xor result;
    for (int i = 0; i < input.length; i++) {
        if (input.result[i] != 0) {
            index = i;
            break;
        }
    }

    result.length = input.length - index;
    result.result = (unsigned char *)malloc(result.length * sizeof(unsigned char));
    for (int j = 0; j < result.length; j++) {
        result.result[j] = input.result[index + j];
    }
    return result;
}
