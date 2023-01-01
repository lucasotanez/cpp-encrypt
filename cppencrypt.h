#ifndef CPPENCRYPT_H
#define CPPENCRYPT_H

/*
    Efficient encryption for passwords and
    single key words in C++ using char arrays.
    This version does not support strings.
    By: Lucas Otanez
    Date: December 31, 2022
    License: This code is open source (MIT License)
*/

//================================================================

//IMPORTANT: When using character arrays, make sure to allocate an array 
//large enough to hold ciphertext (always 28 bytes including terminating char) or
//password (maximum of 20 characters), depending on the context.
//Failure to allocate enough memory may lead to segmentation fault.

//================================================================

//encode a password or key word into ciphertext
//NOTE: password must have a maximum of 20 characters
//NOTE: return value will always be length 27
void encrypt(char* src_password, char* dest_ciphertext);

//decode password ciphertext
//NOTE: ciphertext must have been created with encrypt()
void decrypt(char* src_ciphertext, char* dest_password);

//decode only the password length (characters) from ciphertext
int decryptLength(char* ciphertext);

//================================================================

#endif