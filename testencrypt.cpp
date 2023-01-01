#include <cstring>
#include <iostream>
#include "cppencrypt.h"

//This code is an example of the library. Use it for reference.
//Compile and run this script to view the output.

int main(){

    //allocate 20 (maximum) or the exact amount (11 in this case) of characters
    //normally, this could be declared someplace safe 
    char passphrase[20] = "secret@123"; //OR char passphrase[11] = "secret123!";

    //allocate 28 bytes for all instances of ciphertext
    char ciphersecret[28];

    //encrypt takes the word to be encrypted, and a destination respectively
    encrypt(passphrase, ciphersecret);

    std::cout << "This cipher contains your password:   " << ciphersecret << std::endl;
    std::cout << "This is the length of your password, extracted from the cipher:   " << decryptLength(ciphersecret) << std::endl;

    char backtothis[20];

    //decrypt takes the cipher, and a destination to hold the password, respectively
    decrypt(ciphersecret, backtothis);

    std::cout << "This is your password, decrypted from the cipher:   " << backtothis << std::endl;

    return 0;
}