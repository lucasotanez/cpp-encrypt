#include <cstring>
#include <cstdlib>
#include <iostream>
#include <cctype>
#include <ctime>
#include "cppencrypt.h"

/*
    Efficient encryption for passwords and
    single key words in C++ using char arrays.
    This version does not support strings.
    By: Lucas Otanez
    Date: December 31, 2022
    License: This code is open source (MIT License)
*/

int shifter[62] = {48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70,
    71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113,
    114, 115, 116, 117, 118, 119, 120, 121, 122
};

int randAlpha()
{
    return rand() % 26 + 97;
}

void swapShifter(int* key, int i)
{
    int swapWith = rand() % 62;
    int temp = key[i];
    key[i] = key[swapWith];
    key[swapWith] = temp;
    return;
}

int decryptLength(char* ciphertext)
{
    int passLen = 0;
    //2nd redundant check
    if (strlen(ciphertext) != 27) throw std::runtime_error("This password was not encrypted using this software.");

    if ((ciphertext[24] < 58) && (ciphertext[24] > 47)){
        passLen = (ciphertext[24] - 48) * 10 + (ciphertext[25] - 48);
    }
    else passLen = ciphertext[25] - 48;
    return passLen;
}

void encrypt(char* password, char* ciphertext)
{
    if (strlen(password) > 20) throw std::runtime_error("Password is too long.");

    srand(time(0));

    int capLoc = rand() % 3; //capital location

    int shifterSeed = rand() % 9 + 1 ; //seeds from 1 - 9 

    int shift = randAlpha();
    while (shift == 116) shift = randAlpha();

    //scramble shifter array
    for (unsigned i = 0; i < 62; i++){
        swapShifter(shifter, i);
    }

    for (unsigned i = 0; i < 3; i++){
        if (i == capLoc){
            ciphertext[i] = shift - 32; //uppercase
        }
        else{
            ciphertext[i] = randAlpha();
        }
    }

    //ACSII value overflow handling
    for (unsigned i = 0; i < strlen(password); i++){
        int newAscii = password[i] + shift;
        while (newAscii > 122) newAscii = 48 + newAscii - 123;
        if (newAscii == 92) newAscii = 36; //special case;
        ciphertext[i+3] = newAscii;
    }

    //fills in ciphertext with garbage values
    for (unsigned i = strlen(password) + 3; i < 24; i++){
        ciphertext[i] = shifter[rand() % 62];
    }

    //encode password length
    if (strlen(password) < 10){ //setting password length
        ciphertext[24] = randAlpha();
        ciphertext[25] = 48 + strlen(password); // ASCII number characters
    } 
    else{
        ciphertext[24] = strlen(password) / 10 + 48;
        ciphertext[25] = strlen(password) - ((ciphertext[24] - 48) * 10) + 48;
    };

    ciphertext[26] = randAlpha();
    ciphertext[27] = '\0';

    return;
}

void decrypt(char* ciphertext, char* password)
{
    if (strlen(ciphertext) != 27) throw std::runtime_error("This password was not encrypted using this software.");
    
    int unshift = -1;

    for (unsigned i = 0; i < 3; i++){
        if (isupper(ciphertext[i])){
            unshift = ciphertext[i] + 32;
            break;
        }
        else if (i == 2) throw std::runtime_error("This password was not encrypted using this software.");
    }

    int passwordLength = decryptLength(ciphertext);

    for (unsigned i = 3; i < passwordLength+3; i++){
        if (ciphertext[i] == 36){ //special case
            password[i-3] = 92;
            password[i-3] -= unshift;
            while (password[i-3] < 48) password[i-3] = 123 - (48 - password[i-3]);
            continue;
        }
        int backShift = ciphertext[i] - unshift;
        while (backShift < 48) backShift = 123 - (48 - backShift);
        password[i-3] = backShift;
    }
    
    password[passwordLength] = '\0';

    return;
}