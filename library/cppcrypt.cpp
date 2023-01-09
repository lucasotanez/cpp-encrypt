#include <iostream>
#include <cctype>
#include <ctime>
#include <cstring>
#include <string>
#include "cppcrypt.h"

/*
    Better encryption for passwords and
    single key words in C++.
    By: Lucas Otanez
    Date: January 7, 2022
    Version 2
    License: This code is open source (MIT License)
*/

std::string NE_error_msg = "This password was not encrypted using this software.";

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

Key::Key()
: ciphertext_(ciphertext_ = new char[27]), len_(0)
{}

Key::Key(const char* password)
: ciphertext_(nullptr)
{
    unsigned passlen_ = strlen(password);
    if (passlen_ < 21) {
        encrypt(password);
        len_ = passlen_;
    }
    else throw std::runtime_error("Password is too long.");
}

Key::Key(const std::string password)
{
    char* C_password = new char[password.length()+1];
    std::strcpy(C_password, password.c_str());
    unsigned passlen_ = strlen(C_password);
    if (passlen_ < 21) {
        encrypt(C_password);
        len_ = passlen_;
    }
}

Key::Key(const Key& k)
{
    len_ = k.len_;
    ciphertext_ = new char[27];
    strcpy(ciphertext_, k.ciphertext_);
}

void Key::encrypt(const char* password)
{

    if (ciphertext_ == nullptr) ciphertext_ = new char[27]; //empty allocation

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
            ciphertext_[i] = shift - 32; //uppercase
        }
        else{
            ciphertext_[i] = randAlpha();
        }
    }

    //ACSII value overflow handling
    for (unsigned i = 0; i < strlen(password); i++){
        int newAscii = password[i] + shift;
        while (newAscii > 122) newAscii = 48 + newAscii - 123;
        if (newAscii == 92) newAscii = 36; //special case;
        ciphertext_[i+3] = newAscii;
    }

    //fills in ciphertext_ with garbage values
    for (unsigned i = strlen(password) + 3; i < 24; i++){
        ciphertext_[i] = shifter[rand() % 62];
    }

    //encode password length
    if (strlen(password) < 10){ //setting password length
        ciphertext_[24] = randAlpha();
        ciphertext_[25] = 48 + strlen(password); // ASCII number characters
    } 
    else{
        ciphertext_[24] = strlen(password) / 10 + 48;
        ciphertext_[25] = strlen(password) - ((ciphertext_[24] - 48) * 10) + 48;
    };

    ciphertext_[26] = randAlpha();
    ciphertext_[27] = '\0';

    return;
}

std::string Key::decrypt() const
{
    if (strlen(ciphertext_) != 27) throw std::runtime_error(NE_error_msg);
    
    int unshift = -1;
    char password[len_+1];

    for (unsigned i = 0; i < 3; i++){
        if (isupper(ciphertext_[i])){
            unshift = ciphertext_[i] + 32;
            break;
        }
        else if (i == 2) throw std::runtime_error(NE_error_msg);
    }

    for (unsigned i = 3; i < len_+3; i++){
        if (ciphertext_[i] == 36){ //special case
            password[i-3] = 92;
            password[i-3] -= unshift;
            while (password[i-3] < 48) password[i-3] = 123 - (48 - password[i-3]);
            continue;
        }
        int backShift = ciphertext_[i] - unshift;
        while (backShift < 48) backShift = 123 - (48 - backShift);
        password[i-3] = backShift;
    }
    
    password[len_] = '\0';
    std::string retPassword = password;

    return retPassword;
}

int Key::length() const
{
    int passlen_ = 0;
    
    //redundancy
    if (strlen(ciphertext_) != 27) throw std::runtime_error(NE_error_msg);

    if ((ciphertext_[24] < 58) && (ciphertext_[24] > 47)){
        passlen_ = (ciphertext_[24] - 48) * 10 + (ciphertext_[25] - 48);
    }
    else passlen_ = ciphertext_[25] - 48;

    if (passlen_ == len_) return len_;
    else throw std::runtime_error("Key length was not encrypted correctly.");
}

Key& Key::operator=(const Key& k)
{
    if (!(strcmp(ciphertext_, k.ciphertext_))) return *this;
    len_ = k.len_;
    strcpy(this->ciphertext_, k.ciphertext_);
    return *this;
}

Key& Key::operator=(const char* k)
{
    if (!(strcmp(ciphertext_, k))) return *this;
    len_ = strlen(k);
    this->encrypt(k);
    return *this;
}

bool Key::operator==(const Key& k) const
{
    return (this->decrypt() == k.decrypt());
}

bool Key::operator!=(const Key& k) const
{
    return !(this->decrypt() == k.decrypt());
}

std::istream& operator>>(std::istream& istr, Key& k)
{
    std::string ktemp;
    istr >> ktemp;
    k = ktemp;
    return istr;
}

std::ostream& operator<<(std::ostream& ostr, const Key& k)
{
    ostr << k.ciphertext_;
    return ostr;
}

Key::~Key()
{
    delete [] ciphertext_;
}