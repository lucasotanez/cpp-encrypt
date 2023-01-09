#ifndef CPPCRYPT_H
#define CPPCRYPT_H
#include <iostream>
#include <string>

/*
    Better encryption for passwords and
    single key words in C++.
    By: Lucas Otanez
    Date: January 7, 2022
    Version 2
    License: This code is open source (MIT License)
*/

class Key {
    public:

        //all accepted constructors
        Key();
        Key(const char* password);
        Key(const std::string password);
        Key(const Key& k);

        ~Key();

        //access raw password
        std::string decrypt() const;

        //acces raw length
        int length() const;

        Key& operator=(const Key&);
        Key& operator=(const char*);

        bool operator==(const Key&) const;
        bool operator!=(const Key&) const;

        friend std::istream& operator>>(std::istream&, Key&);
        friend std::ostream& operator<<(std::ostream&, const Key&);

    private:
        //raw password not stored. must be decrypted
        char* ciphertext_;
        int len_;

        void encrypt(const char* password);
};

#endif