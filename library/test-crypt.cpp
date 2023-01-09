#include <string>
#include <iostream>
#include "cppcrypt.h"

using namespace std;

int main(){

    Key pword("piggylololol");
    cout << pword.decrypt() << " " << pword.length() << endl;

    Key pword2 = "pablo5";
    cout << pword2.decrypt() << " " << pword2.length() << endl;

    Key pword3;
    cout << pword3 << endl;
    pword3 = "testerz";

    cout << pword3.decrypt() << " " << pword3.length() <<  endl;
    pword3 = pword;
    cout << pword3.decrypt() << " " << pword3.length() << endl;

    cout << boolalpha << (pword2 != pword) << endl;

    return 0;
}