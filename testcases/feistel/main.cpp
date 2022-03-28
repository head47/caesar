#include <iostream>
#include <string>
#include <cstdlib>
#include <cmath>
#include <vector>

using namespace std;

//создадим некоторые константы
const int BIN_LEN = 8;
const int sizeb = 64;
const uint64_t mykey = 2495599072149523524;
const int raunds = 4;
int str_len = 0;

//Преобразование из bin в dec, дописывая незначащие нули до размера блока
string toBinAnother(uint64_t dec) {
    string bin;
    while(dec > 0 ){
        char temp = (dec % 2) + '0';
        bin = temp + bin;
        dec = dec/2;
        }

    while( bin.length() < sizeb){
        bin = '0' + bin;
        }
    return bin;
    }
//Преобразование из bin в dec
uint64_t toDecUint(string bin) {
    uint64_t deci = 0;
    for( int i = 0; i < bin.length(); i++ ){
        int temp = bin.length() - i - 1;
        if( bin[temp] == '1' ){
            deci += pow(2, i);
            }
        }
    return deci;

    }
//Преобразование из dec в bin, дописывая незначащие нули до размера слова
string toBin(char deci) {
    int dec = static_cast<int>(deci);
    string bin;
    while(dec > 0 ){
        char temp = (dec % 2) + '0';
        bin = temp + bin;
        dec = dec/2;
        }
    while( bin.length() < BIN_LEN ){
        bin = '0' + bin;
        }
    return bin;
    }
//Преобразование из bin в dec
char toDec(string bin) {
    int deci = 0;
    for( int i = 0; i < bin.length(); i++ ){
        int temp = bin.length() - i - 1;
        if( bin[temp] == '1' ){
            deci += pow(2, i);
            }
        }
    return (char)deci;
    }
//Операция XOR для бинарных строк
string XORxxx(string R, string L){
    string nR;
    for( int j = 0; j < L.length(); j++ ){
            nR += R[j] == L[j] ? '0' : '1';
            }
    return nR;
    }
//Расшифровка текста, принимает на вход бинарную последовательность
string decr(string block){
    string L = block.substr(0, block.length()/2);
    string R = block.substr(block.length()/2);
    for( int i = raunds; i > 0; i-- ){
        string newL = R;
        string newR;
        uint64_t ff = toDecUint(R);
        uint64_t result = ((pow(2, 128*(sqrt(abs(sin(ff)))*log(abs(sin(mykey))+1)))) - 1);
        R = toBinAnother(result);
        newR = XORxxx(R,L);
        L = newL;
        R = newR;
        }
    block = R + L;
    string thing;
    for( int i = 0; i < block.length(); i+=BIN_LEN ){
        string sub = block.substr(i, BIN_LEN);
        char ch = toDec(sub);
        thing += ch;
        }
    return thing;
    }

int main(){
    string s;
    vector<string> v_s;
    vector<string> v_s_decr;
    constexpr int size = 16;
    cout<<"[    OK    ] Enter text to encrypt: ";
    getline(cin, s);
    int length = s.length();
    int quotient = length/size;
    if(length % size != 0)
        quotient++;
    for(int i = 0; i < quotient; i++) {
        string new_message = s.substr(0, size);
        v_s.push_back(new_message);
        s.erase(0, size);
        }
    string last_string = v_s.at(v_s.size()-1);
    if (last_string.length() < size) {
        last_string.resize(size, '0');
        }

    cout << "[    OK    ] Encrypted text: ";
    for (const auto& block : v_s) {

        str_len = block.length();
        string bin;

        for( int i = 0; i < str_len; i++ ){
            bin += toBin(block[i]);
            }
        string L = bin.substr(0, bin.length()/2);
        string R = bin.substr(bin.length()/2);
        for( int i = 0; i < raunds; i++ ){
            string newL = R;
            string newR;
            uint64_t ff = toDecUint(R);
            uint64_t result = ((pow(2, 128*(sqrt(abs(sin(ff)))*log(abs(sin(mykey))+1)))) - 1);
            R = toBinAnother(result);
            newR = XORxxx(R,L);
            L = newL;
            R = newR;
            }
        bin = R + L;
        string thing;
        for( int i = 0; i < bin.length(); i+=BIN_LEN ){
            string sub = bin.substr(i, BIN_LEN);
            char ch = toDec(sub);
            thing += ch;
            }
        cout << thing;
        auto str = bin;

        v_s_decr.push_back(str);
        }
    cout << "\n";
    cout << "[    OK    ] Decrypted text: ";
    for (const auto& block : v_s_decr) {
        string res = decr(block);
        cout << res;
        }
    cout << endl;
    }
