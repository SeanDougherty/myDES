#ifndef MYDES_H
#define MYDES_H
#include <iostream>
#include <sstream>
#include <ios>
#include <fstream>
#include <streambuf>
#include <utility>
#include <algorithm>
#include <iterator>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <bitset>
#include <chrono>

using namespace std;

string loadFileToString(string fileName);
void encrypt(string text, string key, string iv, string fileName);
void decrypt(string text, string key, string iv, string fileName);
string generateRandomKey(string keyFileName);
string generateRandomIV(string ivFileName);
vector<string> generateSubKeys(string key);
vector<string> generateTextBlocks(string text, bool isEncrypt);
string padBlock(string text);
string unpadBlock(string text);
string permuteTextBlock(string textBlock, bool initialPerm);
string feistel(string permutedBlock, vector<string> subKeys, bool isDecryption);
string feistelRight(string left, string right, string key);
string roundFunction(string right, string key);
string expand(string text);
string subBox(string keyed);
string permBox(string subBoxed);
string permuteKey(string binKey, int PCBox);
vector<string> generateSubBlocks(string permutedKey);
string hexToBinary(string hex);
string binToHex(string bin);
string asciiToBinary(string text);
string binaryToAscii(string text);
int binaryToDec(string val);
string decimalToBin(int val);
string xorString(string val1, string val2);
void writeToFile(string fileName, string val);

#endif
