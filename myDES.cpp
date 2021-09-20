#include "myDES.h"
#include "utility.h"
int main(int argc, char *argv[])
{
	if (argc != 8)
	{
		cout << "Incorrect number of commandline arguments, expecting 6" << '\n';
		cout << "Expected Syntax:" << '\n';
		cout << "./a.out text.txt key.txt iv.txt output.txt -{cryptoFlag} -{keyFlag} -{ivFlag}" << '\n';
	}

	// Load flags
	string cryptoFlag = argv[5];
	string keyFlag = argv[6];
	string ivFlag = argv[7];

	// Initialize iv and key variables
	string iv;
	string key;

	// Load or Generate key
	if (keyFlag[1] == 'y')
		key = generateRandomKey(argv[2]);
	else if (keyFlag[1] == 'n')
		key = loadFileToString(argv[2]);
	else
	{
		cout << "Unrecognized key flag: " << keyFlag << '\n';
		cout << "Quitting program." << '\n';
		return 0;
	}

	// Load or Generate iv
	if (ivFlag[1] == 'y')
		iv = generateRandomIV(argv[3]);
	else if (ivFlag[1] == 'n')
		iv = loadFileToString(argv[3]);
	else
	{
		cout << "Unrecognized IV flag: " << ivFlag << '\n';
		cout << "Quitting program." << '\n';
		return 0;
	}

	// Load user defined parameters into variables
	string text = loadFileToString(argv[1]);
	string fileName = argv[4];

	// Perform proper crypto operation
	switch(cryptoFlag[1])
	{
		case 'e':
		{
			encrypt(text, key, iv, fileName);
			break;
		}
		case 'd':
		{
			decrypt(text, key, iv, fileName);
			break;
		}
		default:
		{
			cout << "Error in parsing your flag" << '\n';
			cout << "Accepted Flags:" << '\n';
			cout << "Encrypt    Decrypt" << '\n';
			cout << "-e         -d  " << '\n';
			break;
		}
	} 
	return 0;
}	

string loadFileToString(string fileName)
{
	ifstream fileStream (fileName, ifstream::in);
	if(fileStream.fail())
		cout << "error loading file: " << fileName << '\n';

	string fileString;
	char temp;
	while(fileStream.good())
	{
		fileStream.get(temp);
	//	if (temp.empty())
	//		temp = '\n';
		fileString+=temp;
	}
//	string fileString ((std::istreambuf_iterator<char>(fileStream)),
//				std::istreambuf_iterator<char>());

	return fileString;
}

void encrypt(std::string text, std::string key, std::string iv, std::string fileName)
{
	string outputBinary = "";
	string chainingBlock = hexToBinary(iv);
	vector <string> subKeys = generateSubKeys(key);
	vector <string> textBlocks = generateTextBlocks(text, true);
	for (auto block : textBlocks)
	{
		string chainedBlock = xorString(block,chainingBlock);
		string permutedBlock = permuteTextBlock(chainedBlock, true);
		string feistelBlock = feistel(permutedBlock, subKeys, false);
		string repermutedBlock = permuteTextBlock(feistelBlock, false);
		chainingBlock = repermutedBlock;
		outputBinary+=repermutedBlock;
	}
	string cryptedText = binaryToAscii(outputBinary);
	writeToFile(fileName, cryptedText);
}

void decrypt(std::string text, std::string key, std::string iv, std::string fileName)
{
	string outputBinary = "";
	string chainingBlock = hexToBinary(iv);
	vector <string> subKeys = generateSubKeys(key);
	vector <string> textBlocks = generateTextBlocks(text, false);
	for (int i = 0; i < textBlocks.size(); i++)
	{	
		string block = textBlocks[i];
		string permutedBlock = permuteTextBlock(block, true);
		string feistelBlock = feistel(permutedBlock, subKeys, true);
		string repermutedBlock = permuteTextBlock(feistelBlock,false);
		string dechainedBlock = xorString(repermutedBlock, chainingBlock);
		chainingBlock = block;
		if (i == (textBlocks.size()-1))
		{ 
			string unpaddedBlock = unpadBlock(dechainedBlock);
			outputBinary+=unpaddedBlock;
		}
		else
		{
			outputBinary+=dechainedBlock;
		}

	}
	string cryptedText = binaryToAscii(outputBinary);
	writeToFile(fileName, cryptedText);
}

string generateRandomKey(std::string keyFileName)
{
	string key = "";
	while (key.length() < 64)
	{
		auto time_now = std::chrono::high_resolution_clock::now();
		std::chrono::nanoseconds nanos = time_now.time_since_epoch();
		if (nanos.count()%2 == 0)
			key+='0';
		else
			key+='1';	
	}
	string hexKey = binToHex(key);
	cout << "Random Key Generated: " << hexKey << '\n';
	writeToFile(keyFileName, hexKey);
	return hexKey;
}

string generateRandomIV(std::string ivFileName)
{
	string iv = "";
	while (iv.length() < 64)
	{
		auto time_now = std::chrono::high_resolution_clock::now();
		std::chrono::nanoseconds nanos = time_now.time_since_epoch();
		if (nanos.count()%2 == 0)
			iv+='0';
		else
			iv+='1';
	}
	string hexIV = binToHex(iv);
	cout << "Random IV Generated: " << hexIV << '\n';
	writeToFile(ivFileName, hexIV);
	return hexIV;
}

vector<string> generateSubKeys(std::string key)
{
	vector<string> subKeys;
	string binKey = hexToBinary(key);
	string permutedKey = permuteKey(binKey, 1);
	vector<string> subBlocks = generateSubBlocks(permutedKey);

	for (auto elem : subBlocks)
		subKeys.push_back(permuteKey(elem, 2));
	
	return subKeys;
}

vector<string> generateTextBlocks(std::string text, bool isEncrypt)
{
	vector<string> textBlocks;
	int numOfBlocks = text.length() / 8;
	int unfinishedBlock = text.length() % 8;

	for (int i = 0; i < numOfBlocks; i++)
	{
		string textBinaryBlock = asciiToBinary(text.substr(i*8,8));
		textBlocks.push_back(textBinaryBlock);
	}
	
	if(isEncrypt)
	{
		if (unfinishedBlock > 0)
		{
			string finalTextBlock = asciiToBinary(text.substr(numOfBlocks*8));
			string finalHexBlock = binToHex(finalTextBlock);
			string paddedBlock = padBlock(finalHexBlock);
			string binPadBlock = hexToBinary(paddedBlock);
			textBlocks.push_back(binPadBlock);
		}
		else
		{
			string fullPadBlock = "08080808";
			textBlocks.push_back(fullPadBlock);
		}
	}
	return textBlocks;
}

string padBlock(std::string text)
{
	int blockSize = 16;
	int padAmount = (blockSize - text.length())/2;
	string binPad = decimalToBin(padAmount);
	string hexPad = binToHex(binPad);
	for (int i = 0; i < padAmount; i++)
		text += ('0' + hexPad);
	return text;
}

string unpadBlock(std::string text)
{
	string hexText = binToHex(text);
	char lastChar = hexText.back();
	int padSize = lastChar - '0';
	string trueString = hexText.substr(0,16-(padSize*2));
	string trueBinString = hexToBinary(trueString);
	return trueBinString;
}

string permuteTextBlock(std::string textBlock, bool initialPerm)
{
	string permutedBlock;
	if(initialPerm)
		for (auto elem : IP)
			permutedBlock+=textBlock[elem-1];
	else
		for (auto elem : FP)
			permutedBlock+=textBlock[elem-1];

	return permutedBlock;
}

string feistel(std::string permutedBlock, std::vector<std::string> subKeys, bool isDecryption)
{
	string feistelBlock;
	if(isDecryption)
		reverse(subKeys.begin(), subKeys.end());
	string left = permutedBlock.substr(0,32);
	string right = permutedBlock.substr(32,32);
	for(auto key : subKeys)
	{
		string tempLeft = left;
		string tempRight = right;
		left = tempRight;
		right = feistelRight(tempLeft, tempRight, key);
	}
	feistelBlock = right + left;
	
	return feistelBlock;
}

string feistelRight(std::string left, std::string right, std::string key)
{
	string roundFunctionResult = roundFunction(right, key);
	return xorString(left, roundFunctionResult);
}

string roundFunction(std::string right, std::string key)
{
	string expanded = expand(right);
	string keyed = xorString(expanded, key);
	string subBoxed = subBox(keyed);
	string permBoxed = permBox(subBoxed);
	return permBoxed;
}

string expand(std::string text)
{
	string expanded;
	for (auto elem : E)
		expanded.push_back(text[elem-1]);
	return expanded;
}

string subBox(std::string keyed)
{
	string subBoxed;
	for(int i = 0; i < 8; i++)
	{
		string subBlock = keyed.substr(i*6,6);
		string rowBin;
		rowBin+=subBlock[0];
		rowBin+=subBlock[5];
		int row = binaryToDec(rowBin);
		int column = binaryToDec(subBlock.substr(1,4));
		int index = (row*16)+column;
		int intSubbedBlock = SBOXMAP[i][index];
		string subbedBlock = decimalToBin(intSubbedBlock);
		subBoxed+=subbedBlock;
	}
	return subBoxed;
}

string permBox(std::string subBoxed)
{
	string permBoxed;
	for (auto elem : P)
		permBoxed.push_back(subBoxed[elem-1]);
	return permBoxed;
}

string permuteKey(std::string binKey, int PCBox)
{
	string permutedKey;
    		
	switch(PCBox)
	{
		case 1:
			{
			for (auto elem : PC1)
				permutedKey+=binKey[elem-1];
			break;
			}
		case 2:
			{
			for (auto elem : PC2)
				permutedKey+=binKey[elem-1];
			break;
			}
		default:
			{
			cout << "this shouldn't be called" << '\n';
			for (auto elem : PC2)
				permutedKey+=binKey[elem-1];
			break;
			}
	}

	return permutedKey;
}

vector<string> generateSubBlocks(std::string permutedKey)
{	
	// number of times you shift based on current round of iteration
	int leftshift[16] = 
			{ 1, 1, 2, 2,
			  2, 2, 2, 2,
			  1, 2, 2, 2,
			  2, 2, 2, 1 };
	vector<string> subBlocks;

	// Split the permuted key into two halves and shift them to generate intermediate values referred to as "blocks".
	// These "blocks" are used to generate the sub keys.
	string left = permutedKey.substr(0,28);
	string right = permutedKey.substr(28,28);

	// Perform a shift each round before rejoining the left and right sides into a new subBlock
	for (int i = 0; i < 16; i++)
	{
		left = left.substr(leftshift[i]) + left.substr(0,leftshift[i]);
		right = right.substr(leftshift[i]) + right.substr(0,leftshift[i]);
		subBlocks.push_back(left + right);
	}

	return subBlocks;
}

string hexToBinary(std::string hex)
{
	string bin;
	for (auto elem : hex)
	{
		switch(toupper(elem))
		{
			case '0': bin+="0000"; break;
        		case '1': bin+="0001"; break;
       			case '2': bin+="0010"; break;
        		case '3': bin+="0011"; break;
        		case '4': bin+="0100"; break;
        		case '5': bin+="0101"; break;
        		case '6': bin+="0110"; break;
        		case '7': bin+="0111"; break;
        		case '8': bin+="1000"; break;
        		case '9': bin+="1001"; break;
        		case 'A': bin+="1010"; break;
        		case 'B': bin+="1011"; break;
        		case 'C': bin+="1100"; break;
        		case 'D': bin+="1101"; break;
        		case 'E': bin+="1110"; break;
        		case 'F': bin+="1111"; break;
			default: 
			{
				std::cout << "Unrecognized Hex Value: " << (int) elem << '\n';
				break;
			}
		}
	}
	return bin;	
}

string binToHex(std::string bin)
{	
	string hex = "";
	for (int i = 0; i < bin.size(); i+=4)
	{
		string binChunk = bin.substr(i,4);
		if (binChunk.compare("0000") == 0)
			hex += '0';
		else if (binChunk.compare("0001") == 0)
			hex += '1';
		else if (binChunk.compare("0010") == 0)
			hex += '2';
		else if (binChunk.compare("0011") == 0)
			hex += '3';
		else if (binChunk.compare("0100") == 0)
			hex += '4';
		else if (binChunk.compare("0101") == 0)
			hex += '5';
		else if (binChunk.compare("0110") == 0)
			hex += '6';
		else if (binChunk.compare("0111") == 0)
			hex += '7';
		else if (binChunk.compare("1000") == 0)
			hex += '8';
		else if (binChunk.compare("1001") == 0)
			hex += '9';
		else if (binChunk.compare("1010") == 0)
			hex += 'A';
		else if (binChunk.compare("1011") == 0)
			hex += 'B';
		else if (binChunk.compare("1100") == 0)
			hex += 'C';
		else if (binChunk.compare("1101") == 0)
			hex += 'D';
		else if (binChunk.compare("1110") == 0)
			hex += 'E';
		else if (binChunk.compare("1111") == 0)
			hex += 'F';
	}
	return hex;
}

string asciiToBinary(std::string text)
{
	string textBinary;
	for (auto elem : text)
	{
		bitset<8> temp(elem);
		textBinary+=temp.to_string();
	}
	return textBinary;
}

string binaryToAscii(std::string text)
{
	string textAscii;
	stringstream sstream(text);
	while(sstream.good())
	{
		bitset<8> bits;
		sstream >> bits;
		char c = char(bits.to_ulong());
		if ((int) c != 0)
			textAscii += c;
	}
	
	return textAscii;
}

int binaryToDec(std::string val)
{
	unsigned long ul = bitset<8>(val).to_ulong();
	return (int) ul;
}

string decimalToBin(int val)
{
	return  bitset<4>(val).to_string();
}

string xorString(std::string val1, std::string val2)
{
	string xored;
	for (int i = 0; i < val1.length(); i++)
	{
		if (val1[i] == val2[i])
			xored+='0';
		else
			xored+='1';		
	}
	return xored;
}

void writeToFile(std::string fileName, std::string val)
{
	ofstream myFile;
	myFile.open(fileName);
	myFile << val;
	myFile.close();
}



