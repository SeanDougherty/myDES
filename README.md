
# myDES Implementation

This is an implementation of the [Date Encryption Standard symmetric key algorithm](https://en.wikipedia.org/wiki/Data_Encryption_Standard). Complete with padding and key/iv generation.

#	Compiling myDES

In the same directory as myDES.cpp, myDES.h and utility.h, type the command:
```bash
	$   g++ -std=c++11 myDES.cpp
```
Given that you have g++ on your machine and access to it, this should generate
your object file "a.out"


#	Running myDES

A total of 7 additional commandline arguments are expected when executing
this program.

The outline for executing this program is:
```bash
	$	./a.out [textFiletoEncryptOrDecryptName] [keyFileName] [ivFileName][outputFileName] -[cryptoFlag] -[keyFlag] -[ivFlag]
```

An example of a valid commandline execution is:
```bash
	$   ./a.out secret.txt key.txt iv.txt cipher.txt -e -n -n
```

See below for details on each argument


#	Argument Details

### textFileToEncryptOrDecryptName
 This is a required file. It should be a plaintext file containing only
 the first 128 UTF-8 characters. Any length is allowed, but longer files may harm
 or slow down your machine.

### keyFileName
This is either the name of an existing keyFile that you would like to use
 or is the name of the keyFile that will be generated if you choose to use 
 random key generation.

### ivFileName
This is either the name of an existing ivFile that you would like to use
 or is the name of the ivFile that will be generated if you choose to use 
 random iv generation.

### outputFileName
This is the name you would like the program to use when saving the output of the decryption or encryption operation.

### cryptoFlag
This accepts one of two possible flags. 'e' will execute the encryption operation. 'd' will execute the decryption operation.

### keyFlag & ivFlag
This accepts one of two possible flags. 'y' specifies that you would like a random value to be generated and saved. 'n' specifies that you would like to use values saved in the files specified by the previous options.

