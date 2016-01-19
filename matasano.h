/*
 * matasano.h
 *
 *  Created on: Jan 10, 2016
 *      Author: George Mossessian
 */
 
 #pragma once

#include <limits.h>
#include <time.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <curl/curl.h>
#include "CStringUtils.h"
#include "aes128.h"
#include "MTRNG.h"
#include "sha1.h"
#include "MD4.h"

typedef struct charFreq_t{
	char c;
	float f;
	int r;
} charFreq_t;

typedef struct code_t{
	string cipher;
	string key;
	string plaintext;
	float score;
} code_t;

typedef struct keyvalue_t{
	int n;
	string *keys;
	string *vals;
	string encoded;
}keyvalue_t;


#define FILE4 "/home/gmoss/workspace/Matasano/1.4.txt"
#define FILE6 "/home/gmoss/workspace/Matasano/1.6.txt"
#define FILE7 "/home/gmoss/workspace/Matasano/1.7.txt"
#define FILE8 "/home/gmoss/workspace/Matasano/1.8.txt"
#define FILE10 "/home/gmoss/workspace/Matasano/2.2.txt"
#define FILE20 "/home/gmoss/workspace/Matasano/3.4.txt"

#define SHA1HMACSERVERLOC "/home/gmoss/workspace/Matasano/4.7server"

#define MILLION 1000000

extern int H4XX0R; //if this is 1, byte-at-a-time and others print out as they work

void problem1(void);
void problem2(void);
void problem3(void);
void problem4(void);
void problem5(void);
void problem6(void);
void problem7(void);
void problem8(void);
void problem9(void);
void problem10(void);
void problem11(void);
void problem12(void);
void problem13(void);
void problem14(void);
void problem15(void);
void problem16(void);
void problem17(void);
void problem18(void);
void problem19(void);
void problem20(void);
void problem21(void);
void problem22(void);
void problem23(void);
void problem24(void);
void problem25(void);
void problem26(void);
void problem27(void);
void problem28(void);
void problem29(void);
void problem30(void);
void problem31(void);
void problem32(void);
void problem33(void);

/*matasanoUtils.c*/
string AES128EncodeBlock(string in, string key);
string AES128DecodeBlock(string in, string key);
string AES128EncodeECB(string in, string key);
string AES128DecodeECB(string in, string key);
string AES128EncodeCBC(string in, string key, string IV);
string AES128DecodeCBC(string in, string key, string IV);
string AES128CTR(string in, string key, string nonce);
void littleEndianIncrement(string *counter);

/*set1Utils.c*/
/*Problem 3*/
code_t *breakFixedXOR(string cipher, string range);
charFreq_t *computeCharFreq(string str);
float scoreString(string str);
/*Problem 6*/
code_t *breakRepeatingXOR(string cipher, int maxKey, int depth);
float scoreKeysize(string str, int ks);

/*set2Utilcs.c*/
/*Problem 11*/
int breakOracleECBCBC(string (*oracle)(string));
string encryptionOracleECBCBC(string str);
/*Problem 12*/
string encryptionOracleAppend(string prefix);
int findEncryptionBlockSize(string (*oracle)(string));
string breakOracleAppend(string (*oracle)(string));
void stripLeadingByte(string *str); //shifts a string one byte left, reducing length by 1, chopping off leading byte.
/*Problem 13*/
keyvalue_t parseKeyValue(string in);
keyvalue_t profileFor(string email);
string profileForEncrypt(string email);
string decodeProfile(string p);
int findOffset(string (*oracle)(string));
/*Problem 14*/
string encryptionOracleAppendRandomPrefix(string text);
string oracleRandomPrefixWrapper(string text);
/*Problem 16*/
string problem16function1(string in);
int isAdmin(string cipher);
string createAdmin(string (*oracle)(string));

/*set3Utils.c*/
/*Problem 17*/
string problem17func1(string *tenStrings);
int paddingOracle(string cipher);
string breakPaddingBlock(string prevBlock, string block, int (*oracle)(string));
string breakPaddingOracle(string cipher, int (*oracle)(string));
/*Problem 18*/
string breakFixedNonceCTRAsRepeatedXOR(string *ciphers, int numCiphers);
string modifyKey(string keystream, string *ciphers, int numCiphers);
void printXORedCiphers(string keystream, string *ciphers, int numCiphers);
/*Problem 23*/
uint32_t untemper(uint32_t y);
void twistMTState(uint32_t *MTState);
uint32_t MTRNGClone(uint32_t *MTState, uint32_t i);
uint32_t temperTEST(uint32_t y);
/*Problem 24*/
string MTCipher(string plaintext, uint16_t key);
uint16_t breakMTCipher(string plaintext, string cipher);
string MTCipherWithPrefix(string plaintext, uint16_t key);
string generatePasswordToken(void);
int checkTokenIsTime(string token);

/*set4Utils.c*/
//Problem 25
string makeCipherText(void);
string CTRSeek(string cipher, string key, string newText, int offset);
string edit(string cipher, string newText, int offset);//the API key-less edit function
string stringReplace(string old, string new, int offset);
/*Problem 26*/
string problem26function1(string in);
string injectAdmin(string (*oracle)(string));
int isCTRAdmin(string cipher);
/*Problem 27*/
string problem27function1(string);
string checkASCIICompliance(string cipher);
/*Problem 28*/
string SHA1MAC(string data);
string getSHA1Key();
void setSHA1Key();
int validateSHA1MAC(string message, string MAC);
//Problem 29
string computePadding(string message);
uint32_t *breakSHA1DigestIntoRegisters(string digest);
string *forgeSHA1Digest(string message, string extension);
//Problem 30
string MD4MAC(string data);
int validateMD4MAC(string message, string MAC);
string getMD4Key(void);
void setMD4Key(void);
string computeMD4Padding(string message);
uint32_t *breakMD4DigestIntoRegisters(string digest);
string *forgeMD4Digest(string message, string extension);
//Problem 31
string timevalToString(struct timeval tv, int nsec);
string findHMAC(string url_base, string file, int numAttempts, struct timeval delay);	/*4.7.c*/
pid_t startServer(string url, string command, int *infp, int *outfp);			/*4.7.c*/
int curlRequest(string url);													/*4.7.c*/
long int *timeRequest(string url, int num);										/*4.7.c*/
int waitForServer(string url, long int timeOutms);								/*4.7.c*/
int wait_on_socket(curl_socket_t sockfd, int for_recv, long timeout_ms);		/*4.7.c*/
pid_t runExternalScript(string command, int *, int *);							/*4.7.c*/
int killPid(pid_t pid);															/*4.7.c*/
int longintcompare(const void *a, const void *b);								/*4.7.c*/

/*set5Utils.c*/
//problem 33
string DHPublicKey(string a);
