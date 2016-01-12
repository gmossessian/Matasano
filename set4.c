#include "matasano.h"

void problem25(void){
	//Break "random access read/write" AES CTR
	string cipher=makeCipherText();

	//As the attacker, just use the edit function to recover the keystream:
	string zeroes = newString(NULL, cipher.len);
	string keystream = edit(cipher,zeroes,0);

	//...And recover the plaintext
	string plaintext = stringXOR(cipher, keystream);
	prints(plaintext); PRINTNL;
}

void problem26(void){
	//CTR bitflipping
	string cipher;
	extern string savedKey;
	savedKey=randString(16);

	cipher=injectAdmin(problem26function1);
	if(isCTRAdmin(cipher)){
		printf("Admin profile created!\n");
	}
}	

void problem27(void){
	//Recover the key from CBC with IV=Key
	string cipher;
	string attackCipher;
	string attackPlaintext;
	string key;
	extern string savedKey;
	char i;

	savedKey=randString(16);

	i=0;
	do{
		cipher=problem27function1(newString( &i, 1));
		attackCipher=stringCat(stringCat(blockString(cipher,16)[0],newString(NULL,16)),blockString(cipher,16)[0]);
		attackPlaintext=checkASCIICompliance(attackCipher);
		i++;
	} while(attackPlaintext.len == 0);

	key=stringXOR(blockString(attackPlaintext,16)[0], blockString(attackPlaintext,16)[2]);

	printf("The secret key used was ..... "); printsint(savedKey); PRINTNL;
	printf("And the recovered key is .... "); printsint(key); PRINTNL;
}

void problem28(void){
	setSHA1Key();
	string message=newString("Test message.",0);

	string signature = SHA1MAC(message);

	printf("The message\n");prints(message);PRINTNL;printf("has MAC\n");printsint(signature);PRINTNL;


	printf("Does the MAC validate?\n");
	if(validateSHA1MAC(message, signature)==1)printf("Yes!\n"); else printf("No!\n");

	message=newString("Test message..",0);
	printf("What about the new message, \n"); prints(message);PRINTNL;
	printf("Validating MAC?\n");
	if(validateSHA1MAC(message, signature)==1)printf("Yes!\n"); else printf("No!\n");
}

void problem29(void){
	//Break a SHA-1 keyed MAC using length extension
	string message=newString("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon",0);
	string extension=newString(";admin=True",0);
	string *MAC;
	setSHA1Key();
	printf("The secret key is "); printsint(getSHA1Key());PRINTNL;
	printf("Its length is %i.\n", getSHA1Key().len);PRINTNL;
	MAC=forgeSHA1Digest(message,extension);

	printf("The forged message is\n"); prints(MAC[0]); PRINTNL;
	printf("The forged digest is \n"); printsint(MAC[1]);PRINTNL;
}

void problem30(void){
	//Break an MD4 keyed MAC using length extension
	string message=newString("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon",0);
	string extension=newString(";admin=True",0);
	string *MAC;
	setMD4Key();
	printf("The secret key is "); printsint(getMD4Key());PRINTNL;
	printf("Its length is %i.\n", getMD4Key().len);PRINTNL;
	MAC=forgeMD4Digest(message,extension);

	printf("The forged message is\n"); prints(MAC[0]); PRINTNL;
	printf("The forged digest is \n"); printsint(MAC[1]);PRINTNL;
}

void problem31(void){
	//Break HMAC-SHA1 with an artificial timing leak
		pid_t pid;
	struct timeval delay;
	string file = newString("TriggerTheDoomsdayMachine", 0);
	string url = newString("http://localhost:5000/", 0);
	string command = newString(SHA1HMACSERVERLOC, 0);
	string HMAC;

	printf("Starting server...");
	pid = startServer(url, command, NULL, NULL);
	printf("Done!\n");

	PRINTNL;

	delay.tv_sec = 0;
	delay.tv_usec = 50000;
	HMAC = findHMAC(newString("http://localhost:5000/test", 0), file, 6, delay);

	killPid(pid);

	printf("The recovered HMAC was: \n");
	prints(HMAC);
	PRINTNL;
}

void problem32(void){
	//Break HMAC-SHA1 with a slightly less artificial timing leak
	pid_t pid;
	struct timeval delay;
	string file = newString("TriggerTheDoomsdayMachine", 0);
	string url = newString("http://localhost:5000/", 0);
	string command = newString(SHA1HMACSERVERLOC, 0);
	string HMAC;

	int numRequests=50;
	
	printf("Using a 5 ms delay, averaging over 50 requests to the server...\n");
	delay.tv_sec = 0;
	delay.tv_usec = 5000;


	printf("Starting server...");
	pid = startServer(url, command, NULL, NULL);
	printf("Done!\n");

	delay.tv_sec = 0;
	delay.tv_usec = 5000; //5 milliseconds
	HMAC = findHMAC(newString("http://localhost:5000/test", 0), file, numRequests, delay);

	killPid(pid);

	printf("The recovered HMAC was: \n");
	prints(HMAC);
	PRINTNL;
}
